from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
from threading import Lock
import unittest
from unittest.mock import patch

from gateway.breaker import (
    AdmissionDenied,
    BreakerState,
    BreakerStateStoreError,
    CircuitBreakerPolicy,
    CircuitBreakerRegistry,
    ObservationResult,
    RouteKey,
)
from gateway.state import AtomicBreakerStateStore


class FakeClock:
    def __init__(self, value: datetime | None = None) -> None:
        self._value = value or datetime(2026, 7, 12, tzinfo=UTC)
        self._lock = Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._value += timedelta(seconds=seconds)


class LeaseSequence:
    def __init__(self) -> None:
        self._value = 0
        self._lock = Lock()

    def __call__(self) -> str:
        with self._lock:
            self._value += 1
            return f"lease-{self._value}"


ROUTE = RouteKey("instance-a", "group-a", "primary", "profile-a")
FINGERPRINT = "sha256:route-fixture-a"


def policy(**overrides: object) -> CircuitBreakerPolicy:
    values: dict[str, object] = {
        "failure_threshold": 3,
        "error_rate_threshold": 0.5,
        "minimum_samples": 4,
        "window_size": 5,
        "recovery_success_threshold": 2,
        "base_cooldown_seconds": 10,
        "max_cooldown_seconds": 100,
        "jitter_ratio": 0,
    }
    values.update(overrides)
    return CircuitBreakerPolicy(**values)


def registry(clock: FakeClock | None = None) -> CircuitBreakerRegistry:
    return CircuitBreakerRegistry(
        clock=clock or FakeClock(),
        rng=lambda: 0.5,
        lease_factory=LeaseSequence(),
    )


def configure(
    breaker: CircuitBreakerRegistry,
    *,
    revision: int = 1,
    fingerprint: str = FINGERPRINT,
    breaker_policy: CircuitBreakerPolicy | None = None,
    enabled: bool = True,
) -> None:
    breaker.configure_route(
        ROUTE,
        config_revision=revision,
        route_fingerprint=fingerprint,
        policy=breaker_policy or policy(),
        enabled=enabled,
    )


def acquire(
    breaker: CircuitBreakerRegistry,
    attempt: str,
    *,
    revision: int = 1,
    fingerprint: str = FINGERPRINT,
    manual_probe: bool = False,
):
    admission = breaker.acquire(
        ROUTE,
        config_revision=revision,
        route_fingerprint=fingerprint,
        attempt_id=attempt,
        manual_probe=manual_probe,
    )
    if not admission.allowed:
        return admission
    assert admission.ticket is not None
    return admission


class CircuitBreakerPolicyTests(unittest.TestCase):
    def test_policy_rejects_unbounded_or_invalid_values(self) -> None:
        invalid = (
            {"failure_threshold": 0},
            {"minimum_samples": 6, "window_size": 5},
            {"error_rate_threshold": 0},
            {"error_rate_threshold": 1.01},
            {"recovery_success_threshold": 0},
            {"base_cooldown_seconds": float("nan")},
            {"max_cooldown_seconds": 1, "base_cooldown_seconds": 2},
            {"jitter_ratio": 1.01},
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    policy(**values)

    def test_transition_journal_capacity_is_bounded_and_validated(self) -> None:
        for invalid in (0, 10_001, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    CircuitBreakerRegistry(transition_capacity=invalid)

        breaker = CircuitBreakerRegistry(
            clock=FakeClock(),
            rng=lambda: 0.5,
            lease_factory=LeaseSequence(),
            transition_capacity=2,
        )
        configure(breaker)
        succeeded = acquire(breaker, "bounded-success")
        assert succeeded.ticket is not None
        breaker.record_success(succeeded.ticket)
        configure(breaker, revision=2, enabled=False)
        configure(breaker, revision=3, enabled=True)

        transitions = breaker.transition_events()
        self.assertEqual(len(transitions), 2)
        self.assertEqual(
            [transition.reason for transition in transitions],
            ["configuration_disabled", "configuration_enabled"],
        )


class CircuitBreakerStateTests(unittest.TestCase):
    def test_transition_audit_captures_reason_revision_and_manual_probe(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(breaker, breaker_policy=policy(recovery_success_threshold=1))

        failure = acquire(breaker, "auth-failure")
        assert failure.ticket is not None
        breaker.record_action_required(
            failure.ticket,
            failure_category="auth_rejected",
            http_status=401,
        )
        manual = acquire(breaker, "manual-retest", manual_probe=True)
        assert manual.ticket is not None
        breaker.record_cancelled(manual.ticket)

        transitions = breaker.transition_events()
        self.assertEqual(
            [(event.old_state, event.new_state, event.reason) for event in transitions],
            [
                (BreakerState.UNKNOWN, BreakerState.OPEN_ACTION_REQUIRED, "business_failed"),
                (BreakerState.OPEN_ACTION_REQUIRED, BreakerState.HALF_OPEN, "manual_probe_started"),
                (BreakerState.HALF_OPEN, BreakerState.OPEN_ACTION_REQUIRED, "probe_cancelled"),
            ],
        )
        first = transitions[0]
        self.assertEqual(first.timestamp, "2026-07-12T00:00:00Z")
        self.assertEqual(first.route_key, ROUTE)
        self.assertEqual(first.config_revision, 1)
        self.assertEqual(first.failure_category, "auth_rejected")
        self.assertEqual(first.http_status, 401)
        self.assertEqual(first.signal.value, "business")
        self.assertNotIn(FINGERPRINT, repr(transitions))

    def test_configuration_state_changes_have_independent_transition_events(self) -> None:
        breaker = registry()
        configure(breaker)
        success = acquire(breaker, "success")
        assert success.ticket is not None
        breaker.record_success(success.ticket)
        configure(breaker, revision=2, enabled=False)
        configure(breaker, revision=3, enabled=True)

        transitions = breaker.transition_events()
        self.assertEqual(
            [(event.config_revision, event.old_state, event.new_state, event.reason) for event in transitions],
            [
                (1, BreakerState.UNKNOWN, BreakerState.CLOSED, "business_succeeded"),
                (2, BreakerState.CLOSED, BreakerState.DISABLED, "configuration_disabled"),
                (3, BreakerState.DISABLED, BreakerState.UNKNOWN, "configuration_enabled"),
            ],
        )

    def test_unknown_success_closes_and_ticket_is_one_shot(self) -> None:
        breaker = registry()
        configure(breaker)
        admission = acquire(breaker, "attempt-1")
        self.assertTrue(admission.allowed)
        self.assertEqual(admission.state, BreakerState.UNKNOWN)
        ticket = admission.ticket
        assert ticket is not None
        self.assertEqual(breaker.record_success(ticket), ObservationResult.APPLIED)
        self.assertEqual(breaker.record_success(ticket), ObservationResult.IGNORED)
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.CLOSED)
        self.assertEqual(snapshot.sample_count, 1)
        self.assertEqual(snapshot.failure_count, 0)

    def test_consecutive_threshold_opens_then_half_open_recovers(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(breaker)
        for index in range(3):
            admission = acquire(breaker, f"failure-{index}")
            assert admission.ticket is not None
            self.assertEqual(
                breaker.record_temporary_failure(
                    admission.ticket,
                    failure_category="upstream_timeout",
                ),
                ObservationResult.APPLIED,
            )
        opened = breaker.snapshot(ROUTE)
        assert opened is not None and opened.open_until is not None
        self.assertEqual(opened.state, BreakerState.OPEN_TEMPORARY)
        self.assertEqual(opened.open_until, clock() + timedelta(seconds=10))
        denied = acquire(breaker, "too-early")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.denied, AdmissionDenied.OPEN_TEMPORARY)

        clock.advance(10)
        probe1 = acquire(breaker, "probe-1")
        assert probe1.ticket is not None
        self.assertTrue(probe1.ticket.half_open_probe)
        self.assertEqual(breaker.record_success(probe1.ticket), ObservationResult.APPLIED)
        still_half_open = breaker.snapshot(ROUTE)
        assert still_half_open is not None
        self.assertEqual(still_half_open.state, BreakerState.HALF_OPEN)
        probe2 = acquire(breaker, "probe-2")
        assert probe2.ticket is not None
        self.assertEqual(breaker.record_success(probe2.ticket), ObservationResult.APPLIED)
        recovered = breaker.snapshot(ROUTE)
        assert recovered is not None
        self.assertEqual(recovered.state, BreakerState.CLOSED)
        self.assertEqual(recovered.open_count, 0)
        self.assertEqual(recovered.failure_count, 0)

    def test_half_open_failure_reopens_with_exponential_backoff(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(
            breaker,
            breaker_policy=policy(failure_threshold=1, recovery_success_threshold=1),
        )
        first = acquire(breaker, "failure")
        assert first.ticket is not None
        breaker.record_temporary_failure(first.ticket, failure_category="network_error")
        clock.advance(10)
        probe = acquire(breaker, "probe")
        assert probe.ticket is not None
        breaker.record_temporary_failure(probe.ticket, failure_category="network_error")
        reopened = breaker.snapshot(ROUTE)
        assert reopened is not None
        self.assertEqual(reopened.state, BreakerState.OPEN_TEMPORARY)
        self.assertEqual(reopened.open_count, 2)
        self.assertEqual(reopened.open_until, clock() + timedelta(seconds=20))

    def test_temporary_open_applies_deterministic_bounded_jitter(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(
            breaker,
            breaker_policy=policy(
                failure_threshold=1,
                base_cooldown_seconds=10,
                max_cooldown_seconds=100,
                jitter_ratio=0.2,
            ),
        )
        failed = acquire(breaker, "jittered-failure")
        assert failed.ticket is not None

        breaker.record_temporary_failure(
            failed.ticket,
            failure_category="network_error",
        )

        opened = breaker.snapshot(ROUTE)
        assert opened is not None
        self.assertEqual(opened.state, BreakerState.OPEN_TEMPORARY)
        self.assertEqual(opened.open_until, clock() + timedelta(seconds=11))

    def test_error_rate_and_bounded_window_open(self) -> None:
        breaker = registry()
        configure(
            breaker,
            breaker_policy=policy(failure_threshold=99, error_rate_threshold=0.6),
        )
        for index, failed in enumerate((False, True, False, True, True)):
            admission = acquire(breaker, f"sample-{index}")
            assert admission.ticket is not None
            if failed:
                breaker.record_temporary_failure(admission.ticket, failure_category="upstream_5xx")
            else:
                breaker.record_success(admission.ticket)
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.sample_count, 5)
        self.assertEqual(snapshot.failure_count, 3)
        self.assertEqual(snapshot.error_rate, 0.6)
        self.assertEqual(snapshot.state, BreakerState.OPEN_TEMPORARY)

    def test_rate_limit_is_immediate_and_retry_after_is_bounded(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(breaker, breaker_policy=policy(max_cooldown_seconds=100))
        first = acquire(breaker, "rate-limited")
        assert first.ticket is not None
        breaker.record_rate_limited(first.ticket, retry_after_seconds=60)
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.OPEN_TEMPORARY)
        self.assertEqual(snapshot.open_until, clock() + timedelta(seconds=60))

        breaker2 = registry(clock)
        configure(breaker2, breaker_policy=policy(max_cooldown_seconds=100))
        second = acquire(breaker2, "rate-limited-long")
        assert second.ticket is not None
        breaker2.record_rate_limited(second.ticket, retry_after_seconds=1000)
        bounded = breaker2.snapshot(ROUTE)
        assert bounded is not None
        self.assertEqual(bounded.open_until, clock() + timedelta(seconds=100))

    def test_action_required_never_ages_out_and_manual_retest_is_controlled(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(breaker, breaker_policy=policy(recovery_success_threshold=1))
        failure = acquire(breaker, "auth-failure")
        assert failure.ticket is not None
        breaker.record_action_required(failure.ticket, failure_category="auth_rejected")
        clock.advance(365 * 24 * 3600)
        denied = acquire(breaker, "automatic")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.denied, AdmissionDenied.OPEN_ACTION_REQUIRED)
        probe = acquire(breaker, "manual", manual_probe=True)
        assert probe.ticket is not None
        self.assertTrue(probe.ticket.half_open_probe)
        breaker.record_success(probe.ticket)
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.CLOSED)
        self.assertFalse(snapshot.action_required)

    def test_cancelled_manual_probe_never_allows_ordinary_business_admission(self) -> None:
        breaker = registry()
        configure(breaker, breaker_policy=policy(recovery_success_threshold=1))
        failure = acquire(breaker, "auth-failure")
        assert failure.ticket is not None
        breaker.record_action_required(failure.ticket, failure_category="auth_rejected")
        probe = acquire(breaker, "manual-probe", manual_probe=True)
        assert probe.ticket is not None
        breaker.record_cancelled(probe.ticket)
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.OPEN_ACTION_REQUIRED)
        ordinary = acquire(breaker, "ordinary-business")
        self.assertFalse(ordinary.allowed)
        self.assertEqual(ordinary.denied, AdmissionDenied.OPEN_ACTION_REQUIRED)

    def test_temporary_manual_probe_failure_preserves_action_required_redline(self) -> None:
        breaker = registry()
        configure(breaker, breaker_policy=policy(recovery_success_threshold=1))
        failure = acquire(breaker, "auth-failure")
        assert failure.ticket is not None
        breaker.record_action_required(failure.ticket, failure_category="auth_rejected")
        probe = acquire(breaker, "manual-probe", manual_probe=True)
        assert probe.ticket is not None
        breaker.record_temporary_failure(probe.ticket, failure_category="network_error")
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.OPEN_ACTION_REQUIRED)
        self.assertTrue(snapshot.action_required)

    def test_cancelled_probe_releases_lease_without_failure_signal(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(breaker, breaker_policy=policy(failure_threshold=1))
        failed = acquire(breaker, "failure")
        assert failed.ticket is not None
        breaker.record_temporary_failure(failed.ticket, failure_category="network_error")
        clock.advance(10)
        probe = acquire(breaker, "probe-cancelled")
        assert probe.ticket is not None
        before = breaker.snapshot(ROUTE)
        breaker.record_cancelled(probe.ticket)
        after = breaker.snapshot(ROUTE)
        assert before is not None and after is not None
        self.assertEqual(before.failure_count, after.failure_count)
        self.assertEqual(before.consecutive_failures, after.consecutive_failures)
        self.assertFalse(after.half_open_lease_active)
        replacement = acquire(breaker, "replacement-probe")
        self.assertTrue(replacement.allowed)

    def test_revision_fingerprint_epoch_and_lease_make_stale_results_noops(self) -> None:
        breaker = registry()
        configure(breaker)
        old = acquire(breaker, "old-attempt")
        assert old.ticket is not None
        configure(breaker, revision=2, fingerprint="sha256:route-fixture-b")
        self.assertEqual(
            breaker.record_temporary_failure(old.ticket, failure_category="network_error"),
            ObservationResult.APPLIED,
        )
        current_snapshot = breaker.snapshot(ROUTE)
        assert current_snapshot is not None
        self.assertEqual(current_snapshot.config_revision, 2)
        self.assertEqual(current_snapshot.failure_count, 0)
        stale_admission = acquire(breaker, "stale-config")
        self.assertFalse(stale_admission.allowed)
        self.assertEqual(stale_admission.denied, AdmissionDenied.STALE_CONFIGURATION)
        current = acquire(
            breaker,
            "current-attempt",
            revision=2,
            fingerprint="sha256:route-fixture-b",
        )
        assert current.ticket is not None
        forged = type(current.ticket)(
            route_key=current.ticket.route_key,
            config_revision=current.ticket.config_revision,
            route_fingerprint=current.ticket.route_fingerprint,
            transition_epoch=current.ticket.transition_epoch,
            lease_id="lease-forged",
            attempt_id=current.ticket.attempt_id,
            half_open_probe=current.ticket.half_open_probe,
            signal=current.ticket.signal,
        )
        self.assertEqual(breaker.record_success(forged), ObservationResult.IGNORED)
        self.assertEqual(breaker.record_success(current.ticket), ObservationResult.APPLIED)

    def test_same_route_hot_revision_keeps_one_global_probe_lease(self) -> None:
        breaker = registry()
        configure(breaker)
        old = acquire(breaker, "revision-one-probe")
        assert old.ticket is not None

        configure(
            breaker,
            revision=2,
            breaker_policy=policy(failure_threshold=4),
        )
        preview = breaker.preview_admission(
            ROUTE,
            config_revision=2,
            route_fingerprint=FINGERPRINT,
        )
        current = acquire(breaker, "revision-two-probe", revision=2)

        self.assertFalse(preview.allowed)
        self.assertEqual(preview.denied, AdmissionDenied.HALF_OPEN_BUSY)
        self.assertFalse(current.allowed)
        self.assertEqual(current.denied, AdmissionDenied.HALF_OPEN_BUSY)
        self.assertEqual(breaker.record_cancelled(old.ticket), ObservationResult.APPLIED)

        replacement = acquire(breaker, "revision-two-replacement", revision=2)
        self.assertTrue(replacement.allowed)
        assert replacement.ticket is not None
        self.assertEqual(breaker.record_success(replacement.ticket), ObservationResult.APPLIED)

    def test_policy_hot_update_preserves_failure_evidence(self) -> None:
        breaker = registry()
        configure(breaker, breaker_policy=policy(failure_threshold=10))
        failed = acquire(breaker, "failure")
        assert failed.ticket is not None
        breaker.record_temporary_failure(failed.ticket, failure_category="network_error")
        configure(
            breaker,
            revision=2,
            breaker_policy=policy(failure_threshold=2, window_size=4, minimum_samples=4),
        )
        snapshot = breaker.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.consecutive_failures, 1)
        self.assertEqual(snapshot.failure_count, 1)
        self.assertEqual(snapshot.state, BreakerState.UNKNOWN)
        self.assertEqual(snapshot.config_revision, 2)

    def test_same_revision_only_allows_idempotent_registration(self) -> None:
        breaker = registry()
        original = policy()
        configure(breaker, breaker_policy=original)
        configure(breaker, breaker_policy=original)
        with self.assertRaises(ValueError):
            configure(breaker, breaker_policy=policy(failure_threshold=4))
        with self.assertRaises(ValueError):
            configure(breaker, breaker_policy=original, enabled=False)

    def test_disabled_route_requires_explicit_reenable(self) -> None:
        breaker = registry()
        configure(breaker, enabled=False)
        denied = acquire(breaker, "disabled")
        self.assertEqual(denied.denied, AdmissionDenied.DISABLED)
        configure(breaker, revision=2, enabled=True)
        enabled = acquire(breaker, "enabled", revision=2)
        self.assertTrue(enabled.allowed)


class CircuitBreakerConcurrencyTests(unittest.TestCase):
    def test_10_50_100_competitors_get_exactly_one_unknown_ticket(self) -> None:
        for concurrency in (10, 50, 100):
            with self.subTest(concurrency=concurrency):
                breaker = registry()
                configure(breaker)

                def compete(index: int):
                    return acquire(breaker, f"unknown-{index}")

                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    results = list(pool.map(compete, range(concurrency)))
                allowed = [result for result in results if result.allowed]
                self.assertEqual(len(allowed), 1)
                self.assertTrue(allowed[0].ticket.half_open_probe)
                self.assertTrue(
                    all(
                        result.denied is AdmissionDenied.HALF_OPEN_BUSY
                        for result in results
                        if not result.allowed
                    )
                )

    def test_10_50_100_competitors_get_exactly_one_half_open_ticket(self) -> None:
        for concurrency in (10, 50, 100):
            with self.subTest(concurrency=concurrency):
                clock = FakeClock()
                breaker = registry(clock)
                configure(breaker, breaker_policy=policy(failure_threshold=1))
                failed = acquire(breaker, "initial-failure")
                assert failed.ticket is not None
                breaker.record_temporary_failure(failed.ticket, failure_category="network_error")
                clock.advance(10)

                def compete(index: int):
                    return acquire(breaker, f"competitor-{index}")

                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    results = list(pool.map(compete, range(concurrency)))
                allowed = [result for result in results if result.allowed]
                self.assertEqual(len(allowed), 1)
                self.assertTrue(allowed[0].ticket.half_open_probe)
                self.assertTrue(
                    all(
                        result.denied is AdmissionDenied.HALF_OPEN_BUSY
                        for result in results
                        if not result.allowed
                    )
                )


class CircuitBreakerPersistenceTests(unittest.TestCase):
    def test_failed_persistence_does_not_publish_phantom_transition(self) -> None:
        class FailingStore:
            def load(self):
                return None

            def save(self, _document):
                raise BreakerStateStoreError("fixture_failure")

        breaker = registry()
        configure(breaker)
        admission = acquire(breaker, "auth-failure")
        assert admission.ticket is not None
        breaker._store = FailingStore()
        with self.assertRaises(BreakerStateStoreError):
            breaker.record_action_required(
                admission.ticket,
                failure_category="auth_rejected",
                http_status=401,
            )
        self.assertEqual(breaker.transition_events(), ())

    def test_atomic_store_round_trip_redacts_runtime_ephemera(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "breaker.json"
            store = AtomicBreakerStateStore(path)
            breaker = registry()
            configure(breaker)
            admission = acquire(breaker, "active-attempt")
            assert admission.ticket is not None
            breaker.attach_store(store)
            document = json.loads(path.read_text(encoding="utf-8"))
            serialized = json.dumps(document, sort_keys=True)
            self.assertNotIn("attempt_id", serialized)
            self.assertNotIn("lease_id", serialized)
            self.assertNotIn("request_body", serialized)
            self.assertNotIn("authorization", serialized.lower())
            self.assertEqual(store.load(), document)
            self.assertFalse(any(path.parent.glob("*.tmp")))

    def test_restore_refuses_to_replace_live_attempt_table(self) -> None:
        breaker = registry()
        configure(breaker)
        admission = acquire(breaker, "active")
        assert admission.ticket is not None
        with self.assertRaises(RuntimeError):
            breaker.restore(breaker.export_state())
        self.assertEqual(breaker.record_success(admission.ticket), ObservationResult.APPLIED)

    def test_store_rejects_forbidden_fields_and_corrupt_or_oversized_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            store = AtomicBreakerStateStore(path, max_bytes=128)
            with self.assertRaises(BreakerStateStoreError):
                store.save({"schema_version": 1, "routes": [], "secret": "fixture"})
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(BreakerStateStoreError):
                store.load()

    def test_atomic_store_has_no_failing_step_after_replace_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            store = AtomicBreakerStateStore(path)
            original_replace = os.replace
            original_chmod = os.chmod
            calls = []

            def tracked_chmod(target, mode):
                calls.append(("chmod", Path(target).name))
                return original_chmod(target, mode)

            def tracked_replace(source, target):
                calls.append(("replace", Path(target).name))
                return original_replace(source, target)

            with patch("gateway.state.os.chmod", side_effect=tracked_chmod), patch(
                "gateway.state.os.replace",
                side_effect=tracked_replace,
            ):
                store.save({"schema_version": 2, "routes": []})

            replace_index = next(index for index, item in enumerate(calls) if item[0] == "replace")
            self.assertTrue(all(item[0] != "chmod" for item in calls[replace_index + 1 :]))
            self.assertEqual(store.load(), {"schema_version": 2, "routes": []})
            path.write_bytes(b"x" * 129)
            with self.assertRaises(BreakerStateStoreError):
                store.load()

    def test_replace_that_commits_then_raises_is_verified_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            store = AtomicBreakerStateStore(path)
            original_replace = os.replace

            def committed_then_raised(source, target):
                original_replace(source, target)
                raise OSError("fixture_after_commit")

            document = {"schema_version": 2, "routes": []}
            with patch("gateway.state.os.replace", side_effect=committed_then_raised):
                store.save(document)
            self.assertEqual(store.load(), document)

    def test_committed_then_raised_breaker_transition_keeps_memory_and_disk_equal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            store = AtomicBreakerStateStore(path)
            breaker = registry()
            configure(breaker)
            breaker.attach_store(store)

            admission = acquire(breaker, "auth")
            assert admission.ticket is not None
            original_replace = os.replace

            def committed_then_raised(source, target):
                original_replace(source, target)
                raise OSError("fixture_after_commit")

            with patch("gateway.state.os.replace", side_effect=committed_then_raised):
                breaker.record_action_required(
                    admission.ticket,
                    failure_category="auth_rejected",
                    http_status=401,
                )
            memory = breaker.snapshot(ROUTE)
            assert memory is not None
            disk_route = store.load()["routes"][0]
            self.assertEqual(memory.state, BreakerState.OPEN_ACTION_REQUIRED)
            self.assertEqual(disk_route["state"], BreakerState.OPEN_ACTION_REQUIRED.value)
            self.assertTrue(memory.action_required)
            self.assertTrue(disk_route["action_required"])

    def test_restore_rejects_unknown_but_well_formed_failure_category(self) -> None:
        breaker = registry()
        configure(breaker)
        document = breaker.export_state()
        document["routes"][0]["last_failure_category"] = "valid-format-secret-canary"
        with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_category_invalid"):
            breaker.restore(document)

    def test_unverifiable_replace_failure_latches_registry_before_any_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            store = AtomicBreakerStateStore(path)
            breaker = registry()
            configure(breaker)
            breaker.attach_store(store)
            admission = acquire(breaker, "failure")
            assert admission.ticket is not None
            with patch("gateway.state.os.replace", side_effect=OSError("fixture_before_commit")):
                with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_commit_uncertain"):
                    breaker.record_action_required(
                        admission.ticket,
                        failure_category="auth_rejected",
                    )
            with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_commit_uncertain"):
                acquire(breaker, "must-not-admit")
            with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_commit_uncertain"):
                breaker.attach_store(store)
            with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_commit_uncertain"):
                breaker.restore_from_store(store)
            with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_commit_uncertain"):
                breaker.configure_route(
                    ROUTE,
                    config_revision=2,
                    route_fingerprint="sha256:route-fixture-a",
                    policy=policy(),
                )
        breaker = registry()
        configure(breaker)
        for invalid_version in (True, 0, 3, "2"):
            with self.subTest(schema_version=invalid_version):
                with self.assertRaises(BreakerStateStoreError):
                    breaker.restore({"schema_version": invalid_version, "routes": []})

    def test_restart_preserves_open_temporary_and_action_required(self) -> None:
        clock = FakeClock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "breaker.json"
            store = AtomicBreakerStateStore(path)
            source = registry(clock)
            configure(source, breaker_policy=policy(failure_threshold=1))
            source.attach_store(store)
            failed = acquire(source, "failure")
            assert failed.ticket is not None
            source.record_temporary_failure(failed.ticket, failure_category="network_error")

            restored = registry(clock)
            configure(restored, breaker_policy=policy(failure_threshold=1))
            self.assertEqual(restored.restore_from_store(store), 1)
            restored_snapshot = restored.snapshot(ROUTE)
            assert restored_snapshot is not None
            self.assertEqual(restored_snapshot.state, BreakerState.OPEN_TEMPORARY)
            self.assertEqual(restored_snapshot.open_until, clock() + timedelta(seconds=10))

            manual_source = registry(clock)
            configure(manual_source)
            manual_source.attach_store(store)
            auth = acquire(manual_source, "auth")
            assert auth.ticket is not None
            manual_source.record_action_required(auth.ticket, failure_category="auth_rejected")
            manual_restored = registry(clock)
            configure(manual_restored)
            manual_restored.restore_from_store(store)
            action = manual_restored.snapshot(ROUTE)
            assert action is not None
            self.assertEqual(action.state, BreakerState.OPEN_ACTION_REQUIRED)
        self.assertTrue(action.action_required)

    def test_legacy_schema_one_without_http_status_restores_idempotently(self) -> None:
        source = registry()
        configure(source)
        admission = acquire(source, "legacy-auth")
        source.record_action_required(admission.ticket, failure_category="auth_rejected")
        document = source.export_state()
        document["schema_version"] = 1
        for route_state in document["routes"]:
            route_state.pop("last_http_status")

        restored = registry()
        configure(restored)
        self.assertEqual(restored.restore(document), 1)
        snapshot = restored.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.OPEN_ACTION_REQUIRED)
        self.assertIsNone(snapshot.last_http_status)

        with tempfile.TemporaryDirectory() as directory:
            store = AtomicBreakerStateStore(Path(directory) / "breaker.json")
            store.save(document)
            migrated = registry()
            configure(migrated)
            migrated.restore_from_store(store)
            self.assertEqual(store.load()["schema_version"], 2)

    def test_repeated_protocol_failures_escalate_from_temporary_to_action_required(self) -> None:
        breaker = registry()
        configure(
            breaker,
            breaker_policy=policy(
                failure_threshold=99,
                error_rate_threshold=None,
                protocol_failure_threshold=2,
            ),
        )
        first = acquire(breaker, "protocol-1")
        breaker.record_protocol_failure(first.ticket, failure_category="protocol_error")
        degraded = breaker.snapshot(ROUTE)
        assert degraded is not None
        self.assertEqual(degraded.state, BreakerState.UNKNOWN)
        self.assertEqual(degraded.consecutive_protocol_failures, 1)
        second = acquire(breaker, "protocol-2")
        breaker.record_protocol_failure(second.ticket, failure_category="protocol_error")
        escalated = breaker.snapshot(ROUTE)
        assert escalated is not None
        self.assertEqual(escalated.state, BreakerState.OPEN_ACTION_REQUIRED)
        self.assertEqual(escalated.consecutive_protocol_failures, 2)
        self.assertTrue(escalated.action_required)

    def test_half_open_restart_returns_to_temporary_open_without_lease(self) -> None:
        clock = FakeClock()
        breaker = registry(clock)
        configure(breaker, breaker_policy=policy(failure_threshold=1))
        failed = acquire(breaker, "failure")
        assert failed.ticket is not None
        breaker.record_temporary_failure(failed.ticket, failure_category="network_error")
        clock.advance(10)
        probe = acquire(breaker, "probe")
        assert probe.ticket is not None
        document = breaker.export_state()

        restarted = registry(clock)
        configure(restarted, breaker_policy=policy(failure_threshold=1))
        self.assertEqual(restarted.restore(document), 1)
        snapshot = restarted.snapshot(ROUTE)
        assert snapshot is not None and snapshot.open_until is not None
        self.assertEqual(snapshot.state, BreakerState.OPEN_TEMPORARY)
        self.assertFalse(snapshot.half_open_lease_active)
        self.assertGreaterEqual(snapshot.open_until, clock() + timedelta(seconds=10))

    def test_expired_temporary_state_restores_then_allows_one_controlled_half_open(self) -> None:
        clock = FakeClock()
        source = registry(clock)
        configure(source, breaker_policy=policy(failure_threshold=1))
        failure = acquire(source, "failure")
        source.record_temporary_failure(failure.ticket, failure_category="network_error")
        document = source.export_state()
        clock.advance(60)

        restarted = registry(clock)
        configure(restarted, breaker_policy=policy(failure_threshold=1))
        restarted.restore(document)
        first = acquire(restarted, "half-open-1")
        second = acquire(restarted, "half-open-2")
        self.assertTrue(first.allowed)
        self.assertEqual(first.state, BreakerState.HALF_OPEN)
        self.assertFalse(second.allowed)
        self.assertEqual(second.denied, AdmissionDenied.HALF_OPEN_BUSY)

    def test_restore_ignores_stale_revision_and_fingerprint(self) -> None:
        source = registry()
        configure(source)
        auth = acquire(source, "auth")
        assert auth.ticket is not None
        source.record_action_required(auth.ticket, failure_category="auth_rejected")
        document = source.export_state()

        target = registry()
        configure(target, revision=2, fingerprint="sha256:route-fixture-b")
        self.assertEqual(target.restore(document), 0)
        snapshot = target.snapshot(ROUTE)
        assert snapshot is not None
        self.assertEqual(snapshot.state, BreakerState.UNKNOWN)

    def test_persistence_failure_rolls_back_observation_and_consumption(self) -> None:
        class FailingStore:
            def load(self):
                return None

            def save(self, _document):
                raise BreakerStateStoreError("fixture_failure")

        breaker = registry()
        configure(breaker)
        admission = acquire(breaker, "attempt")
        assert admission.ticket is not None
        breaker._store = FailingStore()
        with self.assertRaises(BreakerStateStoreError):
            breaker.record_temporary_failure(
                admission.ticket,
                failure_category="network_error",
            )
        before_retry = breaker.snapshot(ROUTE)
        assert before_retry is not None
        self.assertEqual(before_retry.failure_count, 0)
        breaker._store = None
        self.assertEqual(
            breaker.record_temporary_failure(
                admission.ticket,
                failure_category="network_error",
            ),
            ObservationResult.APPLIED,
        )


if __name__ == "__main__":
    unittest.main()
