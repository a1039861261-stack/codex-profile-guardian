from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
import unittest

from gateway.breaker import (
    AdmissionDenied,
    BreakerState,
    BreakerStateStoreError,
    CircuitBreakerPolicy,
    CircuitBreakerRegistry,
    RouteKey,
)
from gateway.cancellation import CancellationToken
from gateway.config import (
    AtomicGroupConfig,
    FailoverGroupConfig,
    ProbeMode,
    ProbePolicy,
    RouteConfig,
    RouteRole,
    StateCompatibility,
    StateCompatibilityError,
    StateCompatibilityEvidence,
)
from gateway.failures import FailureClassifier
from gateway.models import AttemptFailure, AttemptResult, BufferedResponse, CancelReason, GatewayLimits
from gateway.request_snapshot import create_request_snapshot
from gateway.router import FailoverRouter, TrafficSignal
from gateway.probes import create_probe_snapshot
from gateway.secrets import InMemorySecretResolver
from tests.gateway_probe_support import FAKE_BEARER, FIXTURE_MODEL, fixture_request, tool_sse_frames


def buffered(response_id: str, body: bytes | None = None) -> BufferedResponse:
    value = body or b'event: response.completed\ndata: {"type":"response.completed"}\n\n'
    return BufferedResponse(
        status=200,
        content_type="text/event-stream",
        body=value,
        body_sha256=hashlib.sha256(value).hexdigest(),
        terminal_status="completed",
        response_id=response_id,
        buffer_bytes=len(value),
    )


class ScriptedRunner:
    def __init__(self, *results: AttemptResult) -> None:
        self.results = list(results)
        self.calls = []

    async def run(self, snapshot, bearer, cancellation):
        self.calls.append((snapshot, bearer, cancellation))
        if not self.results:
            raise AssertionError("unexpected_attempt")
        return self.results.pop(0)


class BlockingRunner:
    def __init__(self, result: AttemptResult) -> None:
        self.result = result
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0
        self.bearers = []

    async def run(self, _snapshot, _bearer, _cancellation):
        self.calls += 1
        self.bearers.append(_bearer)
        self.entered.set()
        await self.release.wait()
        return self.result


class MutableSecretResolver:
    def __init__(self, values):
        self.values = dict(values)
        self.calls = []

    def resolve(self, secret_ref):
        self.calls.append(secret_ref)
        value = self.values.get(secret_ref)
        if not value:
            raise RuntimeError("guardian_upstream_credential_unavailable")
        return value


class FailOnceStateStore:
    def __init__(self) -> None:
        self.document = None
        self.fail_next = False

    def load(self):
        return self.document

    def save(self, document):
        if self.fail_next:
            self.fail_next = False
            raise BreakerStateStoreError("breaker_state_write_failed")
        self.document = json.loads(json.dumps(document))


def temporary_failure(*, status: int | None = 503, possible_double_charge: bool = False):
    return AttemptResult(
        failure=AttemptFailure(
            category="upstream_http_error" if status else "upstream_transport_error",
            public_code=f"guardian_upstream_http_{status}" if status else "guardian_upstream_transport_error",
            http_status=status,
            request_started=True,
            possible_double_charge=possible_double_charge,
        )
    )


def route(role: RouteRole, profile: str, runner, *, fingerprint: str | None = None) -> RouteConfig:
    return RouteConfig(
        role=role,
        profile_id=profile,
        fingerprint=fingerprint or f"fp-{profile}",
        adapter_name="openai-responses-v1",
        secret_ref=f"secret:{profile}",
        secret_suffix=profile[-4:],
        runner=runner,
    )


def group(primary, backup, *, revision: int = 1, evidence=None) -> FailoverGroupConfig:
    return FailoverGroupConfig(
        instance_id="instance-1",
        group_id="group-1",
        revision=revision,
        primary=primary,
        backup=backup,
        allowed_models=(FIXTURE_MODEL,),
        breaker_policy=CircuitBreakerPolicy(
            failure_threshold=1,
            minimum_samples=1,
            window_size=10,
            recovery_success_threshold=1,
            base_cooldown_seconds=30,
            max_cooldown_seconds=300,
            jitter_ratio=0,
        ),
        state_compatibility=evidence or {},
    )


def snapshot(*, previous_response_id: str | None = None):
    return create_request_snapshot(
        fixture_request(previous_response_id=previous_response_id),
        {"content-type": "application/json"},
        GatewayLimits(),
    )


def server_tool_snapshot():
    body = json.dumps(
        {
            "model": FIXTURE_MODEL,
            "input": "Synthetic server tool fixture.",
            "stream": True,
            "tools": [{"type": "web_search_preview"}],
        },
        separators=(",", ":"),
    ).encode()
    return create_request_snapshot(body, {"content-type": "application/json"}, GatewayLimits())


class FailoverRouterTests(unittest.IsolatedAsyncioTestCase):
    def router(self, value: FailoverGroupConfig, breaker=None):
        return FailoverRouter(
            value,
            breaker or CircuitBreakerRegistry(rng=lambda: 0),
            FailureClassifier(),
            InMemorySecretResolver({"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}),
            wall_clock=lambda: 1_700_000_000,
        )

    async def test_primary_success_never_calls_backup(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("resp_p1")))
        backup = ScriptedRunner(
            AttemptResult(complete=buffered("resp_p2")),
            AttemptResult(complete=buffered("resp_p2")),
        )
        routed = await self.router(group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))).execute(
            snapshot(), CancellationToken()
        )
        self.assertEqual(routed.complete.response_id, "resp_p1")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 0)
        self.assertFalse(routed.failover_used)

    async def test_missing_route_secret_stops_before_breaker_and_upstream(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("resp_primary")))
        backup = ScriptedRunner(AttemptResult(complete=buffered("must-not-run")))
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        router = FailoverRouter(
            value,
            CircuitBreakerRegistry(rng=lambda: 0),
            FailureClassifier(),
            InMemorySecretResolver({"secret:p1": FAKE_BEARER}),
        )
        with self.assertRaisesRegex(RuntimeError, "guardian_upstream_credential_unavailable"):
            await router.execute(snapshot(), CancellationToken())
        self.assertEqual(primary.calls, [])
        self.assertEqual(backup.calls, [])

    async def test_preopened_primary_does_not_require_its_secret_before_using_backup(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("must-not-run")))
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_backup")))
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        router = self.router(value, breaker)
        primary_key = RouteKey("instance-1", "group-1", "primary", "p1")
        admission = breaker.acquire(
            primary_key,
            config_revision=1,
            route_fingerprint="fp-p1",
            attempt_id="open-primary",
        )
        assert admission.ticket is not None
        breaker.record_action_required(
            admission.ticket,
            failure_category="upstream_http_error",
            http_status=401,
        )
        router._secrets = InMemorySecretResolver({"secret:p2": FAKE_BEARER})
        routed = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(routed.complete.response_id, "resp_backup")
        self.assertEqual(primary.calls, [])
        self.assertEqual(len(backup.calls), 1)
        self.assertEqual(routed.primary_admission.denied, AdmissionDenied.OPEN_ACTION_REQUIRED)

    async def test_credentials_are_snapshotted_before_primary_attempt(self) -> None:
        primary = BlockingRunner(temporary_failure())
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_backup")))
        resolver = MutableSecretResolver({"secret:p1": "primary-v1", "secret:p2": "backup-v1"})
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        router = FailoverRouter(
            value,
            CircuitBreakerRegistry(rng=lambda: 0),
            FailureClassifier(),
            resolver,
        )
        running = asyncio.create_task(router.execute(snapshot(), CancellationToken()))
        await asyncio.wait_for(primary.entered.wait(), timeout=1)
        resolver.values["secret:p2"] = "backup-v2"
        primary.release.set()
        result = await running
        self.assertEqual(result.complete.response_id, "resp_backup")
        self.assertEqual(primary.bearers[0], "primary-v1")
        self.assertEqual(backup.calls[0][1], "backup-v1")

    async def test_public_identity_and_repr_never_contain_secret_reference(self) -> None:
        primary = route(RouteRole.PRIMARY, "p1", ScriptedRunner())
        backup = route(RouteRole.BACKUP, "p2", ScriptedRunner())
        value = group(primary, backup)
        rendered = json.dumps(asdict(value.public_identity()), default=str)
        self.assertNotIn("secret:p1", repr(value))
        self.assertNotIn("secret:p1", rendered)
        self.assertNotIn(FAKE_BEARER, repr(value))
        self.assertNotIn("fp-p1", rendered)
        self.assertNotIn("fp-p2", rendered)

    async def test_retryable_primary_failure_uses_same_snapshot_once_on_backup(self) -> None:
        primary = ScriptedRunner(temporary_failure(possible_double_charge=True))
        backup_body = b"".join(tool_sse_frames(response_id="resp_backup_tool"))
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_backup_tool", backup_body)))
        routed = await self.router(group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))).execute(
            snapshot(), CancellationToken()
        )
        self.assertEqual(routed.complete.response_id, "resp_backup_tool")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 1)
        self.assertIs(primary.calls[0][0], backup.calls[0][0])
        self.assertEqual(primary.calls[0][0].body_sha256, backup.calls[0][0].body_sha256)
        self.assertEqual(len(routed.attempts), 2)
        self.assertEqual(len({attempt.attempt_id for attempt in routed.attempts}), 2)
        self.assertTrue(routed.failover_used)
        self.assertTrue(routed.possible_double_charge)

    async def test_rate_limit_uses_classifier_retry_after_for_breaker_deadline(self) -> None:
        now = datetime(2026, 7, 12, tzinfo=UTC)
        primary = ScriptedRunner(
            AttemptResult(
                failure=AttemptFailure(
                    category="upstream_http_error",
                    public_code="guardian_upstream_http_429",
                    http_status=429,
                    request_started=True,
                    retry_after="120",
                )
            )
        )
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_backup")))
        breaker = CircuitBreakerRegistry(clock=lambda: now, rng=lambda: 0)
        router = FailoverRouter(
            group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup)),
            breaker,
            FailureClassifier(),
            InMemorySecretResolver({"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}),
            wall_clock=lambda: now.timestamp(),
        )

        routed = await router.execute(snapshot(), CancellationToken())

        route_state = breaker.snapshot(RouteKey("instance-1", "group-1", "primary", "p1"))
        assert route_state is not None
        self.assertEqual(routed.complete.response_id, "resp_backup")
        self.assertEqual(routed.attempts[0].decision.retry_after_seconds, 120)
        self.assertEqual(route_state.state, BreakerState.OPEN_TEMPORARY)
        self.assertEqual(route_state.open_until, now + timedelta(seconds=120))

    async def test_persistence_failure_does_not_leak_guarded_router_ticket(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(complete=buffered("resp_before_store_failure")),
            AttemptResult(complete=buffered("resp_after_store_recovery")),
        )
        backup = ScriptedRunner(AttemptResult(complete=buffered("must-not-use-backup")))
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        router = self.router(
            group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup)),
            breaker,
        )
        store = FailOnceStateStore()
        breaker.attach_store(store)
        store.fail_next = True

        with self.assertRaisesRegex(BreakerStateStoreError, "breaker_state_write_failed"):
            await router.execute(snapshot(), CancellationToken())

        route_key = RouteKey("instance-1", "group-1", "primary", "p1")
        after_failure = breaker.snapshot(route_key)
        assert after_failure is not None
        self.assertFalse(after_failure.half_open_lease_active)

        recovered = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(recovered.complete.response_id, "resp_after_store_recovery")
        self.assertEqual(len(primary.calls), 2)
        self.assertEqual(len(backup.calls), 0)

    async def test_backup_attempt_requires_explicit_uncommitted_guard(self) -> None:
        primary = ScriptedRunner(temporary_failure())
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_backup")))
        router = self.router(group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup)))
        with self.assertRaisesRegex(RuntimeError, "backup_attempt_requires_uncommitted_response"):
            await router.execute(snapshot(), CancellationToken(), can_failover=lambda: False)
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 0)

    async def test_nonretryable_primary_error_never_calls_backup(self) -> None:
        primary = ScriptedRunner(temporary_failure(status=400))
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_p2")))
        routed = await self.router(group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))).execute(
            snapshot(), CancellationToken()
        )
        self.assertIsNone(routed.complete)
        self.assertEqual(routed.primary_failure.http_status, 400)
        self.assertEqual(len(backup.calls), 0)
        self.assertFalse(routed.failover_used)

    async def test_both_routes_fail_once_and_aggregate_flags(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(
                failure=AttemptFailure("upstream_http_error", "guardian_upstream_http_401", 401, request_started=True)
            )
        )
        backup = ScriptedRunner(temporary_failure(possible_double_charge=True))
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        routed = await self.router(value, breaker).execute(snapshot(), CancellationToken())
        self.assertIsNone(routed.complete)
        self.assertEqual(len(routed.attempts), 2)
        self.assertTrue(routed.action_required)
        self.assertFalse(routed.possible_double_charge)
        primary_state = breaker.snapshot(RouteKey("instance-1", "group-1", "primary", "p1"))
        backup_state = breaker.snapshot(RouteKey("instance-1", "group-1", "backup", "p2"))
        self.assertEqual(primary_state.state, BreakerState.OPEN_ACTION_REQUIRED)
        self.assertEqual(backup_state.state, BreakerState.OPEN_TEMPORARY)
        alerts = self.router(value, breaker).action_required_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].persistent)
        self.assertEqual(alerts[0].route_role, "primary")

    async def test_backup_failure_clears_stale_backup_carrying_alert(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(
                failure=AttemptFailure(
                    "upstream_http_error",
                    "guardian_upstream_http_401",
                    401,
                    request_started=True,
                )
            )
        )
        backup = ScriptedRunner(
            AttemptResult(complete=buffered("backup-success")),
            temporary_failure(),
        )
        router = self.router(
            group(
                route(RouteRole.PRIMARY, "p1", primary),
                route(RouteRole.BACKUP, "p2", backup),
            )
        )

        first = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(first.complete.response_id, "backup-success")
        self.assertTrue(router.action_required_alerts()[0].backup_carrying)

        second = await router.execute(snapshot(), CancellationToken())
        self.assertIsNone(second.complete)
        self.assertFalse(router.action_required_alerts()[0].backup_carrying)

    async def test_double_charge_requires_uncertain_primary_and_started_backup(self) -> None:
        primary = ScriptedRunner(temporary_failure(possible_double_charge=True))
        backup = ScriptedRunner(temporary_failure(possible_double_charge=True))
        routed = await self.router(
            group(
                route(RouteRole.PRIMARY, "p1", primary),
                route(RouteRole.BACKUP, "p2", backup),
            )
        ).execute(snapshot(), CancellationToken())
        self.assertTrue(routed.possible_double_charge)

    async def test_possible_server_tool_side_effect_blocks_automatic_backup_replay(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(
                failure=AttemptFailure(
                    "upstream_timeout",
                    "guardian_upstream_timeout",
                    request_started=True,
                    possible_double_charge=True,
                    possible_server_side_effects=True,
                )
            )
        )
        backup = ScriptedRunner(AttemptResult(complete=buffered("must-not-run")))
        routed = await self.router(
            group(
                route(RouteRole.PRIMARY, "p1", primary),
                route(RouteRole.BACKUP, "p2", backup),
            )
        ).execute(server_tool_snapshot(), CancellationToken())
        self.assertTrue(routed.replay_blocked)
        self.assertFalse(routed.failover_used)
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 0)

    async def test_server_tool_auth_rejection_can_still_fail_over(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(
                failure=AttemptFailure(
                    "upstream_http_error",
                    "guardian_upstream_http_401",
                    401,
                    request_started=True,
                )
            )
        )
        backup = ScriptedRunner(AttemptResult(complete=buffered("safe-backup")))
        routed = await self.router(
            group(
                route(RouteRole.PRIMARY, "p1", primary),
                route(RouteRole.BACKUP, "p2", backup),
            )
        ).execute(server_tool_snapshot(), CancellationToken())
        self.assertFalse(routed.replay_blocked)
        self.assertEqual(routed.complete.response_id, "safe-backup")
        self.assertEqual(len(backup.calls), 1)

    async def test_preopened_primary_is_skipped_and_backup_is_independent(self) -> None:
        primary = ScriptedRunner(temporary_failure())
        backup = ScriptedRunner(
            AttemptResult(complete=buffered("resp_p2")),
            AttemptResult(complete=buffered("resp_p2")),
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        first_router = self.router(value, breaker)
        first = await first_router.execute(snapshot(), CancellationToken())
        self.assertEqual(first.complete.response_id, "resp_p2")
        second = await self.router(value, breaker).execute(snapshot(), CancellationToken())
        self.assertEqual(second.complete.response_id, "resp_p2")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 2)

    async def test_cancel_never_calls_backup_or_counts_failure(self) -> None:
        primary = ScriptedRunner(AttemptResult(cancelled=CancelReason.CLIENT_DISCONNECTED))
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_p2")))
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        routed = await self.router(value, breaker).execute(snapshot(), CancellationToken())
        self.assertEqual(routed.cancelled, CancelReason.CLIENT_DISCONNECTED)
        self.assertEqual(len(backup.calls), 0)
        state = breaker.snapshot(RouteKey("instance-1", "group-1", "primary", "p1"))
        self.assertEqual(state.sample_count, 0)
        self.assertEqual(state.consecutive_failures, 0)

    async def test_backup_cancel_preserves_started_evidence_for_double_charge_flag(self) -> None:
        primary = ScriptedRunner(temporary_failure(possible_double_charge=True))
        backup = ScriptedRunner(
            AttemptResult(
                cancelled=CancelReason.CLIENT_DISCONNECTED,
                request_started=True,
            )
        )
        routed = await self.router(
            group(
                route(RouteRole.PRIMARY, "p1", primary),
                route(RouteRole.BACKUP, "p2", backup),
            )
        ).execute(snapshot(), CancellationToken())
        self.assertEqual(routed.cancelled, CancelReason.CLIENT_DISCONNECTED)
        self.assertTrue(routed.possible_double_charge)

    async def test_nested_state_references_block_before_breaker_and_upstream(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("must-not-run")))
        backup = ScriptedRunner(AttemptResult(complete=buffered("must-not-run")))
        payloads = (
            {"model": FIXTURE_MODEL, "input": [{"type": "item_reference", "id": "item_fixture"}]},
            {"model": FIXTURE_MODEL, "input": "fixture", "prompt": {"id": "pmpt_fixture"}},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                value = create_request_snapshot(
                    json.dumps(payload).encode(),
                    {"content-type": "application/json"},
                    GatewayLimits(),
                )
                router = self.router(
                    group(
                        route(RouteRole.PRIMARY, "p1", primary),
                        route(RouteRole.BACKUP, "p2", backup),
                    )
                )
                with self.assertRaises(StateCompatibilityError) as caught:
                    await router.execute(value, CancellationToken())
                self.assertEqual(caught.exception.code, "guardian_state_compatibility_unknown")
        self.assertEqual(primary.calls, [])
        self.assertEqual(backup.calls, [])

    async def test_state_dependency_is_blocked_before_breaker_or_upstream(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("resp_p1")))
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_p2")))
        for evidence, expected in (({}, "guardian_state_compatibility_unknown"), ({FIXTURE_MODEL: StateCompatibilityEvidence(
            status=StateCompatibility.INCOMPATIBLE,
            config_revision=1,
            primary_fingerprint="fp-p1",
            backup_fingerprint="fp-p2",
            adapter_name="openai-responses-v1",
            model=FIXTURE_MODEL,
        )}, "guardian_state_incompatible")):
            with self.subTest(expected=expected):
                value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup), evidence=evidence)
                with self.assertRaises(StateCompatibilityError) as caught:
                    await self.router(value).execute(snapshot(previous_response_id="resp_state"), CancellationToken())
                self.assertEqual(caught.exception.code, expected)
        self.assertEqual(primary.calls, [])
        self.assertEqual(backup.calls, [])

    async def test_shared_state_evidence_must_bind_both_directions_revision_fingerprints_adapter_model(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("resp_p1")))
        backup = ScriptedRunner(AttemptResult(complete=buffered("resp_p2")))
        primary_route = route(RouteRole.PRIMARY, "p1", primary)
        backup_route = route(RouteRole.BACKUP, "p2", backup)
        evidence = StateCompatibilityEvidence(
            status=StateCompatibility.SHARED,
            config_revision=1,
            primary_fingerprint="fp-p1",
            backup_fingerprint="fp-p2",
            adapter_name="openai-responses-v1",
            model=FIXTURE_MODEL,
            primary_to_backup=True,
            backup_to_primary=True,
        )
        value = group(primary_route, backup_route, evidence={FIXTURE_MODEL: evidence})
        routed = await self.router(value).execute(snapshot(previous_response_id="resp_state"), CancellationToken())
        self.assertEqual(routed.complete.response_id, "resp_p1")
        stale = replace(value, revision=2)
        with self.assertRaises(StateCompatibilityError) as caught:
            await self.router(stale).execute(snapshot(previous_response_id="resp_state"), CancellationToken())
        self.assertEqual(caught.exception.code, "guardian_state_compatibility_stale")

    async def test_action_required_route_requires_explicit_probe_signal(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(failure=AttemptFailure("upstream_http_error", "guardian_upstream_http_401", 401)),
            AttemptResult(complete=buffered("resp_probe")),
        )
        backup = ScriptedRunner(
            AttemptResult(complete=buffered("resp_backup")),
            AttemptResult(complete=buffered("resp_backup_after_probe")),
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        router = self.router(value, breaker)
        first = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(first.complete.response_id, "resp_backup")
        business = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(business.complete.response_id, "resp_backup_after_probe")
        self.assertEqual(len(primary.calls), 1)
        probe = await router.execute(
            create_probe_snapshot(
                FIXTURE_MODEL,
                GatewayLimits(),
                manual_billable_confirmation=True,
            ),
            CancellationToken(),
            signal=TrafficSignal.PROBE,
            probe_role=RouteRole.PRIMARY,
        )
        self.assertEqual(probe.complete.response_id, "resp_probe")
        self.assertEqual(probe.signal, TrafficSignal.PROBE)

    async def test_probe_signal_rejects_business_request_body(self) -> None:
        primary = ScriptedRunner(AttemptResult(complete=buffered("must-not-run")))
        backup = ScriptedRunner(AttemptResult(complete=buffered("must-not-run-either")))
        router = self.router(
            group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup))
        )
        with self.assertRaisesRegex(RuntimeError, "guardian_unsafe_probe_request"):
            await router.execute(snapshot(), CancellationToken(), signal=TrafficSignal.PROBE)
        self.assertEqual(primary.calls, [])
        self.assertEqual(backup.calls, [])

    def test_billable_probe_requires_policy_and_per_call_confirmation(self) -> None:
        default = ProbePolicy()
        self.assertFalse(default.enabled)
        self.assertEqual(default.mode, ProbeMode.MODELS)
        self.assertFalse(default.allow_billable)
        with self.assertRaisesRegex(ValueError, "billable_probe_requires_explicit_opt_in"):
            ProbePolicy(enabled=True, mode=ProbeMode.RESPONSES)
        policy = ProbePolicy(
            enabled=True,
            mode=ProbeMode.RESPONSES,
            allow_billable=True,
        )
        with self.assertRaisesRegex(ValueError, "billable_probe_requires_manual_confirmation"):
            create_probe_snapshot(FIXTURE_MODEL, GatewayLimits(), policy=policy)
        probe = create_probe_snapshot(
            FIXTURE_MODEL,
            GatewayLimits(),
            policy=policy,
            manual_billable_confirmation=True,
        )
        self.assertFalse(probe.stream)
        self.assertFalse(probe.state_dependencies)

    async def test_probe_requires_explicit_route_and_never_fails_over(self) -> None:
        primary = ScriptedRunner(temporary_failure())
        backup = ScriptedRunner(AttemptResult(complete=buffered("backup-probe-success")))
        router = self.router(
            group(
                route(RouteRole.PRIMARY, "p1", primary),
                route(RouteRole.BACKUP, "p2", backup),
            )
        )
        probe = create_probe_snapshot(
            FIXTURE_MODEL,
            GatewayLimits(),
            manual_billable_confirmation=True,
        )
        with self.assertRaisesRegex(RuntimeError, "guardian_probe_route_required"):
            await router.execute(probe, CancellationToken(), signal=TrafficSignal.PROBE)

        primary_result = await router.execute(
            probe,
            CancellationToken(),
            signal=TrafficSignal.PROBE,
            probe_role=RouteRole.PRIMARY,
        )
        self.assertIsNone(primary_result.complete)
        self.assertFalse(primary_result.failover_used)
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 0)

        backup_result = await router.execute(
            probe,
            CancellationToken(),
            signal=TrafficSignal.PROBE,
            probe_role=RouteRole.BACKUP,
        )
        self.assertEqual(backup_result.complete.response_id, "backup-probe-success")
        self.assertFalse(backup_result.failover_used)
        self.assertEqual(len(backup.calls), 1)

        with self.assertRaisesRegex(RuntimeError, "guardian_probe_route_requires_probe_signal"):
            await router.execute(snapshot(), CancellationToken(), probe_role=RouteRole.PRIMARY)
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 1)

    async def test_probe_success_does_not_clear_closed_business_failure_window(self) -> None:
        primary = ScriptedRunner(
            AttemptResult(complete=buffered("resp-business")),
            AttemptResult(complete=buffered("resp-probe")),
        )
        backup = ScriptedRunner(AttemptResult(complete=buffered("unused-backup")))
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = replace(
            group(route(RouteRole.PRIMARY, "p1", primary), route(RouteRole.BACKUP, "p2", backup)),
            breaker_policy=CircuitBreakerPolicy(
                failure_threshold=99,
                minimum_samples=10,
                window_size=20,
                recovery_success_threshold=2,
                base_cooldown_seconds=30,
                max_cooldown_seconds=300,
                jitter_ratio=0,
            ),
        )
        router = self.router(value, breaker)
        business = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(business.complete.response_id, "resp-business")
        key = RouteKey("instance-1", "group-1", "primary", "p1")
        failed = breaker.acquire(
            key,
            config_revision=1,
            route_fingerprint="fp-p1",
            attempt_id="business-failure",
        )
        breaker.record_temporary_failure(
            failed.ticket,
            failure_category="upstream_http_error",
            http_status=503,
        )
        before = breaker.snapshot(key)
        probe = await router.execute(
            create_probe_snapshot(
                FIXTURE_MODEL,
                GatewayLimits(),
                manual_billable_confirmation=True,
            ),
            CancellationToken(),
            signal=TrafficSignal.PROBE,
            probe_role=RouteRole.PRIMARY,
        )
        after = breaker.snapshot(key)
        self.assertEqual(probe.complete.response_id, "resp-probe")
        for field in (
            "sample_count",
            "failure_count",
            "consecutive_failures",
            "consecutive_protocol_failures",
            "first_failed_at",
            "last_failed_at",
            "last_failure_category",
            "last_http_status",
        ):
            self.assertEqual(getattr(after, field), getattr(before, field), field)

    async def test_half_open_busy_primary_routes_other_requests_to_backup(self) -> None:
        primary_runner = BlockingRunner(AttemptResult(complete=buffered("resp_probe")))
        backup_runner = ScriptedRunner(AttemptResult(complete=buffered("resp_backup")))
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        value = group(route(RouteRole.PRIMARY, "p1", primary_runner), route(RouteRole.BACKUP, "p2", backup_runner))
        router = self.router(value, breaker)
        key = RouteKey("instance-1", "group-1", "primary", "p1")
        admission = breaker.acquire(key, config_revision=1, route_fingerprint="fp-p1", attempt_id="seed")
        breaker.record_temporary_failure(admission.ticket, failure_category="upstream_timeout")
        snapshot_state = breaker.snapshot(key)
        clock = breaker._clock
        breaker._clock = lambda: snapshot_state.open_until
        first = asyncio.create_task(router.execute(snapshot(), CancellationToken()))
        await asyncio.wait_for(primary_runner.entered.wait(), timeout=1)
        second = await router.execute(snapshot(), CancellationToken())
        self.assertEqual(second.complete.response_id, "resp_backup")
        self.assertEqual(primary_runner.calls, 1)
        primary_runner.release.set()
        self.assertEqual((await first).complete.response_id, "resp_probe")
        breaker._clock = clock

    async def test_atomic_config_activation_preserves_inflight_snapshot(self) -> None:
        old_runner = BlockingRunner(AttemptResult(complete=buffered("resp_old")))
        old_backup = ScriptedRunner(AttemptResult(complete=buffered("resp_old_backup")))
        old_config = group(route(RouteRole.PRIMARY, "p1", old_runner), route(RouteRole.BACKUP, "p2", old_backup))
        holder = AtomicGroupConfig(old_config)
        old_router = self.router(holder.snapshot())
        in_flight = asyncio.create_task(old_router.execute(snapshot(), CancellationToken()))
        await asyncio.wait_for(old_runner.entered.wait(), timeout=1)

        new_runner = ScriptedRunner(AttemptResult(complete=buffered("resp_new")))
        new_backup = ScriptedRunner(AttemptResult(complete=buffered("resp_new_backup")))
        new_config = group(
            route(RouteRole.PRIMARY, "p1", new_runner),
            route(RouteRole.BACKUP, "p2", new_backup),
            revision=2,
        )
        holder.activate(new_config)
        fresh = await self.router(holder.snapshot()).execute(snapshot(), CancellationToken())
        self.assertEqual(fresh.complete.response_id, "resp_new")
        old_runner.release.set()
        old = await in_flight
        self.assertEqual(old.complete.response_id, "resp_old")
        self.assertEqual(old_runner.calls, 1)
        self.assertEqual(len(new_runner.calls), 1)

    async def test_shared_breaker_hot_revision_preserves_old_backup_snapshot(self) -> None:
        old_primary = BlockingRunner(temporary_failure())
        old_backup = ScriptedRunner(AttemptResult(complete=buffered("resp_old_backup")))
        old_config = group(
            route(RouteRole.PRIMARY, "p1", old_primary),
            route(RouteRole.BACKUP, "p2", old_backup),
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        old_router = self.router(old_config, breaker)
        old_request = asyncio.create_task(old_router.execute(snapshot(), CancellationToken()))
        await asyncio.wait_for(old_primary.entered.wait(), timeout=1)

        new_primary = ScriptedRunner(AttemptResult(complete=buffered("resp_new")))
        new_backup = ScriptedRunner(AttemptResult(complete=buffered("resp_new_backup")))
        new_config = group(
            route(RouteRole.PRIMARY, "p1", new_primary, fingerprint="fp-p1-v2"),
            route(RouteRole.BACKUP, "p2", new_backup, fingerprint="fp-p2-v2"),
            revision=2,
        )
        new_router = self.router(new_config, breaker)
        fresh = await new_router.execute(snapshot(), CancellationToken())
        self.assertEqual(fresh.complete.response_id, "resp_new")

        old_primary.release.set()
        old = await old_request
        self.assertEqual(old.complete.response_id, "resp_old_backup")
        self.assertEqual(len(old_backup.calls), 1)

    async def test_independent_routers_use_globally_unique_attempt_ids(self) -> None:
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        seeded = group(
            route(RouteRole.PRIMARY, "p1", ScriptedRunner(AttemptResult(complete=buffered("resp_seed")))),
            route(RouteRole.BACKUP, "p2", ScriptedRunner(AttemptResult(complete=buffered("unused-seed")))),
        )
        await self.router(seeded, breaker).execute(snapshot(), CancellationToken())
        first_runner = BlockingRunner(AttemptResult(complete=buffered("resp_first")))
        second_runner = BlockingRunner(AttemptResult(complete=buffered("resp_second")))
        first_config = group(
            route(RouteRole.PRIMARY, "p1", first_runner),
            route(RouteRole.BACKUP, "p2", ScriptedRunner(AttemptResult(complete=buffered("unused-1")))),
        )
        second_config = group(
            route(RouteRole.PRIMARY, "p1", second_runner),
            route(RouteRole.BACKUP, "p2", ScriptedRunner(AttemptResult(complete=buffered("unused-2")))),
        )
        first_router = self.router(first_config, breaker)
        first = asyncio.create_task(first_router.execute(snapshot(), CancellationToken()))
        await asyncio.wait_for(first_runner.entered.wait(), timeout=1)
        second_router = self.router(second_config, breaker)
        second = asyncio.create_task(second_router.execute(snapshot(), CancellationToken()))
        await asyncio.wait_for(second_runner.entered.wait(), timeout=1)
        first_runner.release.set()
        first_result = await first
        self.assertEqual(first_result.complete.response_id, "resp_first")
        second_runner.release.set()
        second_result = await second
        self.assertEqual(second_result.complete.response_id, "resp_second")
        self.assertNotEqual(first_result.attempts[0].attempt_id, second_result.attempts[0].attempt_id)


if __name__ == "__main__":
    unittest.main()
