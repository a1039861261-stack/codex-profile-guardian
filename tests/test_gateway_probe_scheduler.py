from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest

from gateway.adapter import OpenAIResponsesAdapter
from gateway.breaker import BreakerState, CircuitBreakerPolicy, CircuitBreakerRegistry, RouteKey
from gateway.config import FailoverGroupConfig, ProbePolicy, RouteConfig, RouteRole
from gateway.probe_scheduler import ModelsProbeScheduler


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


class FakeContent:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def read(self, maximum: int) -> bytes:
        return self.payload[:maximum]


class FakeResponse:
    def __init__(self, status: int, payload: bytes, *, content_length: int | None = None) -> None:
        self.status = status
        self.content_length = len(payload) if content_length is None else content_length
        self.content = FakeContent(payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exception_type, _exception, _traceback) -> None:
        return None


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.urls: list[str] = []

    def get(self, url: str, **_kwargs) -> FakeResponse:
        self.urls.append(url)
        return self.response


class DummyRunner:
    def __init__(self) -> None:
        self._adapter = OpenAIResponsesAdapter("https://fixture.invalid/v1")


class ModelsProbeSchedulerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.breaker = CircuitBreakerRegistry(clock=self.clock, rng=lambda: 0)
        self.policy = CircuitBreakerPolicy(
            failure_threshold=1,
            protocol_failure_threshold=1,
            error_rate_threshold=None,
            minimum_samples=1,
            window_size=4,
            recovery_success_threshold=1,
            base_cooldown_seconds=10,
            max_cooldown_seconds=20,
            jitter_ratio=0,
        )
        self.primary = RouteConfig(
            role=RouteRole.PRIMARY,
            profile_id="probe-primary",
            fingerprint="probe-primary-fingerprint",
            adapter_name="openai-responses-v1",
            secret_ref="profile:probe-primary",
            runner=DummyRunner(),
        )
        self.backup = RouteConfig(
            role=RouteRole.BACKUP,
            profile_id="probe-backup",
            fingerprint="probe-backup-fingerprint",
            adapter_name="openai-responses-v1",
            secret_ref="profile:probe-backup",
            runner=DummyRunner(),
        )
        self.config = FailoverGroupConfig(
            instance_id="probe-instance",
            group_id="probe-group",
            revision=1,
            primary=self.primary,
            backup=self.backup,
            allowed_models=("fixture-model",),
            breaker_policy=self.policy,
            probe_policy=ProbePolicy(enabled=True, interval_seconds=30, timeout_seconds=1),
        )
        for route in (self.primary, self.backup):
            self.breaker.configure_route(
                self.key(route),
                config_revision=1,
                route_fingerprint=route.fingerprint,
                policy=self.policy,
            )

    def key(self, route: RouteConfig) -> RouteKey:
        return RouteKey(
            self.config.instance_id,
            self.config.group_id,
            route.role.value,
            route.profile_id,
        )

    def scheduler(self, response: FakeResponse) -> ModelsProbeScheduler:
        return ModelsProbeScheduler(
            config_provider=lambda: self.config,
            breaker=self.breaker,
            session=FakeSession(response),
            resolve_secret=lambda _reference: "fixture-bearer",
        )

    def snapshot(self, route: RouteConfig | None = None):
        target = route or self.primary
        value = self.breaker.snapshot(self.key(target))
        self.assertIsNotNone(value)
        return value

    def admit_business(self, attempt_id: str):
        admission = self.breaker.acquire(
            self.key(self.primary),
            config_revision=1,
            route_fingerprint=self.primary.fingerprint,
            attempt_id=attempt_id,
        )
        self.assertTrue(admission.allowed)
        self.assertIsNotNone(admission.ticket)
        return admission.ticket

    async def test_successful_unknown_probe_closes_route(self) -> None:
        result = await self.scheduler(FakeResponse(200, b'{"data":[]}'))._probe_route(
            self.config,
            self.primary,
        )
        self.assertTrue(result.ok)
        self.assertEqual(self.snapshot().state, BreakerState.CLOSED)

    async def test_models_failure_does_not_override_unknown_or_closed_business_state(self) -> None:
        unknown = await self.scheduler(FakeResponse(401, b"denied"))._probe_route(
            self.config,
            self.primary,
        )
        self.assertFalse(unknown.ok)
        self.assertEqual(self.snapshot().state, BreakerState.UNKNOWN)

        success = self.admit_business("business-success")
        self.breaker.record_success(success)
        closed = await self.scheduler(FakeResponse(503, b"unavailable"))._probe_route(
            self.config,
            self.primary,
        )
        self.assertFalse(closed.ok)
        self.assertEqual(self.snapshot().state, BreakerState.CLOSED)

    async def test_half_open_probe_failure_reopens_temporary_breaker(self) -> None:
        failed = self.admit_business("business-failure")
        self.breaker.record_temporary_failure(failed, failure_category="network_error")
        self.clock.advance(10)
        result = await self.scheduler(FakeResponse(503, b"unavailable"))._probe_route(
            self.config,
            self.primary,
        )
        self.assertFalse(result.ok)
        snapshot = self.snapshot()
        self.assertEqual(snapshot.state, BreakerState.OPEN_TEMPORARY)
        self.assertEqual(snapshot.last_failure_category, "upstream_5xx")

    async def test_action_required_probe_failure_preserves_redline(self) -> None:
        failed = self.admit_business("auth-failure")
        self.breaker.record_action_required(
            failed,
            failure_category="auth_rejected",
            http_status=401,
        )
        enabled = self.config.probe_policy.__class__(
            enabled=True,
            interval_seconds=30,
            timeout_seconds=1,
            allow_action_required_auto_retest=True,
        )
        self.config = FailoverGroupConfig(
            instance_id=self.config.instance_id,
            group_id=self.config.group_id,
            revision=self.config.revision,
            primary=self.primary,
            backup=self.backup,
            allowed_models=self.config.allowed_models,
            breaker_policy=self.policy,
            probe_policy=enabled,
        )
        result = await self.scheduler(FakeResponse(401, b"denied"))._probe_route(
            self.config,
            self.primary,
        )
        self.assertFalse(result.ok)
        snapshot = self.snapshot()
        self.assertEqual(snapshot.state, BreakerState.OPEN_ACTION_REQUIRED)
        self.assertTrue(snapshot.action_required)

    async def test_explicit_manual_retest_targets_only_selected_role(self) -> None:
        failed = self.admit_business("auth-failure")
        self.breaker.record_action_required(
            failed,
            failure_category="auth_rejected",
            http_status=401,
        )
        session = FakeSession(FakeResponse(200, b'{"data":[]}'))
        scheduler = ModelsProbeScheduler(
            config_provider=lambda: self.config,
            breaker=self.breaker,
            session=session,
            resolve_secret=lambda _reference: "fixture-bearer",
        )

        result = await scheduler.probe_role(RouteRole.PRIMARY)

        self.assertTrue(result.ok)
        self.assertEqual(session.urls, ["https://fixture.invalid/v1/models"])
        self.assertEqual(self.snapshot().state, BreakerState.CLOSED)
        self.assertEqual(self.snapshot(self.backup).state, BreakerState.UNKNOWN)

    async def test_large_half_open_response_is_bounded_and_reopens(self) -> None:
        failed = self.admit_business("business-failure")
        self.breaker.record_temporary_failure(failed, failure_category="network_error")
        self.clock.advance(10)
        response = FakeResponse(
            200,
            b"x",
            content_length=ModelsProbeScheduler._MAX_RESPONSE_BYTES + 1,
        )
        result = await self.scheduler(response)._probe_route(self.config, self.primary)
        self.assertEqual(result.category, "probe_response_too_large")
        self.assertEqual(self.snapshot().state, BreakerState.OPEN_TEMPORARY)


if __name__ == "__main__":
    unittest.main()
