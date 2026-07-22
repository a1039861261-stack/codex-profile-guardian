from __future__ import annotations

import json
import unittest

from gateway.breaker import CircuitBreakerPolicy, CircuitBreakerRegistry, RouteKey
from gateway.cancellation import CancellationToken
from gateway.commit import Committer
from gateway.config import FailoverGroupConfig, RouteConfig, RouteRole
from gateway.failures import FailureClassifier
from gateway.journal import MemoryEventJournal
from gateway.models import AttemptFailure, AttemptResult, CommitState, GatewayError, GatewayLimits
from gateway.router import FailoverRouter
from gateway.secrets import InMemorySecretResolver
from gateway.service import FailoverGatewayCore
from tests.gateway_probe_support import FAKE_BEARER, FIXTURE_MODEL, fixture_request
from tests.test_gateway_core import RecordingDownstream, _buffered
from tests.test_gateway_router import ScriptedRunner


def build_core(primary_results, backup_results, *, breaker=None):
    primary = ScriptedRunner(*primary_results)
    backup = ScriptedRunner(*backup_results)
    policy = CircuitBreakerPolicy(
        failure_threshold=1,
        minimum_samples=1,
        window_size=10,
        recovery_success_threshold=1,
        base_cooldown_seconds=30,
        max_cooldown_seconds=300,
        jitter_ratio=0,
    )
    group = FailoverGroupConfig(
        instance_id="instance-1",
        group_id="group-1",
        revision=1,
        primary=RouteConfig(
            RouteRole.PRIMARY,
            "p1",
            "fp-p1",
            "openai-responses-v1",
            "secret:p1",
            primary,
            "p1xx",
        ),
        backup=RouteConfig(
            RouteRole.BACKUP,
            "p2",
            "fp-p2",
            "openai-responses-v1",
            "secret:p2",
            backup,
            "p2xx",
        ),
        allowed_models=(FIXTURE_MODEL,),
        breaker_policy=policy,
    )
    breaker = breaker or CircuitBreakerRegistry(rng=lambda: 0)
    router = FailoverRouter(
        group,
        breaker,
        FailureClassifier(),
        InMemorySecretResolver({"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}),
        wall_clock=lambda: 1_700_000_000,
    )
    journal = MemoryEventJournal()
    return FailoverGatewayCore(router, GatewayLimits(), journal), primary, backup, journal, breaker


class FailoverGatewayCoreTests(unittest.IsolatedAsyncioTestCase):
    async def proxy(self, core):
        downstream = RecordingDownstream()
        committer = Committer()
        result = await core.proxy(
            fixture_request(),
            {"content-type": "application/json"},
            "unused",
            downstream,
            CancellationToken(),
            committer,
        )
        return result, downstream, committer

    async def test_primary_failure_backup_success_commits_once(self) -> None:
        primary_failure = AttemptResult(
            failure=AttemptFailure("upstream_http_error", "guardian_upstream_http_503", 503, request_started=True)
        )
        core, primary, backup, journal, _breaker = build_core(
            [primary_failure],
            [AttemptResult(complete=_buffered(b"backup-complete"))],
        )
        result, downstream, committer = await self.proxy(core)
        self.assertEqual(result.state, CommitState.DELIVERED)
        self.assertEqual(committer.state, CommitState.DELIVERED)
        self.assertEqual(downstream.body, b"backup-complete")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 1)
        events = journal.snapshot()
        self.assertEqual([event["event"] for event in events], [
            "request_received", "attempt_finished", "attempt_finished", "commit_finished"
        ])
        self.assertTrue(events[-1]["failover_used"])
        self.assertEqual(
            [(event["breaker_before"], event["breaker_after"]) for event in events[1:3]],
            [("unknown", "open_temporary"), ("unknown", "closed")],
        )

    async def test_both_routes_failed_commits_one_redacted_error(self) -> None:
        primary_failure = AttemptResult(
            failure=AttemptFailure("upstream_http_error", "guardian_upstream_http_401", 401, request_started=True)
        )
        backup_failure = AttemptResult(
            failure=AttemptFailure(
                "upstream_timeout",
                "guardian_upstream_timeout",
                request_started=True,
                possible_double_charge=True,
            )
        )
        core, primary, backup, _journal, _breaker = build_core([primary_failure], [backup_failure])
        result, downstream, committer = await self.proxy(core)
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 503)
        self.assertEqual(payload["error"]["code"], "guardian_all_routes_failed")
        self.assertFalse(payload["error"]["possible_double_charge"])
        self.assertTrue(payload["error"]["action_required"])
        self.assertEqual([item["role"] for item in payload["error"]["attempts"]], ["primary", "backup"])
        rendered = downstream.body.decode("utf-8")
        self.assertNotIn(FAKE_BEARER, rendered)
        self.assertNotIn("fixture input", rendered)
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 1)

    async def test_nonretryable_primary_error_remains_original_and_backup_zero(self) -> None:
        failure = AttemptResult(
            failure=AttemptFailure("upstream_http_error", "guardian_upstream_http_400", 400, request_started=True)
        )
        core, _primary, backup, _journal, _breaker = build_core(
            [failure],
            [AttemptResult(complete=_buffered(b"must-not-run"))],
        )
        result, downstream, committer = await self.proxy(core)
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 400)
        self.assertEqual(payload["error"]["code"], "guardian_upstream_http_400")
        self.assertEqual(len(backup.calls), 0)

    async def test_missing_backup_credential_returns_local_500_before_any_attempt(self) -> None:
        core, primary, backup, _journal, _breaker = build_core(
            [AttemptResult(complete=_buffered(b"must-not-run"))],
            [AttemptResult(complete=_buffered(b"must-not-run"))],
        )
        core._router._secrets = InMemorySecretResolver({"secret:p1": FAKE_BEARER})
        result, downstream, committer = await self.proxy(core)
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 500)
        self.assertEqual(payload["error"]["code"], "guardian_upstream_credential_unavailable")
        self.assertEqual(len(primary.calls), 0)
        self.assertEqual(len(backup.calls), 0)

    async def test_server_side_tool_replay_block_returns_explicit_error_and_backup_zero(self) -> None:
        failure = AttemptResult(
            failure=AttemptFailure(
                "upstream_timeout",
                "guardian_upstream_timeout",
                request_started=True,
                possible_double_charge=True,
                possible_server_side_effects=True,
            )
        )
        core, _primary, backup, _journal, _breaker = build_core(
            [failure],
            [AttemptResult(complete=_buffered(b"must-not-run"))],
        )
        body = json.dumps(
            {
                "model": FIXTURE_MODEL,
                "input": "Synthetic server tool fixture.",
                "stream": True,
                "tools": [{"type": "web_search_preview"}],
            },
            separators=(",", ":"),
        ).encode()
        downstream = RecordingDownstream()
        committer = Committer()
        result = await core.proxy(
            body,
            {"content-type": "application/json"},
            "unused",
            downstream,
            CancellationToken(),
            committer,
        )
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 409)
        self.assertEqual(payload["error"]["code"], "guardian_automatic_replay_blocked")
        self.assertEqual(len(backup.calls), 0)

    async def test_preopened_routes_return_one_503_with_both_unavailable_reasons(self) -> None:
        core, primary, backup, _journal, breaker = build_core(
            [AttemptResult(complete=_buffered(b"unused-primary"))],
            [AttemptResult(complete=_buffered(b"unused-backup"))],
        )
        for role, profile, fingerprint in (
            ("primary", "p1", "fp-p1"),
            ("backup", "p2", "fp-p2"),
        ):
            admission = breaker.acquire(
                RouteKey("instance-1", "group-1", role, profile),
                config_revision=1,
                route_fingerprint=fingerprint,
                attempt_id=f"seed-{role}",
            )
            breaker.record_action_required(admission.ticket, failure_category="auth_rejected")
        result, downstream, _committer = await self.proxy(core)
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 503)
        self.assertEqual(
            payload["error"]["attempts"],
            [
                {"role": "primary", "category": "breaker_open_action_required"},
                {"role": "backup", "category": "breaker_open_action_required"},
            ],
        )
        self.assertEqual(len(primary.calls), 0)
        self.assertEqual(len(backup.calls), 0)

    async def test_preopened_primary_backup_nonretryable_4xx_is_preserved(self) -> None:
        failure = AttemptResult(
            failure=AttemptFailure("upstream_http_error", "guardian_upstream_http_409", 409, request_started=True)
        )
        core, primary, backup, _journal, breaker = build_core(
            [AttemptResult(complete=_buffered(b"unused-primary"))],
            [failure],
        )
        admission = breaker.acquire(
            RouteKey("instance-1", "group-1", "primary", "p1"),
            config_revision=1,
            route_fingerprint="fp-p1",
            attempt_id="seed-primary",
        )
        breaker.record_action_required(admission.ticket, failure_category="auth_rejected")
        result, downstream, committer = await self.proxy(core)
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 409)
        self.assertEqual(payload["error"]["code"], "guardian_upstream_http_409")
        self.assertEqual(len(primary.calls), 0)
        self.assertEqual(len(backup.calls), 1)

    async def test_actual_primary_and_backup_failures_are_aggregated_even_when_backup_is_4xx(self) -> None:
        primary_failure = AttemptResult(
            failure=AttemptFailure(
                "upstream_http_error",
                "guardian_upstream_http_503",
                503,
                request_started=True,
            )
        )
        backup_failure = AttemptResult(
            failure=AttemptFailure(
                "upstream_http_error",
                "guardian_upstream_http_400",
                400,
                request_started=True,
            )
        )
        core, primary, backup, _journal, _breaker = build_core([primary_failure], [backup_failure])
        result, downstream, committer = await self.proxy(core)
        payload = json.loads(downstream.body)
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(committer.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 502)
        self.assertEqual(payload["error"]["code"], "guardian_all_routes_failed")
        self.assertEqual(
            payload["error"]["attempts"],
            [
                {"role": "primary", "category": "upstream_http_error", "http_status": 503},
                {"role": "backup", "category": "upstream_http_error", "http_status": 400},
            ],
        )
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(backup.calls), 1)


if __name__ == "__main__":
    unittest.main()
