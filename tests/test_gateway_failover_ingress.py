from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import socket
import unittest
from typing import Callable

import aiohttp
from aiohttp.test_utils import TestClient, TestServer

from gateway.adapter import OpenAIResponsesAdapter
from gateway.attempts import SingleRouteAttemptRunner
from gateway.breaker import BreakerState, CircuitBreakerPolicy, CircuitBreakerRegistry, RouteKey
from gateway.cancellation import CancellationToken
from gateway.commit import Committer, DownstreamWriter
from gateway.config import FailoverGroupConfig, RouteConfig, RouteRole
from gateway.failures import FailureClassifier
from gateway.ingress import GatewayIngress
from gateway.models import BufferedResponse, CommitState, GatewayLimits
from gateway.protocols.responses import validate_buffered_response
from gateway.router import FailoverRouter
from gateway.secrets import InMemorySecretResolver
from gateway.service import FailoverGatewayCore
from tests.gateway_probe_support import (
    FAKE_BEARER,
    FIXTURE_MODEL,
    ProgrammableResponsesMock,
    ScenarioControl,
    ScriptedScenario,
    fixture_request,
    missing_terminal_scenario,
    terminal_sse_frames,
    text_sse_frames,
    tool_sse_frames,
    truncated_tool_scenario,
)


INGRESS_TOKEN = "fixture-failover-ingress-token"


class _WriteFailureDownstream:
    def __init__(self, downstream: DownstreamWriter) -> None:
        self._downstream = downstream

    async def prepare(self, status: int, content_type: str, content_length: int) -> None:
        await self._downstream.prepare(status, content_type, content_length)

    async def write(self, _chunk: bytes) -> None:
        raise ConnectionResetError("synthetic_downstream_commit_failure")

    async def finish(self) -> None:
        raise AssertionError("finish_must_not_follow_failed_write")


class _WriteFailingCommitter(Committer):
    async def commit(
        self,
        response: BufferedResponse,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
    ):
        return await super().commit(
            response,
            _WriteFailureDownstream(downstream),
            cancellation,
        )


@dataclass
class _IngressStack:
    primary: ProgrammableResponsesMock
    backup: ProgrammableResponsesMock
    upstream_session: aiohttp.ClientSession
    breaker: CircuitBreakerRegistry
    core: FailoverGatewayCore
    ingress: GatewayIngress
    client: TestClient
    committers: list[Committer]

    async def close(self) -> None:
        await self.client.close()
        await self.upstream_session.close()
        self.primary.close()
        self.backup.close()


class FailoverIngressIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.limits = GatewayLimits(
            max_request_bytes=1024 * 1024,
            max_response_bytes=1024 * 1024,
            read_chunk_bytes=97,
            max_concurrent_requests=2,
            connect_timeout_seconds=1,
            first_byte_timeout_seconds=1,
            idle_timeout_seconds=2,
            total_timeout_seconds=5,
        )
        self.stacks: list[_IngressStack] = []

    async def asyncTearDown(self) -> None:
        for stack in reversed(self.stacks):
            await stack.close()

    async def _start_stack(
        self,
        primary_scenario: ScriptedScenario,
        backup_scenario: ScriptedScenario,
        *,
        committer_builder: Callable[[], Committer] | None = None,
        breaker_policy: CircuitBreakerPolicy | None = None,
    ) -> _IngressStack:
        primary = ProgrammableResponsesMock(
            lambda _request: primary_scenario,
            route_name="P1",
        ).start()
        backup = ProgrammableResponsesMock(
            lambda _request: backup_scenario,
            route_name="P2",
        ).start()
        upstream_session = aiohttp.ClientSession()
        primary_runner = SingleRouteAttemptRunner(
            upstream_session,
            OpenAIResponsesAdapter(primary.base_url),
            self.limits,
        )
        backup_runner = SingleRouteAttemptRunner(
            upstream_session,
            OpenAIResponsesAdapter(backup.base_url),
            self.limits,
        )
        policy = breaker_policy or CircuitBreakerPolicy(
            failure_threshold=1,
            protocol_failure_threshold=1,
            error_rate_threshold=None,
            minimum_samples=1,
            window_size=8,
            recovery_success_threshold=1,
            base_cooldown_seconds=30,
            max_cooldown_seconds=300,
            jitter_ratio=0,
        )
        group = FailoverGroupConfig(
            instance_id="fixture-instance",
            group_id="fixture-group",
            revision=1,
            primary=RouteConfig(
                RouteRole.PRIMARY,
                "fixture-p1",
                "fixture-p1-fingerprint",
                "openai-responses-v1",
                "secret:p1",
                primary_runner,
            ),
            backup=RouteConfig(
                RouteRole.BACKUP,
                "fixture-p2",
                "fixture-p2-fingerprint",
                "openai-responses-v1",
                "secret:p2",
                backup_runner,
            ),
            allowed_models=(FIXTURE_MODEL,),
            breaker_policy=policy,
        )
        breaker = CircuitBreakerRegistry(rng=lambda: 0)
        router = FailoverRouter(
            group,
            breaker,
            FailureClassifier(),
            InMemorySecretResolver(
                {"secret:p1": FAKE_BEARER, "secret:p2": FAKE_BEARER}
            ),
        )
        core = FailoverGatewayCore(router, self.limits)
        committers: list[Committer] = []

        def new_committer() -> Committer:
            committer = (
                committer_builder()
                if committer_builder is not None
                else Committer(chunk_bytes=self.limits.read_chunk_bytes)
            )
            committers.append(committer)
            return committer

        ingress = GatewayIngress(
            core,
            self.limits,
            ingress_token=INGRESS_TOKEN,
            committer_factory=new_committer,
        )
        client = TestClient(TestServer(ingress.create_app(), handler_cancellation=True))
        try:
            await client.start_server()
        except BaseException:
            await upstream_session.close()
            primary.close()
            backup.close()
            raise
        stack = _IngressStack(
            primary,
            backup,
            upstream_session,
            breaker,
            core,
            ingress,
            client,
            committers,
        )
        self.stacks.append(stack)
        return stack

    @staticmethod
    def _headers() -> dict[str, str]:
        return {
            "Authorization": f"Bearer {INGRESS_TOKEN}",
            "Content-Type": "application/json",
        }

    async def _post(self, stack: _IngressStack) -> tuple[int, str, bytes]:
        response = await stack.client.post(
            "/v1/responses",
            data=fixture_request(),
            headers=self._headers(),
        )
        return response.status, response.headers["Content-Type"], await response.read()

    async def test_primary_503_delivers_only_complete_backup_response(self) -> None:
        primary_scenario = ScriptedScenario(
            name="primary_503",
            status=503,
            content_type="application/json",
            chunks=(b'{"private":"discarded-primary-error"}',),
        )
        backup_scenario = ScriptedScenario(
            name="backup_complete",
            chunks=text_sse_frames(
                "BACKUP_AFTER_503",
                response_id="resp_backup_after_503",
            ),
        )
        stack = await self._start_stack(primary_scenario, backup_scenario)

        status, content_type, body = await self._post(stack)

        self.assertEqual(status, 200)
        self.assertTrue(content_type.startswith("text/event-stream"))
        self.assertEqual(body, b"".join(backup_scenario.chunks))
        self.assertNotIn(b"discarded-primary-error", body)
        self.assertEqual(stack.primary.request_count, 1)
        self.assertEqual(stack.backup.request_count, 1)
        self.assertEqual([item.state for item in stack.committers], [CommitState.DELIVERED])

    async def test_primary_protocol_interruption_delivers_only_complete_backup_response(self) -> None:
        primary_scenario = missing_terminal_scenario(response_id="resp_primary_cut_off")
        backup_scenario = ScriptedScenario(
            name="backup_complete",
            chunks=text_sse_frames(
                "BACKUP_AFTER_PROTOCOL_CUTOFF",
                response_id="resp_backup_after_cutoff",
            ),
        )
        stack = await self._start_stack(primary_scenario, backup_scenario)

        status, content_type, body = await self._post(stack)

        self.assertEqual(status, 200)
        self.assertTrue(content_type.startswith("text/event-stream"))
        self.assertEqual(body, b"".join(backup_scenario.chunks))
        self.assertNotIn(b"resp_primary_cut_off", body)
        self.assertEqual(stack.primary.request_count, 1)
        self.assertEqual(stack.backup.request_count, 1)
        self.assertEqual([item.state for item in stack.committers], [CommitState.DELIVERED])

    async def test_complete_failed_and_incomplete_results_never_call_backup(self) -> None:
        for terminal_status in ("failed", "incomplete"):
            with self.subTest(terminal_status=terminal_status):
                primary_scenario = ScriptedScenario(
                    name=f"primary_complete_{terminal_status}",
                    chunks=terminal_sse_frames(
                        terminal_status,
                        response_id=f"resp_primary_{terminal_status}",
                    ),
                )
                backup_scenario = ScriptedScenario(
                    name="backup_must_not_run",
                    chunks=text_sse_frames("BACKUP_MUST_NOT_RUN"),
                )
                stack = await self._start_stack(primary_scenario, backup_scenario)

                status, content_type, body = await self._post(stack)
                validated = validate_buffered_response(status, content_type, (body,))

                self.assertEqual(body, b"".join(primary_scenario.chunks))
                self.assertEqual(validated.terminal_type, f"response.{terminal_status}")
                self.assertEqual(validated.response_id, f"resp_primary_{terminal_status}")
                self.assertEqual(stack.primary.request_count, 1)
                self.assertEqual(stack.backup.request_count, 0)
                self.assertEqual(
                    [item.state for item in stack.committers],
                    [CommitState.DELIVERED],
                )

    async def test_both_routes_fail_commits_one_guardian_all_routes_failed(self) -> None:
        primary_scenario = ScriptedScenario(
            name="primary_503",
            status=503,
            content_type="application/json",
            chunks=(b'{"secret":"primary-private-body"}',),
        )
        backup_scenario = ScriptedScenario(
            name="backup_504",
            status=504,
            content_type="application/json",
            chunks=(b'{"secret":"backup-private-body"}',),
        )
        stack = await self._start_stack(primary_scenario, backup_scenario)

        status, content_type, body = await self._post(stack)
        payload = json.loads(body)

        self.assertEqual(status, 503)
        self.assertTrue(content_type.startswith("application/json"))
        self.assertEqual(body.count(b"guardian_all_routes_failed"), 1)
        self.assertEqual(payload["error"]["code"], "guardian_all_routes_failed")
        self.assertEqual(
            [(attempt["role"], attempt["http_status"]) for attempt in payload["error"]["attempts"]],
            [("primary", 503), ("backup", 504)],
        )
        self.assertNotIn(b"primary-private-body", body)
        self.assertNotIn(b"backup-private-body", body)
        self.assertEqual(stack.primary.request_count, 1)
        self.assertEqual(stack.backup.request_count, 1)
        self.assertEqual([item.state for item in stack.committers], [CommitState.ERROR_COMMITTED])

    async def test_truncated_primary_tool_delivers_one_complete_backup_tool_call(self) -> None:
        backup_arguments = '{"query":"fixture-only"}'
        backup_scenario = ScriptedScenario(
            name="backup_tool_complete",
            chunks=tool_sse_frames(
                response_id="resp_backup_tool_only",
                item_id="fc_backup_tool_only",
                call_id="call_backup_tool_only",
                name="fixture_backup_lookup",
                arguments=backup_arguments,
            ),
        )
        stack = await self._start_stack(truncated_tool_scenario(), backup_scenario)

        status, content_type, body = await self._post(stack)
        validated = validate_buffered_response(status, content_type, (body,))

        self.assertEqual(body, b"".join(backup_scenario.chunks))
        self.assertEqual(len(validated.tool_calls), 1)
        self.assertEqual(validated.tool_calls[0].item_id, "fc_backup_tool_only")
        self.assertEqual(validated.tool_calls[0].call_id, "call_backup_tool_only")
        self.assertEqual(validated.tool_calls[0].name, "fixture_backup_lookup")
        self.assertEqual(validated.tool_calls[0].arguments, backup_arguments)
        self.assertNotIn(b"fc_g2_tool", body)
        self.assertNotIn(b"call_g2_tool", body)
        self.assertEqual(stack.primary.request_count, 1)
        self.assertEqual(stack.backup.request_count, 1)
        self.assertEqual([item.state for item in stack.committers], [CommitState.DELIVERED])

    async def test_tool_failover_is_deterministic_across_100_full_ingress_runs(self) -> None:
        backup_arguments = '{"query":"fixture-only"}'
        backup_scenario = ScriptedScenario(
            name="backup_tool_complete_100_runs",
            chunks=tool_sse_frames(
                response_id="resp_backup_tool_100_runs",
                item_id="fc_backup_tool_100_runs",
                call_id="call_backup_tool_100_runs",
                name="fixture_backup_lookup",
                arguments=backup_arguments,
            ),
        )
        stack = await self._start_stack(
            truncated_tool_scenario(),
            backup_scenario,
            breaker_policy=CircuitBreakerPolicy(
                failure_threshold=101,
                protocol_failure_threshold=101,
                error_rate_threshold=None,
                minimum_samples=1,
                window_size=128,
                recovery_success_threshold=1,
                base_cooldown_seconds=30,
                max_cooldown_seconds=300,
                jitter_ratio=0,
            ),
        )

        for _ in range(100):
            status, content_type, body = await self._post(stack)
            validated = validate_buffered_response(status, content_type, (body,))

            self.assertEqual(body, b"".join(backup_scenario.chunks))
            self.assertEqual(len(validated.tool_calls), 1)
            self.assertEqual(validated.tool_calls[0].item_id, "fc_backup_tool_100_runs")
            self.assertEqual(validated.tool_calls[0].call_id, "call_backup_tool_100_runs")
            self.assertEqual(validated.tool_calls[0].name, "fixture_backup_lookup")
            self.assertEqual(validated.tool_calls[0].arguments, backup_arguments)
            self.assertNotIn(b"fc_g2_tool", body)
            self.assertNotIn(b"call_g2_tool", body)

        expected_hash = hashlib.sha256(fixture_request()).hexdigest()
        self.assertEqual(stack.primary.request_count, 100)
        self.assertEqual(stack.backup.request_count, 100)
        self.assertEqual(
            {request.body_sha256 for request in stack.primary.requests},
            {expected_hash},
        )
        self.assertEqual(
            {request.body_sha256 for request in stack.backup.requests},
            {expected_hash},
        )
        self.assertEqual(
            [committer.state for committer in stack.committers],
            [CommitState.DELIVERED] * 100,
        )

    async def test_precommit_client_disconnect_cancels_primary_without_backup_request(self) -> None:
        control = ScenarioControl()
        primary_frames = text_sse_frames(
            "PRIMARY_MUST_NEVER_COMMIT",
            response_id="resp_primary_waiting",
        )
        primary_scenario = ScriptedScenario(
            name="primary_waiting_before_terminal",
            chunks=primary_frames,
            wait_before_chunk=len(primary_frames) - 1,
            control=control,
        )
        backup_scenario = ScriptedScenario(
            name="backup_must_not_run",
            chunks=text_sse_frames("BACKUP_MUST_NOT_RUN"),
        )
        stack = await self._start_stack(primary_scenario, backup_scenario)
        body = fixture_request()
        host, port = stack.client.server.host, stack.client.server.port

        def disconnect_before_commit() -> None:
            request = (
                f"POST /v1/responses HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Authorization: Bearer {INGRESS_TOKEN}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + body
            downstream = socket.create_connection((host, port), timeout=3)
            try:
                downstream.sendall(request)
                if not control.partial_sent.wait(3):
                    raise AssertionError("primary_partial_response_not_observed")
            finally:
                try:
                    downstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                downstream.close()

        try:
            await asyncio.to_thread(disconnect_before_commit)
            for _ in range(300):
                if (
                    control.client_disconnected.is_set()
                    and stack.core.active_requests == 0
                    and stack.ingress.active_requests == 0
                ):
                    break
                await asyncio.sleep(0.01)

            self.assertTrue(control.client_disconnected.is_set())
            self.assertEqual(stack.primary.request_count, 1)
            self.assertEqual(stack.backup.request_count, 0)
            self.assertEqual(stack.core.active_requests, 0)
            self.assertEqual(stack.ingress.active_requests, 0)
            self.assertEqual(len(stack.committers), 1)
            self.assertEqual(stack.committers[0].state, CommitState.UNCOMMITTED)
        finally:
            control.release_terminal.set()

    async def test_disconnect_after_backup_starts_cancels_without_breaker_failure(self) -> None:
        control = ScenarioControl()
        backup_frames = text_sse_frames(
            "BACKUP_MUST_NEVER_COMMIT",
            response_id="resp_backup_waiting",
        )
        backup_scenario = ScriptedScenario(
            name="backup_waiting_before_terminal",
            chunks=backup_frames,
            wait_before_chunk=len(backup_frames) - 1,
            control=control,
        )
        stack = await self._start_stack(
            missing_terminal_scenario(response_id="resp_primary_incomplete"),
            backup_scenario,
        )
        body = fixture_request()
        host, port = stack.client.server.host, stack.client.server.port

        def disconnect_during_backup() -> None:
            request = (
                f"POST /v1/responses HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Authorization: Bearer {INGRESS_TOKEN}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + body
            downstream = socket.create_connection((host, port), timeout=3)
            try:
                downstream.sendall(request)
                if not control.partial_sent.wait(3):
                    raise AssertionError("backup_partial_response_not_observed")
            finally:
                try:
                    downstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                downstream.close()

        try:
            await asyncio.to_thread(disconnect_during_backup)
            for _ in range(300):
                if (
                    control.client_disconnected.is_set()
                    and stack.core.active_requests == 0
                    and stack.ingress.active_requests == 0
                ):
                    break
                await asyncio.sleep(0.01)

            backup_state = stack.breaker.snapshot(
                RouteKey(
                    "fixture-instance",
                    "fixture-group",
                    "backup",
                    "fixture-p2",
                )
            )
            cancellation_events = [
                event
                for event in stack.core.journal.snapshot()
                if event["event"] == "request_cancelled"
            ]
            self.assertTrue(control.client_disconnected.is_set())
            self.assertEqual(stack.primary.request_count, 1)
            self.assertEqual(stack.backup.request_count, 1)
            self.assertEqual(stack.core.active_requests, 0)
            self.assertEqual(stack.ingress.active_requests, 0)
            self.assertEqual(len(stack.committers), 1)
            self.assertEqual(stack.committers[0].state, CommitState.UNCOMMITTED)
            self.assertIsNotNone(backup_state)
            self.assertEqual(backup_state.state, BreakerState.UNKNOWN)
            self.assertEqual(backup_state.failure_count, 0)
            self.assertEqual(backup_state.consecutive_failures, 0)
            self.assertEqual(len(cancellation_events), 1)
            self.assertTrue(cancellation_events[0]["possible_double_charge"])
        finally:
            control.release_terminal.set()

    async def test_commit_write_failure_is_delivery_uncertain_without_backup_request(self) -> None:
        primary_scenario = ScriptedScenario(
            name="primary_complete",
            chunks=text_sse_frames(
                "PRIMARY_COMPLETE_BEFORE_COMMIT_FAILURE",
                response_id="resp_primary_before_commit_failure",
            ),
        )
        backup_scenario = ScriptedScenario(
            name="backup_must_not_run",
            chunks=text_sse_frames("BACKUP_MUST_NOT_RUN"),
        )
        stack = await self._start_stack(
            primary_scenario,
            backup_scenario,
            committer_builder=lambda: _WriteFailingCommitter(
                chunk_bytes=self.limits.read_chunk_bytes
            ),
        )
        body = fixture_request()
        host, port = stack.client.server.host, stack.client.server.port

        def read_truncated_commit() -> bytes:
            request = (
                f"POST /v1/responses HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Authorization: Bearer {INGRESS_TOKEN}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + body
            received = bytearray()
            with socket.create_connection((host, port), timeout=3) as downstream:
                downstream.sendall(request)
                downstream.settimeout(3)
                while True:
                    chunk = downstream.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            return bytes(received)

        received = await asyncio.to_thread(read_truncated_commit)
        for _ in range(300):
            if stack.core.active_requests == 0 and stack.ingress.active_requests == 0:
                break
            await asyncio.sleep(0.01)

        self.assertTrue(received.startswith(b"HTTP/1.1 200"))
        self.assertNotIn(b"response.completed", received)
        self.assertEqual(stack.primary.request_count, 1)
        self.assertEqual(stack.backup.request_count, 0)
        self.assertEqual(len(stack.committers), 1)
        self.assertEqual(stack.committers[0].state, CommitState.DELIVERY_UNCERTAIN)
        self.assertEqual(stack.core.active_requests, 0)
        self.assertEqual(stack.ingress.active_requests, 0)


if __name__ == "__main__":
    unittest.main()
