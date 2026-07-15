from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import threading
import unittest

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.adapter import OpenAIResponsesAdapter
from gateway.attempts import SingleRouteAttemptRunner
from gateway.buffer import BoundedMemoryBuffer
from gateway.cancellation import CancellationToken, RequestCancelled
from gateway.commit import Committer
from gateway.ingress import GatewayIngress
from gateway.journal import GatewayEvent, MemoryEventJournal
from gateway.models import (
    BufferedResponse,
    CancelReason,
    CommitState,
    AttemptResult,
    GatewayError,
    GatewayLimits,
    RequestSnapshot,
)
from gateway.request_snapshot import create_request_snapshot
from gateway.service import SingleRouteGatewayCore
from tests.gateway_probe_support import (
    FAKE_BEARER,
    FIXTURE_MODEL,
    ProgrammableResponsesMock,
    ScenarioControl,
    ScriptedScenario,
    fixture_request,
    json_scenario,
    missing_terminal_scenario,
    text_sse_frames,
    tool_sse_frames,
    truncated_tool_scenario,
)


class RecordingDownstream:
    def __init__(
        self,
        *,
        fail_after_bytes: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.prepared = False
        self.status: int | None = None
        self.content_type: str | None = None
        self.content_length: int | None = None
        self.body = bytearray()
        self.finished = False
        self.fail_after_bytes = fail_after_bytes
        self.failure = failure

    async def prepare(self, status: int, content_type: str, content_length: int) -> None:
        self.prepared = True
        self.status = status
        self.content_type = content_type
        self.content_length = content_length

    async def write(self, chunk: bytes) -> None:
        if self.fail_after_bytes is not None and len(self.body) >= self.fail_after_bytes:
            raise self.failure or BrokenPipeError
        self.body.extend(chunk)

    async def finish(self) -> None:
        self.finished = True


def _buffered(body: bytes = b"validated response") -> BufferedResponse:
    return BufferedResponse(
        status=200,
        content_type="application/octet-stream",
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        terminal_status="completed",
        response_id="resp_g3_fixture",
        buffer_bytes=len(body),
    )


def _error_buffered(body: bytes = b'{"error":{"code":"fixture"}}', *, status: int = 503) -> BufferedResponse:
    return BufferedResponse(
        status=status,
        content_type="application/json",
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        terminal_status="gateway_error",
        response_id="",
        buffer_bytes=len(body),
    )


class RequestSnapshotTests(unittest.TestCase):
    def test_snapshot_is_immutable_and_filters_sensitive_transport_headers(self) -> None:
        body = fixture_request()
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer local-ingress-secret",
            "Cookie": "private-cookie",
            "Host": "127.0.0.1",
            "OpenAI-Beta": "responses=v1",
        }
        snapshot = create_request_snapshot(body, headers, GatewayLimits())
        self.assertEqual(snapshot.model, FIXTURE_MODEL)
        self.assertTrue(snapshot.stream)
        self.assertEqual(dict(snapshot.forward_headers), {"openai-beta": "responses=v1"})
        self.assertEqual(snapshot.body_sha256, hashlib.sha256(body).hexdigest())
        with self.assertRaises(TypeError):
            snapshot.forward_headers["cookie"] = "forbidden"

    def test_snapshot_rejects_invalid_mime_json_model_and_size(self) -> None:
        limits = GatewayLimits(max_request_bytes=16)
        with self.assertRaises(GatewayError) as too_large:
            create_request_snapshot(b"x" * 17, {"content-type": "application/json"}, limits)
        self.assertEqual(too_large.exception.code, "guardian_request_too_large")
        for body, headers, expected in (
            (b"{}", {"content-type": "text/plain"}, "guardian_unsupported_media_type"),
            (b"not-json", {"content-type": "application/json"}, "guardian_invalid_request"),
            (b"{}", {"content-type": "application/json"}, "guardian_invalid_model"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(GatewayError) as caught:
                    create_request_snapshot(body, headers, GatewayLimits())
                self.assertEqual(caught.exception.code, expected)

        for model in ("x" * 257, "bad\nmodel"):
            body = json.dumps({"model": model, "input": "fixture", "stream": True}).encode("utf-8")
            with self.subTest(model_length=len(model)):
                with self.assertRaises(GatewayError) as caught:
                    create_request_snapshot(body, {"content-type": "application/json"}, GatewayLimits())
                self.assertEqual(caught.exception.code, "guardian_invalid_model")

    def test_state_dependencies_are_metadata_only(self) -> None:
        body = fixture_request(previous_response_id="resp_fixture")
        snapshot = create_request_snapshot(body, {"content-type": "application/json"}, GatewayLimits())
        self.assertEqual(snapshot.state_dependencies, ("previous_response_id",))
        self.assertNotIn("resp_fixture", repr(snapshot.state_dependencies))

    def test_state_dependency_detection_covers_nested_and_adapter_owned_references(self) -> None:
        cases = (
            ({"prompt": {"id": "pmpt_fixture"}}, "prompt"),
            ({"conversation": "conv_fixture"}, "conversation"),
            ({"input": [{"type": "item_reference", "id": "item_fixture"}]}, "item_reference"),
            ({"input": [{"type": "reasoning", "id": "rs_fixture"}]}, "input_item_id"),
            ({"input": [{"content": [{"type": "future_reference", "id": "fixture"}]}]}, "unknown_reference"),
            ({"tools": [{"type": "file_search", "vector_store_ids": ["vs_fixture"]}]}, "vector_store_ids"),
            ({"tools": [{"type": "code_interpreter", "container": "cntr_fixture"}]}, "container"),
            ({"tools": [{"type": "mcp", "connector_id": "connector_fixture"}]}, "connector_id"),
        )
        for addition, expected in cases:
            with self.subTest(expected=expected):
                payload = {"model": FIXTURE_MODEL, "input": "fixture"}
                payload.update(addition)
                value = create_request_snapshot(
                    json.dumps(payload).encode(),
                    {"content-type": "application/json"},
                    GatewayLimits(),
                )
                self.assertIn(expected, value.state_dependencies)
                self.assertNotIn("fixture", repr(value.state_dependencies))
        auto_container = create_request_snapshot(
            json.dumps(
                {
                    "model": FIXTURE_MODEL,
                    "input": "fixture",
                    "tools": [{"type": "code_interpreter", "container": {"type": "auto"}}],
                }
            ).encode(),
            {"content-type": "application/json"},
            GatewayLimits(),
        )
        self.assertNotIn("container", auto_container.state_dependencies)

    def test_server_side_tool_risk_is_conservative_and_function_tools_remain_replayable(self) -> None:
        function_body = json.dumps(
            {"model": FIXTURE_MODEL, "input": "fixture", "tools": [{"type": "function", "name": "fixture"}]}
        ).encode()
        server_body = json.dumps(
            {"model": FIXTURE_MODEL, "input": "fixture", "tools": [{"type": "web_search_preview"}]}
        ).encode()
        malformed_body = json.dumps(
            {"model": FIXTURE_MODEL, "input": "fixture", "tools": [{"name": "unknown"}]}
        ).encode()
        function_snapshot = create_request_snapshot(
            function_body,
            {"content-type": "application/json"},
            GatewayLimits(),
        )
        self.assertFalse(function_snapshot.has_server_side_tool_risk)
        for body in (server_body, malformed_body):
            with self.subTest(body=body):
                value = create_request_snapshot(body, {"content-type": "application/json"}, GatewayLimits())
                self.assertTrue(value.has_server_side_tool_risk)

    def test_public_constructor_defensively_freezes_mutable_inputs(self) -> None:
        source_body = bytearray(b"{}")
        source_headers = {"x-client-request-id": "before"}
        source_dependencies = ["previous_response_id"]
        snapshot = RequestSnapshot(
            body=source_body,
            body_sha256=hashlib.sha256(source_body).hexdigest(),
            model=FIXTURE_MODEL,
            stream=True,
            forward_headers=source_headers,
            state_dependencies=source_dependencies,
        )
        source_body[:] = b"[]"
        source_headers["x-client-request-id"] = "after"
        source_dependencies.append("conversation")
        self.assertEqual(snapshot.body, b"{}")
        self.assertEqual(dict(snapshot.forward_headers), {"x-client-request-id": "before"})
        self.assertEqual(snapshot.state_dependencies, ("previous_response_id",))
        with self.assertRaises(TypeError):
            snapshot.forward_headers["x-client-request-id"] = "forbidden"


class AdapterTests(unittest.TestCase):
    def test_adapter_rejects_ambiguous_or_sensitive_base_urls(self) -> None:
        for base_url in (
            "https://user:pass@example.invalid/v1",
            "https://example.invalid/v1?token=fixture",
            "https://example.invalid/v1#fragment",
            "https://example.invalid/v1/v1",
            "http://example.invalid/v1",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    OpenAIResponsesAdapter(base_url)

    def test_adapter_rejects_header_control_characters_in_bearer(self) -> None:
        adapter = OpenAIResponsesAdapter("http://127.0.0.1:1/v1")
        snapshot = create_request_snapshot(
            fixture_request(),
            {"content-type": "application/json"},
            GatewayLimits(),
        )
        with self.assertRaises(GatewayError) as caught:
            adapter.build_request(snapshot, "fixture\r\nheader: injected")
        self.assertEqual(caught.exception.code, "guardian_upstream_credential_unavailable")

    def test_adapter_action_required_404_is_explicit_and_profile_scoped(self) -> None:
        ordinary = OpenAIResponsesAdapter("http://127.0.0.1:1/v1")
        adapted = OpenAIResponsesAdapter(
            "http://127.0.0.1:1/v1",
            action_required_statuses=frozenset({404}),
        )
        self.assertFalse(ordinary.is_action_required_status(404))
        self.assertTrue(adapted.is_action_required_status(404))
        with self.assertRaises(ValueError):
            OpenAIResponsesAdapter(
                "http://127.0.0.1:1/v1",
                action_required_statuses=frozenset({400}),
            )


class BufferAndCommitterTests(unittest.IsolatedAsyncioTestCase):
    async def test_memory_buffer_has_hard_limit_and_no_spool(self) -> None:
        cancellation = CancellationToken()
        buffer = BoundedMemoryBuffer(4)
        buffer.append(b"ab", cancellation)
        buffer.append(b"cd", cancellation)
        self.assertEqual(buffer.seal(), (b"ab", b"cd"))
        self.assertFalse(hasattr(buffer, "spool"))

        overflow = BoundedMemoryBuffer(3)
        overflow.append(b"ab", cancellation)
        with self.assertRaises(GatewayError) as caught:
            overflow.append(b"cd", cancellation)
        self.assertEqual(caught.exception.code, "guardian_response_too_large")
        self.assertEqual(overflow.size, 0)

    async def test_cancelled_buffer_rejects_append(self) -> None:
        cancellation = CancellationToken()
        cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
        with self.assertRaises(RequestCancelled):
            BoundedMemoryBuffer(8).append(b"x", cancellation)

    async def test_committer_is_the_only_one_way_commit_and_rejects_second_commit(self) -> None:
        downstream = RecordingDownstream()
        committer = Committer(chunk_bytes=4)
        result = await committer.commit(_buffered(b"abcdefgh"), downstream, CancellationToken())
        self.assertEqual(result.state, CommitState.DELIVERED)
        self.assertEqual(bytes(downstream.body), b"abcdefgh")
        self.assertTrue(downstream.finished)
        with self.assertRaises(RuntimeError):
            await committer.commit(_buffered(), RecordingDownstream(), CancellationToken())

    async def test_same_committer_commits_structured_error_once(self) -> None:
        downstream = RecordingDownstream()
        committer = Committer(chunk_bytes=4)
        result = await committer.commit_error(_error_buffered(), downstream, CancellationToken())
        self.assertEqual(result.state, CommitState.ERROR_COMMITTED)
        self.assertEqual(downstream.status, 503)
        self.assertIn(b"fixture", downstream.body)
        with self.assertRaises(RuntimeError):
            await committer.commit(_buffered(), RecordingDownstream(), CancellationToken())

    async def test_precommit_cancel_writes_zero_and_commit_failure_is_uncertain(self) -> None:
        cancelled = CancellationToken()
        cancelled.cancel(CancelReason.CLIENT_DISCONNECTED)
        downstream = RecordingDownstream()
        with self.assertRaises(RequestCancelled):
            await Committer().commit(_buffered(), downstream, cancelled)
        self.assertFalse(downstream.prepared)
        self.assertEqual(downstream.body, b"")

        broken = RecordingDownstream(fail_after_bytes=4)
        result = await Committer(chunk_bytes=4).commit(_buffered(b"abcdefgh"), broken, CancellationToken())
        self.assertEqual(result.state, CommitState.DELIVERY_UNCERTAIN)
        self.assertEqual(bytes(broken.body), b"abcd")

        runtime_failure = RecordingDownstream(fail_after_bytes=0, failure=RuntimeError("fixture_writer_failed"))
        runtime_committer = Committer(chunk_bytes=4)
        result = await runtime_committer.commit(_buffered(b"abcd"), runtime_failure, CancellationToken())
        self.assertEqual(result.state, CommitState.DELIVERY_UNCERTAIN)
        self.assertEqual(runtime_committer.state, CommitState.DELIVERY_UNCERTAIN)
        self.assertEqual(result.error_type, "RuntimeError")

    async def test_cancel_after_first_commit_chunk_is_delivery_uncertain(self) -> None:
        cancellation = CancellationToken()

        class CancellingDownstream(RecordingDownstream):
            async def write(self, chunk: bytes) -> None:
                await super().write(chunk)
                cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)

        downstream = CancellingDownstream()
        committer = Committer(chunk_bytes=4)
        result = await committer.commit(_buffered(b"abcdefgh"), downstream, cancellation)
        self.assertEqual(result.state, CommitState.DELIVERY_UNCERTAIN)
        self.assertEqual(bytes(downstream.body), b"abcd")
        self.assertFalse(downstream.finished)

    async def test_cancel_during_finish_is_delivery_uncertain(self) -> None:
        cancellation = CancellationToken()

        class CancellingFinishDownstream(RecordingDownstream):
            async def finish(self) -> None:
                self.finished = True
                cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)

        downstream = CancellingFinishDownstream()
        committer = Committer(chunk_bytes=4)
        result = await committer.commit(_buffered(b"abcd"), downstream, cancellation)
        self.assertEqual(result.state, CommitState.DELIVERY_UNCERTAIN)
        self.assertEqual(bytes(downstream.body), b"abcd")
        self.assertTrue(downstream.finished)


class AttemptRunnerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session = aiohttp.ClientSession()

    async def asyncTearDown(self) -> None:
        await self.session.close()

    def _runner(self, base_url: str, *, max_response_bytes: int = 1024 * 1024) -> SingleRouteAttemptRunner:
        limits = GatewayLimits(
            max_response_bytes=max_response_bytes,
            read_chunk_bytes=257,
            connect_timeout_seconds=2,
            first_byte_timeout_seconds=2,
            idle_timeout_seconds=2,
            total_timeout_seconds=5,
        )
        return SingleRouteAttemptRunner(self.session, OpenAIResponsesAdapter(base_url), limits)

    async def test_single_route_buffers_text_and_tool_before_returning_complete(self) -> None:
        for scenario, response_id in (
            (
                ScriptedScenario(
                    name="text",
                    chunks=text_sse_frames("G3_TEXT_OK", response_id="resp_g3_text"),
                ),
                "resp_g3_text",
            ),
            (
                ScriptedScenario(name="tool", chunks=tool_sse_frames(response_id="resp_g3_tool")),
                "resp_g3_tool",
            ),
            (json_scenario(response_id="resp_g3_json", text="G3_JSON_OK"), "resp_g3_json"),
        ):
            with self.subTest(response_id=response_id):
                with ProgrammableResponsesMock(
                    lambda _request, scenario=scenario: scenario
                ) as upstream:
                    snapshot = create_request_snapshot(
                        fixture_request(),
                        {"content-type": "application/json"},
                        GatewayLimits(),
                    )
                    result = await self._runner(upstream.base_url).run(snapshot, FAKE_BEARER, CancellationToken())
                self.assertIsNotNone(result.complete)
                self.assertEqual(result.complete.response_id, response_id)
                self.assertEqual(upstream.request_count, 1)

    async def test_missing_terminal_and_overflow_never_return_complete(self) -> None:
        for scenario, limit, expected in (
            (missing_terminal_scenario(), 1024 * 1024, "guardian_upstream_protocol_error"),
            (ScriptedScenario(name="large", chunks=text_sse_frames("x" * 4096)), 64, "guardian_response_too_large"),
        ):
            with self.subTest(expected=expected):
                with ProgrammableResponsesMock(lambda _request, scenario=scenario: scenario) as upstream:
                    snapshot = create_request_snapshot(
                        fixture_request(),
                        {"content-type": "application/json"},
                        GatewayLimits(),
                    )
                    result = await self._runner(upstream.base_url, max_response_bytes=limit).run(
                        snapshot,
                        FAKE_BEARER,
                        CancellationToken(),
                    )
                self.assertIsNone(result.complete)
                self.assertIsNotNone(result.failure)
                self.assertEqual(result.failure.public_code, expected)

    async def test_cancel_stops_single_attempt_and_never_creates_another(self) -> None:
        control = ScenarioControl()
        frames = text_sse_frames("G3_CANCEL")
        scenario = ScriptedScenario(
            name="cancel",
            chunks=frames,
            wait_before_chunk=len(frames) - 1,
            control=control,
        )
        with ProgrammableResponsesMock(lambda _request: scenario) as upstream:
            snapshot = create_request_snapshot(
                fixture_request(),
                {"content-type": "application/json"},
                GatewayLimits(),
            )
            cancellation = CancellationToken()
            task = asyncio.create_task(self._runner(upstream.base_url).run(snapshot, FAKE_BEARER, cancellation))
            observed = await asyncio.to_thread(control.partial_sent.wait, 3)
            self.assertTrue(observed)
            cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
            result = await asyncio.wait_for(task, 3)
            control.release_terminal.set()
        self.assertEqual(result.cancelled, CancelReason.CLIENT_DISCONNECTED)
        self.assertEqual(upstream.request_count, 1)

    async def test_cancelling_caller_task_cancels_and_awaits_child_operation(self) -> None:
        child_finished = asyncio.Event()

        async def child_operation() -> None:
            try:
                await asyncio.Event().wait()
            finally:
                child_finished.set()

        runner = self._runner("http://127.0.0.1:1/v1")
        task = asyncio.create_task(
            runner._await_with_cancel(child_operation(), CancellationToken(), timeout=60)
        )
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(child_finished.wait(), timeout=1)

    async def test_client_cancel_wins_simultaneous_transport_failure(self) -> None:
        runner = self._runner("http://127.0.0.1:1/v1")
        for _ in range(100):
            operation = asyncio.get_running_loop().create_future()
            cancellation = CancellationToken()
            task = asyncio.create_task(runner._await_with_cancel(operation, cancellation, timeout=1))
            await asyncio.sleep(0)
            cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
            operation.set_exception(OSError("simultaneous-fixture-transport-failure"))
            with self.assertRaises(RequestCancelled) as caught:
                await task
            self.assertEqual(caught.exception.reason, CancelReason.CLIENT_DISCONNECTED)

    async def test_upstream_http_status_is_preserved_without_parsing_error_body(self) -> None:
        for status in (401, 403, 429, 503):
            scenario = ScriptedScenario(
                name=f"http_{status}",
                status=status,
                content_type="application/json",
                chunks=(b'{"private":"must-not-be-classified-from-body"}',),
            )
            with self.subTest(status=status):
                with ProgrammableResponsesMock(lambda _request, scenario=scenario: scenario) as upstream:
                    snapshot = create_request_snapshot(
                        fixture_request(),
                        {"content-type": "application/json"},
                        GatewayLimits(),
                    )
                    result = await self._runner(upstream.base_url).run(
                        snapshot,
                        FAKE_BEARER,
                        CancellationToken(),
                    )
                self.assertIsNotNone(result.failure)
                self.assertEqual(result.failure.category, "upstream_http_error")
                self.assertEqual(result.failure.http_status, status)
                self.assertEqual(result.failure.public_code, f"guardian_upstream_http_{status}")

    async def test_first_byte_idle_and_total_timeouts_are_enforced(self) -> None:
        frames = text_sse_frames("G3_TIMEOUT")
        cases = (
            (
                "first_byte",
                ScriptedScenario(name="first_byte", chunks=frames, chunk_delays=(0.12,)),
                GatewayLimits(
                    read_chunk_bytes=257,
                    connect_timeout_seconds=1,
                    first_byte_timeout_seconds=0.03,
                    idle_timeout_seconds=0.2,
                    total_timeout_seconds=0.3,
                ),
            ),
            (
                "idle",
                ScriptedScenario(name="idle", chunks=frames, chunk_delays=(0.0, 0.12)),
                GatewayLimits(
                    read_chunk_bytes=257,
                    connect_timeout_seconds=1,
                    first_byte_timeout_seconds=0.1,
                    idle_timeout_seconds=0.03,
                    total_timeout_seconds=0.3,
                ),
            ),
            (
                "total",
                ScriptedScenario(
                    name="total",
                    chunks=frames,
                    chunk_delays=tuple(0.025 for _ in frames),
                ),
                GatewayLimits(
                    read_chunk_bytes=257,
                    connect_timeout_seconds=1,
                    first_byte_timeout_seconds=0.04,
                    idle_timeout_seconds=0.05,
                    total_timeout_seconds=0.06,
                ),
            ),
        )
        for name, scenario, limits in cases:
            with self.subTest(name=name):
                with ProgrammableResponsesMock(lambda _request, scenario=scenario: scenario) as upstream:
                    snapshot = create_request_snapshot(
                        fixture_request(),
                        {"content-type": "application/json"},
                        limits,
                    )
                    runner = SingleRouteAttemptRunner(
                        self.session,
                        OpenAIResponsesAdapter(upstream.base_url),
                        limits,
                    )
                    result = await runner.run(snapshot, FAKE_BEARER, CancellationToken())
                self.assertIsNotNone(result.failure)
                self.assertEqual(result.failure.category, "upstream_timeout")
                self.assertEqual(result.failure.public_code, "guardian_upstream_timeout")
                self.assertTrue(result.failure.possible_double_charge)
                self.assertEqual(
                    result.failure.possible_server_side_effects,
                    result.failure.request_started,
                )


class GatewayCoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_core_commits_once_and_journal_never_contains_content_or_secret(self) -> None:
        secret = FAKE_BEARER
        prompt = "fixture-prompt-never-log"
        body_value = json.loads(fixture_request().decode("utf-8"))
        body_value["input"] = prompt
        body = json.dumps(body_value).encode("utf-8")
        with ProgrammableResponsesMock() as upstream:
            async with aiohttp.ClientSession() as session:
                limits = GatewayLimits(first_byte_timeout_seconds=2, idle_timeout_seconds=2, total_timeout_seconds=5)
                runner = SingleRouteAttemptRunner(session, OpenAIResponsesAdapter(upstream.base_url), limits)
                journal = MemoryEventJournal()
                core = SingleRouteGatewayCore(runner, limits, journal)
                downstream = RecordingDownstream()
                result = await core.proxy(
                    body,
                    {"content-type": "application/json", "authorization": "Bearer ingress-secret"},
                    secret,
                    downstream,
                    CancellationToken(),
                    Committer(chunk_bytes=limits.read_chunk_bytes),
                )
        self.assertEqual(result.state, CommitState.DELIVERED)
        rendered = json.dumps(journal.snapshot(), ensure_ascii=False)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(prompt, rendered)
        self.assertNotIn(hashlib.sha256(body).hexdigest(), rendered)
        self.assertNotIn("authorization", rendered.lower())
        self.assertEqual([event["event"] for event in journal.snapshot()], ["request_received", "commit_finished"])

    async def test_core_protocol_failure_writes_zero_downstream_bytes(self) -> None:
        for scenario, expected_code in (
            (missing_terminal_scenario(), "guardian_upstream_protocol_error"),
            (truncated_tool_scenario(), "guardian_upstream_protocol_error"),
        ):
            with self.subTest(expected_code=expected_code):
                with ProgrammableResponsesMock(lambda _request, scenario=scenario: scenario) as upstream:
                    async with aiohttp.ClientSession() as session:
                        limits = GatewayLimits(
                            first_byte_timeout_seconds=2,
                            idle_timeout_seconds=2,
                            total_timeout_seconds=5,
                        )
                        core = SingleRouteGatewayCore(
                            SingleRouteAttemptRunner(session, OpenAIResponsesAdapter(upstream.base_url), limits),
                            limits,
                        )
                        downstream = RecordingDownstream()
                        with self.assertRaises(GatewayError) as caught:
                            await core.proxy(
                                fixture_request(),
                                {"content-type": "application/json"},
                                FAKE_BEARER,
                                downstream,
                                CancellationToken(),
                                Committer(chunk_bytes=limits.read_chunk_bytes),
                            )
                self.assertEqual(caught.exception.code, expected_code)
                self.assertFalse(downstream.prepared)
                self.assertEqual(downstream.body, b"")

    async def test_cancel_after_upstream_complete_stays_uncommitted(self) -> None:
        class CancelBeforeCommitRunner:
            async def run(self, _snapshot, _bearer, cancellation):
                cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
                return AttemptResult(complete=_buffered())

        limits = GatewayLimits()
        cancellation = CancellationToken()
        downstream = RecordingDownstream()
        committer = Committer()
        core = SingleRouteGatewayCore(CancelBeforeCommitRunner(), limits)
        with self.assertRaises(GatewayError) as caught:
            await core.proxy(
                fixture_request(),
                {"content-type": "application/json"},
                FAKE_BEARER,
                downstream,
                cancellation,
                committer,
            )
        self.assertEqual(caught.exception.code, "guardian_client_cancelled")
        self.assertEqual(committer.state, CommitState.UNCOMMITTED)
        self.assertFalse(downstream.prepared)

    async def test_concurrency_limit_bounds_total_in_memory_attempts(self) -> None:
        class BlockingRunner:
            def __init__(self) -> None:
                self.entered = 0
                self.all_entered = asyncio.Event()
                self.release = asyncio.Event()

            async def run(self, _snapshot, _bearer, _cancellation):
                self.entered += 1
                if self.entered == 2:
                    self.all_entered.set()
                await self.release.wait()
                return AttemptResult(complete=_buffered())

        limits = GatewayLimits(max_concurrent_requests=2)
        runner = BlockingRunner()
        core = SingleRouteGatewayCore(runner, limits)

        async def proxy_one():
            return await core.proxy(
                fixture_request(),
                {"content-type": "application/json"},
                FAKE_BEARER,
                RecordingDownstream(),
                CancellationToken(),
                Committer(),
            )

        first = asyncio.create_task(proxy_one())
        second = asyncio.create_task(proxy_one())
        await asyncio.wait_for(runner.all_entered.wait(), timeout=1)
        self.assertEqual(core.active_requests, 2)
        rejected_downstream = RecordingDownstream()
        rejected_committer = Committer()
        with self.assertRaises(GatewayError) as caught:
            await core.proxy(
                fixture_request(),
                {"content-type": "application/json"},
                FAKE_BEARER,
                rejected_downstream,
                CancellationToken(),
                rejected_committer,
            )
        self.assertEqual(caught.exception.code, "guardian_gateway_busy")
        self.assertEqual(rejected_committer.state, CommitState.UNCOMMITTED)
        self.assertFalse(rejected_downstream.prepared)
        runner.release.set()
        results = await asyncio.gather(first, second)
        self.assertTrue(all(result.state is CommitState.DELIVERED for result in results))
        self.assertEqual(core.active_requests, 0)


class JournalTests(unittest.TestCase):
    def test_journal_is_bounded_and_allowlisted(self) -> None:
        journal = MemoryEventJournal(capacity=2)
        for index in range(3):
            journal.append(
                GatewayEvent(
                    request_id=str(index),
                    event="fixture",
                    model="fixture-model",
                    status="ok",
                )
            )
        self.assertEqual([event["request_id"] for event in journal.snapshot()], ["1", "2"])


class IngressIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.upstream = ProgrammableResponsesMock()
        self.upstream.start()
        self.upstream_session = aiohttp.ClientSession()
        self.limits = GatewayLimits(
            max_request_bytes=1024 * 1024,
            max_response_bytes=1024 * 1024,
            read_chunk_bytes=257,
            connect_timeout_seconds=2,
            first_byte_timeout_seconds=2,
            idle_timeout_seconds=2,
            total_timeout_seconds=5,
        )
        self.committers: list[Committer] = []
        await self._start_ingress()

    def _new_committer(self) -> Committer:
        committer = Committer(chunk_bytes=self.limits.read_chunk_bytes)
        self.committers.append(committer)
        return committer

    async def _start_ingress(self) -> None:
        runner = SingleRouteAttemptRunner(
            self.upstream_session,
            OpenAIResponsesAdapter(self.upstream.base_url),
            self.limits,
        )
        self.core = SingleRouteGatewayCore(runner, self.limits)
        ingress = GatewayIngress(
            self.core,
            self.limits,
            ingress_token="fixture-ingress-token",
            upstream_bearer=FAKE_BEARER,
            models=[FIXTURE_MODEL],
            committer_factory=self._new_committer,
        )
        self.ingress = ingress
        self.client = TestClient(TestServer(ingress.create_app(), handler_cancellation=True))
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.upstream_session.close()
        self.upstream.close()

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": "Bearer fixture-ingress-token"}

    async def test_health_models_and_auth_are_local_contracts(self) -> None:
        unauthorized = await self.client.get("/health")
        self.assertEqual(unauthorized.status, 401)
        health = await self.client.get("/health", headers=self.auth)
        self.assertEqual(health.status, 200)
        self.assertEqual((await health.json())["mode"], "single_route_g3")
        models = await self.client.get("/v1/models", headers=self.auth)
        payload = await models.json()
        self.assertEqual(models.status, 200)
        self.assertEqual([model["id"] for model in payload["data"]], [FIXTURE_MODEL])
        self.assertEqual(self.upstream.request_count, 0)

    async def test_responses_auth_error_uses_request_committer(self) -> None:
        response = await self.client.post(
            "/v1/responses",
            data=fixture_request(),
            headers={"Content-Type": "application/json"},
        )
        payload = await response.json()
        self.assertEqual(response.status, 401)
        self.assertEqual(payload["error"]["code"], "guardian_unauthorized")
        self.assertEqual(self.committers[-1].state, CommitState.ERROR_COMMITTED)
        self.assertEqual(self.upstream.request_count, 0)

    async def test_unpublished_model_is_blocked_before_upstream(self) -> None:
        body_value = json.loads(fixture_request().decode("utf-8"))
        body_value["model"] = "not-published"
        response = await self.client.post(
            "/v1/responses",
            data=json.dumps(body_value).encode("utf-8"),
            headers={**self.auth, "Content-Type": "application/json"},
        )
        payload = await response.json()
        self.assertEqual(response.status, 400)
        self.assertEqual(payload["error"]["code"], "guardian_model_not_allowed")
        self.assertEqual(self.committers[-1].state, CommitState.ERROR_COMMITTED)
        self.assertEqual(self.upstream.request_count, 0)

    async def test_responses_commits_complete_sse_once(self) -> None:
        response = await self.client.post(
            "/v1/responses",
            data=fixture_request(),
            headers={**self.auth, "Content-Type": "application/json"},
        )
        body = await response.read()
        self.assertEqual(response.status, 200)
        self.assertTrue(response.headers["Content-Type"].startswith("text/event-stream"))
        self.assertIn(b"response.completed", body)
        self.assertEqual(self.upstream.request_count, 1)
        self.assertEqual(self.committers[-1].state, CommitState.DELIVERED)

    async def test_raw_socket_gets_zero_bytes_until_upstream_is_complete(self) -> None:
        await self.client.close()
        self.upstream.close()
        control = ScenarioControl()
        frames = text_sse_frames("G3_ZERO_BYTES", response_id="resp_g3_zero_bytes")
        scenario = ScriptedScenario(
            name="gated",
            chunks=frames,
            wait_before_chunk=len(frames) - 1,
            control=control,
        )
        self.upstream = ProgrammableResponsesMock(lambda _request: scenario)
        self.upstream.start()
        await self.upstream_session.close()
        self.upstream_session = aiohttp.ClientSession()
        await self._start_ingress()

        body = fixture_request()
        host = self.client.server.host
        port = self.client.server.port

        def raw_client() -> tuple[bool, bytes]:
            request = (
                f"POST /v1/responses HTTP/1.1\r\nHost: {host}:{port}\r\n"
                "Authorization: Bearer fixture-ingress-token\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + body
            with socket.create_connection((host, port), timeout=3) as downstream:
                downstream.sendall(request)
                if not control.partial_sent.wait(3):
                    raise AssertionError("upstream_partial_not_observed")
                downstream.settimeout(0.25)
                zero_bytes = False
                try:
                    zero_bytes = downstream.recv(1) == b""
                except socket.timeout:
                    zero_bytes = True
                control.release_terminal.set()
                downstream.settimeout(3)
                received = bytearray()
                while True:
                    chunk = downstream.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                return zero_bytes, bytes(received)

        zero_bytes, received = await asyncio.to_thread(raw_client)
        self.assertTrue(zero_bytes)
        self.assertTrue(received.startswith(b"HTTP/1.1 200"))
        self.assertIn(b"response.completed", received)
        self.assertEqual(self.upstream.request_count, 1)

    async def test_raw_socket_precommit_disconnect_cancels_upstream_and_releases_capacity(self) -> None:
        partial_sent = threading.Event()
        upstream_release = asyncio.Event()
        frames = text_sse_frames("G3_DISCONNECT", response_id="resp_g3_disconnect")

        async def upstream_responses(request: web.Request) -> web.StreamResponse:
            await request.read()
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            await response.write(frames[0])
            partial_sent.set()
            try:
                while not upstream_release.is_set():
                    try:
                        await asyncio.wait_for(upstream_release.wait(), timeout=0.02)
                    except asyncio.TimeoutError:
                        await response.write(b": fixture-keepalive\n\n")
            except asyncio.CancelledError:
                raise
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            return response

        upstream_app = web.Application()
        upstream_app.router.add_post("/v1/responses", upstream_responses)
        upstream_runner = web.AppRunner(
            upstream_app,
            handler_cancellation=True,
            shutdown_timeout=1,
        )
        await upstream_runner.setup()
        upstream_site = web.TCPSite(upstream_runner, "127.0.0.1", 0)
        await upstream_site.start()
        sockets = upstream_site._server.sockets if upstream_site._server is not None else []
        self.assertTrue(sockets)
        upstream_port = sockets[0].getsockname()[1]

        limits = GatewayLimits(
            max_request_bytes=1024 * 1024,
            max_response_bytes=1024 * 1024,
            read_chunk_bytes=257,
            max_concurrent_requests=2,
            connect_timeout_seconds=1,
            first_byte_timeout_seconds=1,
            idle_timeout_seconds=5,
            total_timeout_seconds=10,
        )
        upstream_session = aiohttp.ClientSession()
        class TrackingAttemptRunner(SingleRouteAttemptRunner):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)
                self.abort_observed = False

            def _finalize_response(self, response, reusable: bool) -> None:
                super()._finalize_response(response, reusable)
                if not reusable:
                    self.abort_observed = response.closed and response.connection is None

            def _discard_abandoned_result(self, result) -> None:
                super()._discard_abandoned_result(result)
                if isinstance(result, aiohttp.ClientResponse):
                    self.abort_observed = result.closed and result.connection is None

        attempt_runner = TrackingAttemptRunner(
            upstream_session,
            OpenAIResponsesAdapter(f"http://127.0.0.1:{upstream_port}/v1"),
            limits,
        )
        core = SingleRouteGatewayCore(
            attempt_runner,
            limits,
        )
        committers: list[Committer] = []

        def new_committer() -> Committer:
            committer = Committer(chunk_bytes=limits.read_chunk_bytes)
            committers.append(committer)
            return committer

        ingress = GatewayIngress(
            core,
            limits,
            ingress_token="fixture-ingress-token",
            upstream_bearer=FAKE_BEARER,
            models=[FIXTURE_MODEL],
            committer_factory=new_committer,
        )
        client = TestClient(
            TestServer(ingress.create_app(), handler_cancellation=True)
        )
        await client.start_server()
        try:
            body = fixture_request()
            host = client.server.host
            port = client.server.port

            def raw_client_disconnect() -> None:
                request = (
                    f"POST /v1/responses HTTP/1.1\r\nHost: {host}:{port}\r\n"
                    "Authorization: Bearer fixture-ingress-token\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii") + body
                downstream = socket.create_connection((host, port), timeout=3)
                try:
                    downstream.sendall(request)
                    if not partial_sent.wait(3):
                        raise AssertionError("upstream_partial_not_observed")
                finally:
                    try:
                        downstream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    downstream.close()

            await asyncio.to_thread(raw_client_disconnect)
            for _ in range(200):
                if (
                    attempt_runner.abort_observed
                    and core.active_requests == 0
                    and ingress.active_requests == 0
                ):
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(
                attempt_runner.abort_observed,
                f"upstream_response_not_aborted core={core.active_requests} ingress={ingress.active_requests} "
                f"committer={committers[0].state.value if committers else 'missing'}",
            )
            self.assertEqual(core.active_requests, 0)
            self.assertEqual(ingress.active_requests, 0)
            self.assertEqual(len(committers), 1)
            self.assertEqual(committers[0].state, CommitState.UNCOMMITTED)
        finally:
            upstream_release.set()
            await client.close()
            await upstream_session.close()
            await upstream_runner.cleanup()

    async def test_expect_100_continue_never_emits_interim_response(self) -> None:
        body = fixture_request()
        host = self.client.server.host
        port = self.client.server.port

        def raw_client() -> bytes:
            request_headers = (
                f"POST /v1/responses HTTP/1.1\r\nHost: {host}:{port}\r\n"
                "Authorization: Bearer fixture-ingress-token\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Expect: 100-continue\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            with socket.create_connection((host, port), timeout=3) as downstream:
                downstream.sendall(request_headers)
                downstream.settimeout(3)
                received = bytearray()
                while True:
                    try:
                        chunk = downstream.recv(65536)
                    except socket.timeout:
                        if received:
                            break
                        raise
                    if not chunk:
                        break
                    received.extend(chunk)
                    if b"guardian_expectation_not_supported" in received:
                        break
                return bytes(received)

        received = await asyncio.to_thread(raw_client)
        self.assertTrue(received.startswith(b"HTTP/1.1 417"))
        self.assertNotIn(b"100 Continue", received)
        self.assertIn(b"guardian_expectation_not_supported", received)
        self.assertEqual(self.upstream.request_count, 0)
        self.assertEqual(self.committers, [])

    async def test_protocol_failure_returns_error_without_partial_sse(self) -> None:
        await self.client.close()
        self.upstream.close()
        self.upstream = ProgrammableResponsesMock(lambda _request: missing_terminal_scenario())
        self.upstream.start()
        await self.upstream_session.close()
        self.upstream_session = aiohttp.ClientSession()
        await self._start_ingress()
        response = await self.client.post(
            "/v1/responses",
            data=fixture_request(),
            headers={**self.auth, "Content-Type": "application/json"},
        )
        body = await response.read()
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(response.status, 502)
        self.assertEqual(payload["error"]["code"], "guardian_upstream_protocol_error")
        self.assertNotIn(b"response.created", body)
        self.assertEqual(self.upstream.request_count, 1)
        self.assertEqual(self.committers[-1].state, CommitState.ERROR_COMMITTED)

    async def test_upstream_http_status_survives_ingress_error_commit(self) -> None:
        await self.client.close()
        self.upstream.close()
        scenario = ScriptedScenario(
            name="rate_limited",
            status=429,
            content_type="application/json",
            chunks=(b'{"private":"ignored"}',),
        )
        self.upstream = ProgrammableResponsesMock(lambda _request: scenario)
        self.upstream.start()
        await self.upstream_session.close()
        self.upstream_session = aiohttp.ClientSession()
        await self._start_ingress()
        response = await self.client.post(
            "/v1/responses",
            data=fixture_request(),
            headers={**self.auth, "Content-Type": "application/json"},
        )
        payload = await response.json()
        self.assertEqual(response.status, 429)
        self.assertEqual(payload["error"]["code"], "guardian_upstream_http_429")
        self.assertEqual(self.committers[-1].state, CommitState.ERROR_COMMITTED)
        self.assertEqual(self.upstream.request_count, 1)

    async def test_unexpected_internal_error_is_redacted_and_uses_request_committer(self) -> None:
        class ExplodingCore:
            async def proxy(self, *_args, **_kwargs):
                raise RuntimeError("private-fixture-detail")

        ingress = GatewayIngress(
            ExplodingCore(),
            self.limits,
            ingress_token="fixture-ingress-token",
            upstream_bearer=FAKE_BEARER,
            models=[FIXTURE_MODEL],
            committer_factory=self._new_committer,
        )
        client = TestClient(TestServer(ingress.create_app(), handler_cancellation=True))
        await client.start_server()
        try:
            response = await client.post(
                "/v1/responses",
                data=fixture_request(),
                headers={**self.auth, "Content-Type": "application/json"},
            )
            body = await response.read()
        finally:
            await client.close()
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(response.status, 500)
        self.assertEqual(payload["error"]["code"], "guardian_internal_error")
        self.assertNotIn(b"private-fixture-detail", body)
        self.assertEqual(self.committers[-1].state, CommitState.ERROR_COMMITTED)

    async def test_ingress_rejects_excess_concurrency_before_core_proxy(self) -> None:
        class BlockingCore:
            def __init__(self) -> None:
                self.entered = asyncio.Event()
                self.release = asyncio.Event()
                self.calls = 0

            async def proxy(self, _body, _headers, _bearer, downstream, cancellation, committer):
                self.calls += 1
                self.entered.set()
                await self.release.wait()
                return await committer.commit(_buffered(), downstream, cancellation)

        limits = GatewayLimits(max_concurrent_requests=1)
        core = BlockingCore()
        ingress = GatewayIngress(
            core,
            limits,
            ingress_token="fixture-ingress-token",
            upstream_bearer=FAKE_BEARER,
            models=[FIXTURE_MODEL],
            committer_factory=self._new_committer,
        )
        client = TestClient(TestServer(ingress.create_app(), handler_cancellation=True))
        await client.start_server()
        try:
            first_task = asyncio.create_task(
                client.post(
                    "/v1/responses",
                    data=fixture_request(),
                    headers={**self.auth, "Content-Type": "application/json"},
                )
            )
            await asyncio.wait_for(core.entered.wait(), timeout=1)
            second = await client.post(
                "/v1/responses",
                data=fixture_request(),
                headers={**self.auth, "Content-Type": "application/json"},
            )
            second_payload = await second.json()
            self.assertEqual(second.status, 503)
            self.assertEqual(second_payload["error"]["code"], "guardian_gateway_busy")
            self.assertEqual(core.calls, 1)
            self.assertEqual(self.committers[-1].state, CommitState.ERROR_COMMITTED)
            core.release.set()
            first = await asyncio.wait_for(first_task, timeout=1)
            await first.read()
            self.assertEqual(first.status, 200)
        finally:
            core.release.set()
            await client.close()


if __name__ == "__main__":
    unittest.main()
