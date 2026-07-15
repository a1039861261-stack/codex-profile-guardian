from __future__ import annotations

import json
from http.client import HTTPConnection
import socket
import struct
import sys
import threading
import time
import unittest

from tests.gateway_probe_support import (
    CommitControl,
    ExperimentalFullBufferRelay,
    FAKE_BEARER,
    ProgrammableResponsesMock,
    ProtocolProbeError,
    ScenarioControl,
    ScriptedScenario,
    StateStore,
    _event_bytes,
    fixture_request,
    http_post_json,
    http_post_response,
    json_scenario,
    message_item,
    missing_terminal_scenario,
    raw_post_bytes,
    response_object,
    terminal_sse_frames,
    text_scenario,
    text_sse_frames,
    tool_sse_frames,
    trailing_garbage_scenario,
    truncated_tool_scenario,
    validate_buffered_response,
)


def _set_abortive_close(target: socket.socket) -> None:
    linger_format = "hh" if sys.platform == "win32" else "ii"
    target.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_LINGER,
        struct.pack(linger_format, 1, 0),
    )


def _error_code(chunks: tuple[bytes, ...], content_type: str = "text/event-stream") -> str:
    with unittest.TestCase().assertRaises(ProtocolProbeError) as caught:
        validate_buffered_response(200, content_type, chunks)
    return caught.exception.code


def _validated_with_terminal_compatibility(
    chunks: tuple[bytes, ...],
    *,
    allow_omission: bool = False,
    allow_missing_item_ids: bool = False,
    allow_missing_item_status: bool = False,
    allow_missing_tool_done_name: bool = False,
):
    return validate_buffered_response(
        200,
        "text/event-stream",
        chunks,
        allow_terminal_output_omission=allow_omission,
        allow_terminal_output_missing_item_ids=allow_missing_item_ids,
        allow_terminal_output_missing_item_status=allow_missing_item_status,
        allow_function_call_arguments_done_missing_name=(
            allow_missing_tool_done_name
        ),
    )


class ResponsesProtocolValidatorTests(unittest.TestCase):
    def test_sse_text_accepts_utf8_arbitrary_chunks_crlf_and_multiline_data(self) -> None:
        frames = text_sse_frames(
            "虚构中文 G2_OK",
            mixed_newlines=True,
            multiline_data=True,
        )
        chunks = tuple(bytes((byte,)) for byte in b"".join(frames))

        result = validate_buffered_response(200, "text/event-stream; charset=utf-8", chunks)

        self.assertEqual(result.terminal_type, "response.completed")
        self.assertEqual(result.output_text, "虚构中文 G2_OK")
        self.assertEqual(result.body, b"".join(frames))
        self.assertIn("response.output_text.delta", result.event_types)

    def test_sse_function_arguments_are_complete_and_single(self) -> None:
        frames = tool_sse_frames()

        result = validate_buffered_response(200, "text/event-stream", frames)

        self.assertEqual(result.terminal_type, "response.completed")
        self.assertEqual(len(result.tool_calls), 1)
        self.assertEqual(result.tool_calls[0].call_id, "call_g2_tool")
        self.assertEqual(json.loads(result.tool_calls[0].arguments)["city"], "深圳")

        wrong_name = list(frames)
        wrong_name[5] = wrong_name[5].replace(b'"name":"fixture_lookup"', b'"name":"wrong_tool"')
        self.assertEqual(_error_code(tuple(wrong_name)), "tool_name_mismatch")

        missing_name = list(frames)
        missing_name[5] = missing_name[5].replace(
            b',"name":"fixture_lookup"',
            b"",
        )
        self.assertEqual(_error_code(tuple(missing_name)), "tool_name_missing")
        accepted_missing_name = _validated_with_terminal_compatibility(
            tuple(missing_name),
            allow_missing_tool_done_name=True,
        )
        self.assertEqual(len(accepted_missing_name.tool_calls), 1)
        self.assertEqual(
            accepted_missing_name.tool_calls[0].name,
            "fixture_lookup",
        )

        with self.assertRaises(ProtocolProbeError) as caught:
            _validated_with_terminal_compatibility(
                tuple(wrong_name),
                allow_missing_tool_done_name=True,
            )
        self.assertEqual(caught.exception.code, "tool_name_mismatch")

    def test_terminal_cannot_introduce_unobserved_tool_call(self) -> None:
        frames = list(tool_sse_frames())
        terminal_only = (frames[0], frames[-1])
        self.assertEqual(_error_code(terminal_only), "terminal_output_unobserved_items")

    def test_terminal_output_mismatch_codes_are_structural_and_content_free(self) -> None:
        frames = list(text_sse_frames(text="synthetic terminal structure"))
        response_id = "resp_g2_text"
        complete_item = message_item("msg_g2_text", "synthetic terminal structure")

        missing = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object(response_id, output=[]),
            },
        )
        self.assertEqual(
            _error_code(tuple(frames[:-1] + [missing])),
            "terminal_output_missing_event_items",
        )

        replacement = message_item("msg_terminal_other", "synthetic terminal structure")
        identity = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object(response_id, output=[replacement]),
            },
        )
        self.assertEqual(
            _error_code(tuple(frames[:-1] + [identity])),
            "terminal_output_item_identity_mismatch",
        )

        state_item = dict(complete_item)
        state_item["status"] = "in_progress"
        state = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object(response_id, output=[state_item]),
            },
        )
        self.assertEqual(
            _error_code(tuple(frames[:-1] + [state])),
            "terminal_output_item_status_mismatch",
        )

        type_item = dict(complete_item)
        type_item["type"] = "function_call"
        type_mismatch = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object(response_id, output=[type_item]),
            },
        )
        self.assertEqual(
            _error_code(tuple(frames[:-1] + [type_mismatch])),
            "terminal_output_item_type_mismatch",
        )

        text_item = message_item("msg_g2_text", "different synthetic text")
        text = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object(response_id, output=[text_item]),
            },
        )
        self.assertEqual(
            _error_code(tuple(frames[:-1] + [text])),
            "terminal_output_text_mismatch",
        )

    def test_opt_in_terminal_output_omission_uses_only_closed_stream_items(self) -> None:
        text_frames = list(text_sse_frames(text="synthetic omitted terminal output"))
        omitted_response = response_object("resp_g2_text", output=[])
        omitted_response.pop("output")
        omitted = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": omitted_response,
            },
        )
        strict_code = _error_code(tuple(text_frames[:-1] + [omitted]))
        self.assertEqual(strict_code, "terminal_output_omitted")
        accepted = _validated_with_terminal_compatibility(
            tuple(text_frames[:-1] + [omitted]), allow_omission=True
        )
        self.assertEqual(accepted.output_text, "synthetic omitted terminal output")

        empty = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object("resp_g2_text", output=[]),
            },
        )
        accepted = _validated_with_terminal_compatibility(
            tuple(text_frames[:-1] + [empty]), allow_omission=True
        )
        self.assertEqual(accepted.output_text, "synthetic omitted terminal output")

        tool_frames = list(tool_sse_frames())
        tool_terminal = json.loads(tool_frames[-1].decode("utf-8").split("data: ", 1)[1])
        tool_terminal["response"]["output"] = []
        empty_tool = _event_bytes("response.completed", tool_terminal)
        accepted_tool = _validated_with_terminal_compatibility(
            tuple(tool_frames[:-1] + [empty_tool]), allow_omission=True
        )
        self.assertEqual(len(accepted_tool.tool_calls), 1)

        terminal_only = (tool_frames[0], tool_frames[-1])
        self.assertEqual(
            _error_code(terminal_only),
            "terminal_output_unobserved_items",
        )
        with self.assertRaises(ProtocolProbeError) as caught:
            _validated_with_terminal_compatibility(
                terminal_only, allow_omission=True
            )
        self.assertEqual(caught.exception.code, "terminal_output_unobserved_items")

    def test_opt_in_missing_terminal_item_ids_matches_only_by_output_index(self) -> None:
        text_frames = list(text_sse_frames(text="synthetic missing terminal id"))
        terminal_item = message_item("msg_g2_text", "synthetic missing terminal id")
        terminal_item.pop("id")
        terminal = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object("resp_g2_text", output=[terminal_item]),
            },
        )
        self.assertEqual(
            _error_code(tuple(text_frames[:-1] + [terminal])),
            "terminal_output_item_missing_id",
        )
        accepted = _validated_with_terminal_compatibility(
            tuple(text_frames[:-1] + [terminal]),
            allow_missing_item_ids=True,
        )
        self.assertEqual(accepted.output_text, "synthetic missing terminal id")

        wrong_text = dict(terminal_item)
        wrong_text["content"] = [
            {"type": "output_text", "text": "wrong", "annotations": []}
        ]
        wrong_terminal = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object("resp_g2_text", output=[wrong_text]),
            },
        )
        with self.assertRaises(ProtocolProbeError) as caught:
            _validated_with_terminal_compatibility(
                tuple(text_frames[:-1] + [wrong_terminal]),
                allow_missing_item_ids=True,
            )
        self.assertEqual(caught.exception.code, "terminal_output_text_mismatch")

        tool_frames = list(tool_sse_frames())
        tool_terminal = json.loads(tool_frames[-1].decode("utf-8").split("data: ", 1)[1])
        tool_terminal["response"]["output"][0].pop("id")
        missing_tool_id = _event_bytes("response.completed", tool_terminal)
        accepted_tool = _validated_with_terminal_compatibility(
            tuple(tool_frames[:-1] + [missing_tool_id]),
            allow_missing_item_ids=True,
        )
        self.assertEqual(len(accepted_tool.tool_calls), 1)

        tool_terminal["response"]["output"][0]["arguments"] = '{"city":"wrong"}'
        wrong_tool = _event_bytes("response.completed", tool_terminal)
        with self.assertRaises(ProtocolProbeError) as caught:
            _validated_with_terminal_compatibility(
                tuple(tool_frames[:-1] + [wrong_tool]),
                allow_missing_item_ids=True,
            )
        self.assertEqual(caught.exception.code, "terminal_output_tool_mismatch")

    def test_opt_in_missing_terminal_item_status_uses_closed_stream_status(self) -> None:
        text_frames = list(text_sse_frames(text="synthetic missing terminal status"))
        terminal_item = message_item(
            "msg_g2_text",
            "synthetic missing terminal status",
        )
        terminal_item.pop("id")
        terminal_item.pop("status")
        terminal = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object("resp_g2_text", output=[terminal_item]),
            },
        )
        with self.assertRaises(ProtocolProbeError) as caught:
            _validated_with_terminal_compatibility(
                tuple(text_frames[:-1] + [terminal]),
                allow_missing_item_ids=True,
            )
        self.assertEqual(
            caught.exception.code,
            "terminal_output_item_status_missing",
        )

        accepted = _validated_with_terminal_compatibility(
            tuple(text_frames[:-1] + [terminal]),
            allow_missing_item_ids=True,
            allow_missing_item_status=True,
        )
        self.assertEqual(accepted.output_text, "synthetic missing terminal status")

        wrong_status = dict(terminal_item)
        wrong_status["status"] = "in_progress"
        wrong_terminal = _event_bytes(
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 8,
                "response": response_object("resp_g2_text", output=[wrong_status]),
            },
        )
        with self.assertRaises(ProtocolProbeError) as caught:
            _validated_with_terminal_compatibility(
                tuple(text_frames[:-1] + [wrong_terminal]),
                allow_missing_item_ids=True,
                allow_missing_item_status=True,
            )
        self.assertEqual(
            caught.exception.code,
            "terminal_output_item_status_mismatch",
        )

    def test_orphan_text_delta_and_tool_delta_after_done_fail_closed(self) -> None:
        frames = list(text_sse_frames())
        orphan_delta = (frames[0], frames[4], frames[-1])
        self.assertEqual(_error_code(orphan_delta), "message_item_not_open")

        tool_frames = list(tool_sse_frames())
        extra_delta = _event_bytes(
            "response.function_call_arguments.delta",
            {
                "type": "response.function_call_arguments.delta",
                "sequence_number": 6,
                "response_id": "resp_g2_tool",
                "item_id": "fc_g2_tool",
                "output_index": 0,
                "delta": " ",
            },
        )
        with_extra = tuple(tool_frames[:6] + [extra_delta] + tool_frames[6:])
        self.assertEqual(_error_code(with_extra), "tool_delta_after_done")

    def test_failed_and_incomplete_are_legal_terminal_results(self) -> None:
        for status in ("failed", "incomplete"):
            with self.subTest(status=status):
                result = validate_buffered_response(200, "text/event-stream", terminal_sse_frames(status))
                self.assertEqual(result.terminal_type, f"response.{status}")

                json_result = validate_buffered_response(
                    200,
                    "application/json",
                    json_scenario(status=status).chunks,
                )
                self.assertEqual(json_result.terminal_type, f"response.{status}")

    def test_incomplete_terminal_accepts_incomplete_message_item_but_completed_does_not(self) -> None:
        response_id = "resp_g2_partial_message"
        created = response_object(response_id)
        created.update({"status": "in_progress", "completed_at": None, "output": [], "usage": None})
        opened = message_item("msg_partial", "", status="in_progress")
        partial = message_item("msg_partial", "partial synthetic text", status="incomplete")
        frames = (
            _event_bytes("response.created", {"type": "response.created", "response": created}),
            _event_bytes(
                "response.output_item.added",
                {"type": "response.output_item.added", "response_id": response_id, "output_index": 0, "item": opened},
            ),
            _event_bytes(
                "response.content_part.added",
                {
                    "type": "response.content_part.added",
                    "response_id": response_id,
                    "item_id": "msg_partial",
                    "output_index": 0,
                    "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []},
                },
            ),
            _event_bytes(
                "response.output_text.delta",
                {
                    "type": "response.output_text.delta",
                    "response_id": response_id,
                    "item_id": "msg_partial",
                    "output_index": 0,
                    "content_index": 0,
                    "delta": "partial synthetic text",
                },
            ),
            _event_bytes(
                "response.output_text.done",
                {
                    "type": "response.output_text.done",
                    "response_id": response_id,
                    "item_id": "msg_partial",
                    "output_index": 0,
                    "content_index": 0,
                    "text": "partial synthetic text",
                },
            ),
            _event_bytes(
                "response.content_part.done",
                {
                    "type": "response.content_part.done",
                    "response_id": response_id,
                    "item_id": "msg_partial",
                    "output_index": 0,
                    "content_index": 0,
                    "part": partial["content"][0],
                },
            ),
            _event_bytes(
                "response.output_item.done",
                {"type": "response.output_item.done", "response_id": response_id, "output_index": 0, "item": partial},
            ),
            _event_bytes(
                "response.incomplete",
                {"type": "response.incomplete", "response": response_object(response_id, status="incomplete", output=[partial])},
            ),
        )
        result = validate_buffered_response(200, "text/event-stream", frames)
        self.assertEqual(result.terminal_type, "response.incomplete")

        completed_tail = _event_bytes(
            "response.completed",
            {"type": "response.completed", "response": response_object(response_id, output=[partial])},
        )
        self.assertEqual(
            _error_code(frames[:-1] + (completed_tail,)),
            "completed_with_incomplete_item",
        )

        json_body = json.dumps(response_object(response_id, status="incomplete", output=[partial])).encode("utf-8")
        json_result = validate_buffered_response(200, "application/json", (json_body,))
        self.assertEqual(json_result.terminal_type, "response.incomplete")

    def test_nonstreaming_json_must_be_terminal(self) -> None:
        success = json_scenario(text="G2_JSON_OK")
        result = validate_buffered_response(200, success.content_type, success.chunks)
        self.assertEqual(result.output_text, "G2_JSON_OK")

        nonterminal = response_object("resp_nonterminal")
        nonterminal["status"] = "in_progress"
        self.assertEqual(
            _error_code((json.dumps(nonterminal).encode("utf-8"),), "application/json"),
            "nonterminal_json",
        )

    def test_response_identity_is_required_for_sse_and_json(self) -> None:
        empty_id = response_object("")
        self.assertEqual(
            _error_code((json.dumps(empty_id).encode("utf-8"),), "application/json"),
            "nonterminal_json",
        )
        created = response_object("")
        created.update({"status": "in_progress", "completed_at": None, "output": [], "usage": None})
        self.assertEqual(
            _error_code((_event_bytes("response.created", {"type": "response.created", "response": created}),)),
            "missing_response_id",
        )

        frames = list(text_sse_frames())
        frames[-1] = frames[-1].replace(b'"id":"resp_g2_text"', b'"id":""', 1)
        self.assertEqual(_error_code(tuple(frames)), "missing_response_id")

    def test_missing_terminal_truncated_tool_and_trailing_data_are_rejected(self) -> None:
        cases = {
            "missing_terminal": missing_terminal_scenario().chunks,
            "open_tool_arguments": truncated_tool_scenario().chunks,
            "trailing_data": trailing_garbage_scenario().chunks,
        }
        for expected, chunks in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(_error_code(chunks), expected)

    def test_unterminated_terminal_event_is_not_promoted_by_eof(self) -> None:
        terminal = text_sse_frames()[-1].rstrip(b"\r\n")
        chunks = text_sse_frames()[:-1] + (terminal,)
        self.assertEqual(_error_code(chunks), "unterminated_sse_event")

    def test_unknown_stateless_event_is_preserved_but_stateful_unknown_fails(self) -> None:
        frames = text_sse_frames()
        extension = _event_bytes(
            "response.guardian_fixture_notice",
            {"type": "response.guardian_fixture_notice", "fixture": True},
        )
        result = validate_buffered_response(
            200,
            "text/event-stream",
            frames[:-1] + (extension, frames[-1]),
        )
        self.assertIn("response.guardian_fixture_notice", result.event_types)

        stateful = _event_bytes(
            "response.future_output.delta",
            {
                "type": "response.future_output.delta",
                "item_id": "future_item",
                "delta": "synthetic",
            },
        )
        self.assertEqual(
            _error_code(frames[:-1] + (stateful, frames[-1])),
            "unknown_stateful_event",
        )

    def test_invalid_mime_json_utf8_and_buffer_limit_fail_closed(self) -> None:
        self.assertEqual(_error_code((b"<html></html>",), "text/html"), "invalid_content_type")
        self.assertEqual(_error_code((b"{",), "application/json"), "invalid_json")
        self.assertEqual(_error_code((b"event: x\ndata: \xff\n\n",)), "invalid_utf8")
        frames = text_sse_frames(text="long")
        with self.assertRaises(ProtocolProbeError) as caught:
            validate_buffered_response(200, "text/event-stream", frames, max_bytes=8)
        self.assertEqual(caught.exception.code, "buffer_limit")

    def test_typed_error_event_is_not_a_deliverable_terminal(self) -> None:
        created = text_sse_frames()[0]
        error = _event_bytes(
            "error",
            {"type": "error", "code": "fixture_error", "message": "Synthetic only."},
        )
        self.assertEqual(_error_code((created, error)), "upstream_error_event")

    def test_protocol_split_matrix_is_deterministic_across_100_runs(self) -> None:
        body = b"".join(text_sse_frames("G2_REPEAT_OK", mixed_newlines=True, multiline_data=True))
        for offset in range(100):
            step = (offset % 17) + 1
            chunks = tuple(body[index : index + step] for index in range(0, len(body), step))
            result = validate_buffered_response(200, "text/event-stream", chunks)
            self.assertEqual(result.output_text, "G2_REPEAT_OK")


class FullBufferRelayTests(unittest.TestCase):
    def test_mock_rejects_wrong_path_auth_and_content_type_and_serves_models(self) -> None:
        with ProgrammableResponsesMock() as upstream:
            port = int(upstream.base_url.rsplit(":", 1)[1].split("/", 1)[0])

            connection = HTTPConnection("127.0.0.1", port, timeout=3)
            connection.request("POST", "/v1/responses", body=b"{}", headers={"Content-Type": "application/json"})
            self.assertEqual(connection.getresponse().status, 401)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port, timeout=3)
            connection.request(
                "POST",
                "/v1/responses",
                body=b"{}",
                headers={"Content-Type": "text/plain", "Authorization": f"Bearer {FAKE_BEARER}"},
            )
            self.assertEqual(connection.getresponse().status, 415)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port, timeout=3)
            connection.request("GET", "/v1/models")
            response = connection.getresponse()
            status = response.status
            models = json.loads(response.read().decode("utf-8"))
            connection.close()
            self.assertEqual(status, 200)
            self.assertEqual(models["object"], "list")
            self.assertEqual(upstream.request_count, 0)

    def test_programmable_mock_supports_required_http_status_matrix(self) -> None:
        statuses = (400, 401, 403, 404, 409, 413, 415, 422, 429, 500, 502, 503, 504)

        def scenario_for(request):
            status = int((request.json_body or {}).get("fixture_status", 500))
            return ScriptedScenario(
                name=f"http_{status}",
                status=status,
                content_type="application/json",
                chunks=(b'{"error":{"type":"synthetic_fixture"}}',),
            )

        with ProgrammableResponsesMock(scenario_for) as upstream:
            for status in statuses:
                with self.subTest(status=status):
                    actual, content_type, body = http_post_response(
                        upstream.base_url,
                        {"model": "fixture", "input": "synthetic", "fixture_status": status},
                    )
                    self.assertEqual(actual, status)
                    self.assertEqual(content_type, "application/json")
                    self.assertIn(b"synthetic_fixture", body)
        self.assertEqual(upstream.request_count, len(statuses))
        self.assertTrue(all(request.method == "POST" for request in upstream.requests))
        self.assertTrue(all(request.path == "/v1/responses" for request in upstream.requests))
        self.assertTrue(all(request.authorization_scheme == "Bearer" for request in upstream.requests))
        self.assertTrue(all(request.content_type == "application/json" for request in upstream.requests))

    def test_raw_socket_receives_zero_bytes_until_upstream_terminal_and_eof(self) -> None:
        control = ScenarioControl()
        scenario = ScriptedScenario(
            name="gated",
            chunks=text_sse_frames("G2_BUFFERED_OK"),
            wait_before_chunk=len(text_sse_frames()) - 1,
            control=control,
        )
        with ProgrammableResponsesMock(lambda _request: scenario) as primary:
            with ExperimentalFullBufferRelay(primary.base_url) as relay:
                host, port, request = raw_post_bytes(relay.base_url, fixture_request())
                with socket.create_connection((host, port), timeout=3) as downstream:
                    downstream.sendall(request)
                    self.assertTrue(control.partial_sent.wait(3))
                    downstream.settimeout(0.25)
                    with self.assertRaises(socket.timeout):
                        downstream.recv(1)
                    self.assertEqual(relay.records, [])

                    control.release_terminal.set()
                    downstream.settimeout(3)
                    received = bytearray()
                    while True:
                        chunk = downstream.recv(65536)
                        if not chunk:
                            break
                        received.extend(chunk)

                self.assertTrue(relay.wait_for_records(1))
                record = relay.records[0]
                self.assertTrue(bytes(received).startswith(b"HTTP/1.1 200"))
                self.assertIn(b"response.completed", received)
                self.assertEqual(record.outcome, "delivered")
                self.assertEqual(record.committed_source, "primary")
                self.assertIsNotNone(control.terminal_sent_at)
                self.assertGreaterEqual(record.commit_started_at or 0, control.terminal_sent_at or 0)

    def test_primary_partial_sse_is_discarded_and_backup_is_the_only_delivery(self) -> None:
        with ProgrammableResponsesMock(
            lambda _request: missing_terminal_scenario(),
            route_name="P1",
        ) as primary:
            with ProgrammableResponsesMock(
                lambda _request: ScriptedScenario(name="tool", chunks=tool_sse_frames()),
                route_name="P2",
            ) as backup:
                with ExperimentalFullBufferRelay(primary.base_url, backup.base_url) as relay:
                    status, content_type, body = http_post_response(
                        relay.base_url,
                        json.loads(fixture_request().decode("utf-8")),
                    )

                self.assertEqual(status, 200)
                self.assertTrue(content_type.startswith("text/event-stream"))
                delivered = validate_buffered_response(200, content_type, (body,))
                self.assertEqual(len(delivered.tool_calls), 1)
                self.assertEqual(delivered.tool_calls[0].call_id, "call_g2_tool")
                self.assertEqual(primary.request_count, 1)
                self.assertEqual(backup.request_count, 1)
                record = relay.records[0]
                self.assertEqual(record.committed_source, "backup")
                self.assertEqual([attempt["request_hash"] for attempt in record.attempts], [record.request_hash] * 2)

    def test_nonretryable_http_status_does_not_call_backup(self) -> None:
        bad_request = ScriptedScenario(
            name="bad_request",
            status=400,
            content_type="application/json",
            chunks=(b'{"error":{"type":"invalid_request_error"}}',),
        )
        with ProgrammableResponsesMock(lambda _request: bad_request) as primary:
            with ProgrammableResponsesMock(route_name="P2") as backup:
                with ExperimentalFullBufferRelay(primary.base_url, backup.base_url) as relay:
                    status, payload = http_post_json(
                        relay.base_url,
                        json.loads(fixture_request().decode("utf-8")),
                    )
                self.assertEqual(status, 502)
                self.assertEqual(payload["error"]["code"], "guardian_all_routes_failed")
                self.assertEqual(primary.request_count, 1)
                self.assertEqual(backup.request_count, 0)

    def test_state_reference_unknown_or_incompatible_blocks_before_upstream(self) -> None:
        for capability, expected in (
            ("unknown", "guardian_state_reference_portability_unknown"),
            ("incompatible", "guardian_state_reference_not_portable"),
        ):
            with self.subTest(capability=capability):
                with ProgrammableResponsesMock() as primary:
                    with ProgrammableResponsesMock(route_name="P2") as backup:
                        with ExperimentalFullBufferRelay(
                            primary.base_url,
                            backup.base_url,
                            state_compatibility=capability,
                        ) as relay:
                            request = json.loads(fixture_request(previous_response_id="resp_fixture_state").decode("utf-8"))
                            status, payload = http_post_json(relay.base_url, request)
                        self.assertEqual(status, 409)
                        self.assertEqual(payload["error"]["code"], expected)
                        self.assertEqual(primary.request_count, 0)
                        self.assertEqual(backup.request_count, 0)

    def test_state_sharing_fixture_requires_both_directions(self) -> None:
        shared = StateStore()
        with ProgrammableResponsesMock(route_name="P1", state_store=shared, stateful=True) as p1:
            with ProgrammableResponsesMock(route_name="P2", state_store=shared, stateful=True) as p2:
                status, created_by_p1 = http_post_json(p1.base_url, {"model": "fixture", "input": "p1"})
                self.assertEqual(status, 200)
                status, continued_on_p2 = http_post_json(
                    p2.base_url,
                    {"model": "fixture", "input": "p2", "previous_response_id": created_by_p1["id"]},
                )
                self.assertEqual(status, 200)
                status, continued_back_on_p1 = http_post_json(
                    p1.base_url,
                    {"model": "fixture", "input": "p1", "previous_response_id": continued_on_p2["id"]},
                )
                self.assertEqual(status, 200)
                self.assertIn(continued_back_on_p1["id"], shared.response_ids)

        with ProgrammableResponsesMock(route_name="P1", stateful=True) as isolated_p1:
            with ProgrammableResponsesMock(route_name="P2", stateful=True) as isolated_p2:
                _, created = http_post_json(isolated_p1.base_url, {"model": "fixture", "input": "p1"})
                status, payload = http_post_json(
                    isolated_p2.base_url,
                    {"model": "fixture", "input": "p2", "previous_response_id": created["id"]},
                )
                self.assertEqual(status, 404)
                self.assertEqual(payload["error"]["code"], "previous_response_not_found")

    def test_precommit_client_cancel_does_not_start_backup(self) -> None:
        control = ScenarioControl()
        scenario = ScriptedScenario(
            name="cancel",
            chunks=text_sse_frames("G2_CANCEL"),
            wait_before_chunk=len(text_sse_frames()) - 1,
            control=control,
        )
        with ProgrammableResponsesMock(lambda _request: scenario) as primary:
            with ProgrammableResponsesMock(route_name="P2") as backup:
                with ExperimentalFullBufferRelay(primary.base_url, backup.base_url) as relay:
                    host, port, request = raw_post_bytes(relay.base_url, fixture_request())
                    downstream = socket.create_connection((host, port), timeout=3)
                    downstream.sendall(request)
                    self.assertTrue(control.partial_sent.wait(3))
                    downstream.close()
                    self.assertTrue(relay.wait_for_records(1, timeout=3))
                    self.assertEqual(relay.records[0].outcome, "client_cancelled")
                    self.assertEqual(backup.request_count, 0)
                    lingering = [thread.name for thread in threading.enumerate() if thread.name == "g2-attempt-primary"]
                    self.assertEqual(lingering, [])
                    control.release_terminal.set()
                    control.client_disconnected.wait(0.2)

    def test_cancel_between_validation_and_header_commit_stays_uncommitted(self) -> None:
        commit = CommitControl()
        with ProgrammableResponsesMock() as primary:
            with ProgrammableResponsesMock(route_name="P2") as backup:
                with ExperimentalFullBufferRelay(
                    primary.base_url,
                    backup.base_url,
                    commit_control=commit,
                ) as relay:
                    host, port, request = raw_post_bytes(relay.base_url, fixture_request())
                    downstream = socket.create_connection((host, port), timeout=3)
                    downstream.sendall(request)
                    self.assertTrue(commit.ready.wait(3))
                    _set_abortive_close(downstream)
                    downstream.close()
                    time.sleep(0.15)
                    commit.release.set()
                    self.assertTrue(relay.wait_for_records(1, timeout=3))
                    self.assertEqual(relay.records[0].outcome, "client_cancelled")
                    self.assertIsNone(relay.records[0].commit_started_at)
                    self.assertEqual(primary.request_count, 1)
                    self.assertEqual(backup.request_count, 0)

    def test_commit_disconnect_is_delivery_uncertain_and_never_retries(self) -> None:
        huge_text = "x" * (128 * 1024)
        with ProgrammableResponsesMock(lambda _request: text_scenario(text=huge_text)) as primary:
            with ProgrammableResponsesMock(route_name="P2") as backup:
                with ExperimentalFullBufferRelay(
                    primary.base_url,
                    backup.base_url,
                    commit_chunk_size=1024,
                    commit_delay=0.002,
                ) as relay:
                    host, port, request = raw_post_bytes(relay.base_url, fixture_request())
                    downstream = socket.create_connection((host, port), timeout=5)
                    downstream.sendall(request)
                    downstream.settimeout(10)
                    self.assertIn(b"HTTP/1.1 200", downstream.recv(4096))
                    _set_abortive_close(downstream)
                    downstream.close()
                    self.assertTrue(relay.wait_for_records(1, timeout=5))
                    record = relay.records[0]
                    self.assertTrue(record.delivery_uncertain)
                    self.assertEqual(record.outcome, "delivery_uncertain")
                    self.assertEqual(primary.request_count, 1)
                    self.assertEqual(backup.request_count, 0)


if __name__ == "__main__":
    unittest.main()
