from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from http import HTTPStatus
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import select
import socket
import threading
import time
from typing import Any, Callable
from urllib.parse import urlparse
import uuid

from gateway.protocols.responses import (
    ResponsesProtocolError as ProtocolProbeError,
    ToolCallCapture,
    ValidatedResponsesWire as ValidatedResponse,
    validate_buffered_response,
)


FAKE_BEARER = "guardian-g2-fixture-token"
FIXTURE_MODEL = "gpt-guardian-g2-fixture"
def response_object(
    response_id: str,
    *,
    status: str = "completed",
    output: list[dict[str, Any]] | None = None,
    previous_response_id: str | None = None,
) -> dict[str, Any]:
    error = {"code": "fixture_failed", "message": "Synthetic failure."} if status == "failed" else None
    incomplete = {"reason": "max_output_tokens"} if status == "incomplete" else None
    return {
        "id": response_id,
        "object": "response",
        "created_at": 1,
        "status": status,
        "completed_at": 2 if status == "completed" else None,
        "error": error,
        "incomplete_details": incomplete,
        "instructions": None,
        "max_output_tokens": None,
        "model": FIXTURE_MODEL,
        "output": output or [],
        "parallel_tool_calls": True,
        "previous_response_id": previous_response_id,
        "reasoning": {"effort": None, "summary": None},
        "store": False,
        "temperature": None,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "top_p": None,
        "truncation": "disabled",
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        }
        if status == "completed"
        else None,
    }


def message_item(item_id: str, text: str, *, status: str = "completed") -> dict[str, Any]:
    return {
        "id": item_id,
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": [], "logprobs": []}],
    }


def function_item(item_id: str, call_id: str, name: str, arguments: str, *, status: str = "completed") -> dict[str, Any]:
    return {
        "id": item_id,
        "type": "function_call",
        "call_id": call_id,
        "name": name,
        "arguments": arguments,
        "status": status,
    }


def _event_bytes(event_type: str, payload: dict[str, Any], *, newline: str = "\n", multiline: bool = False) -> bytes:
    text = json.dumps(payload, ensure_ascii=False, indent=2 if multiline else None, separators=None if multiline else (",", ":"))
    data_lines = text.splitlines() or [""]
    lines = [f"event: {event_type}", *(f"data: {line}" for line in data_lines), "", ""]
    return newline.join(lines).encode("utf-8")


def text_sse_frames(
    text: str = "虚构响应 G2_OK",
    *,
    response_id: str = "resp_g2_text",
    mixed_newlines: bool = False,
    multiline_data: bool = False,
) -> tuple[bytes, ...]:
    item_id = "msg_g2_text"
    in_progress = response_object(response_id, status="completed")
    in_progress.update({"status": "in_progress", "completed_at": None, "output": [], "usage": None})
    complete_item = message_item(item_id, text)
    completed = response_object(response_id, output=[complete_item])
    events = [
        ("response.created", {"type": "response.created", "sequence_number": 0, "response": in_progress}),
        ("response.in_progress", {"type": "response.in_progress", "sequence_number": 1, "response": in_progress}),
        (
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "sequence_number": 2,
                "response_id": response_id,
                "output_index": 0,
                "item": {"id": item_id, "type": "message", "status": "in_progress", "role": "assistant", "content": []},
            },
        ),
        (
            "response.content_part.added",
            {
                "type": "response.content_part.added",
                "sequence_number": 3,
                "response_id": response_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            },
        ),
        (
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "sequence_number": 4,
                "response_id": response_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": text,
            },
        ),
        (
            "response.output_text.done",
            {
                "type": "response.output_text.done",
                "sequence_number": 5,
                "response_id": response_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "text": text,
            },
        ),
        (
            "response.content_part.done",
            {
                "type": "response.content_part.done",
                "sequence_number": 6,
                "response_id": response_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": complete_item["content"][0],
            },
        ),
        (
            "response.output_item.done",
            {
                "type": "response.output_item.done",
                "sequence_number": 7,
                "response_id": response_id,
                "output_index": 0,
                "item": complete_item,
            },
        ),
        ("response.completed", {"type": "response.completed", "sequence_number": 8, "response": completed}),
    ]
    frames = []
    for index, (event_type, payload) in enumerate(events):
        newline = "\r\n" if mixed_newlines and index % 2 else "\n"
        frames.append(_event_bytes(event_type, payload, newline=newline, multiline=multiline_data and index == 4))
    return tuple(frames)


def tool_sse_frames(
    *,
    response_id: str = "resp_g2_tool",
    item_id: str = "fc_g2_tool",
    call_id: str = "call_g2_tool",
    name: str = "fixture_lookup",
    arguments: str = '{"city":"深圳","unit":"c"}',
) -> tuple[bytes, ...]:
    first = max(1, len(arguments) // 3)
    second = max(first + 1, (len(arguments) * 2) // 3)
    parts = [arguments[:first], arguments[first:second], arguments[second:]]
    in_progress = response_object(response_id, status="completed")
    in_progress.update({"status": "in_progress", "completed_at": None, "output": [], "usage": None})
    opened_item = function_item(item_id, call_id, name, "", status="in_progress")
    completed_item = function_item(item_id, call_id, name, arguments)
    events: list[tuple[str, dict[str, Any]]] = [
        ("response.created", {"type": "response.created", "sequence_number": 0, "response": in_progress}),
        (
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "sequence_number": 1,
                "response_id": response_id,
                "output_index": 0,
                "item": opened_item,
            },
        ),
    ]
    for index, part in enumerate(parts, start=2):
        events.append(
            (
                "response.function_call_arguments.delta",
                {
                    "type": "response.function_call_arguments.delta",
                    "sequence_number": index,
                    "response_id": response_id,
                    "item_id": item_id,
                    "output_index": 0,
                    "delta": part,
                },
            )
        )
    events.extend(
        [
            (
                "response.function_call_arguments.done",
                {
                    "type": "response.function_call_arguments.done",
                    "sequence_number": 5,
                    "response_id": response_id,
                    "item_id": item_id,
                    "output_index": 0,
                    "arguments": arguments,
                    "name": name,
                },
            ),
            (
                "response.output_item.done",
                {
                    "type": "response.output_item.done",
                    "sequence_number": 6,
                    "response_id": response_id,
                    "output_index": 0,
                    "item": completed_item,
                },
            ),
            (
                "response.completed",
                {
                    "type": "response.completed",
                    "sequence_number": 7,
                    "response": response_object(response_id, output=[completed_item]),
                },
            ),
        ]
    )
    return tuple(_event_bytes(event_type, payload) for event_type, payload in events)


def terminal_sse_frames(status: str, *, response_id: str | None = None) -> tuple[bytes, ...]:
    if status not in ("failed", "incomplete"):
        raise ValueError(status)
    response_id = response_id or f"resp_g2_{status}"
    created = response_object(response_id, status="completed")
    created.update({"status": "in_progress", "completed_at": None, "output": [], "usage": None})
    return (
        _event_bytes("response.created", {"type": "response.created", "sequence_number": 0, "response": created}),
        _event_bytes(
            f"response.{status}",
            {"type": f"response.{status}", "sequence_number": 1, "response": response_object(response_id, status=status)},
        ),
    )


@dataclass
class ScenarioControl:
    release_terminal: threading.Event = field(default_factory=threading.Event)
    partial_sent: threading.Event = field(default_factory=threading.Event)
    terminal_sent: threading.Event = field(default_factory=threading.Event)
    client_disconnected: threading.Event = field(default_factory=threading.Event)
    terminal_sent_at: float | None = None


@dataclass(frozen=True)
class ScriptedScenario:
    name: str
    status: int = 200
    content_type: str = "text/event-stream; charset=utf-8"
    chunks: tuple[bytes, ...] = ()
    wait_before_chunk: int | None = None
    control: ScenarioControl | None = None
    delay_seconds: float = 0.0
    chunk_delays: tuple[float, ...] = ()
    response_headers: tuple[tuple[str, str], ...] = ()


def text_scenario(
    *,
    text: str = "虚构响应 G2_OK",
    response_id: str = "resp_g2_text",
    gate_terminal: bool = False,
    delay_seconds: float = 0.0,
    single_byte_chunks: bool = False,
) -> ScriptedScenario:
    frames = text_sse_frames(text, response_id=response_id)
    control = ScenarioControl() if gate_terminal else None
    chunks = frames
    wait_before = len(chunks) - 1 if gate_terminal else None
    if single_byte_chunks:
        chunks = tuple(bytes((byte,)) for byte in b"".join(frames))
        wait_before = None
    return ScriptedScenario(
        name="text",
        chunks=chunks,
        wait_before_chunk=wait_before,
        control=control,
        delay_seconds=delay_seconds,
    )


def json_scenario(*, response_id: str = "resp_g2_json", text: str = "G2_JSON_OK", status: str = "completed") -> ScriptedScenario:
    output = [message_item("msg_g2_json", text)] if status == "completed" else []
    body = json.dumps(response_object(response_id, status=status, output=output), ensure_ascii=False).encode("utf-8")
    return ScriptedScenario(name=f"json_{status}", content_type="application/json; charset=utf-8", chunks=(body,))


def missing_terminal_scenario(*, response_id: str = "resp_g2_missing") -> ScriptedScenario:
    return ScriptedScenario(name="missing_terminal", chunks=text_sse_frames(response_id=response_id)[:-1])


def trailing_garbage_scenario() -> ScriptedScenario:
    return ScriptedScenario(name="trailing_garbage", chunks=text_sse_frames() + (b"data: garbage-after-terminal\n\n",))


def truncated_tool_scenario() -> ScriptedScenario:
    return ScriptedScenario(name="truncated_tool", chunks=tool_sse_frames()[:3])


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    path: str
    header_names: tuple[str, ...]
    authorization_scheme: str | None
    authorization_valid: bool
    content_type: str | None
    body_sha256: str
    json_body: dict[str, Any] | None


class StateStore:
    def __init__(self) -> None:
        self.response_ids: set[str] = set()


@dataclass
class CommitControl:
    ready: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)


class ProgrammableResponsesMock:
    def __init__(
        self,
        scenario_factory: Callable[[CapturedRequest], ScriptedScenario] | None = None,
        *,
        route_name: str = "P1",
        state_store: StateStore | None = None,
        stateful: bool = False,
    ) -> None:
        self.route_name = route_name
        self.scenario_factory = scenario_factory or (lambda _request: text_scenario())
        self.state_store = state_store or StateStore()
        self.stateful = stateful
        self.requests: list[CapturedRequest] = []
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Mock is not running.")
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    @property
    def request_count(self) -> int:
        with self._lock:
            return len(self.requests)

    def start(self) -> "ProgrammableResponsesMock":
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "GuardianG2Mock/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def do_GET(self) -> None:
                if urlparse(self.path).path.rstrip("/") not in ("/v1/models", "/models"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                body = json.dumps(model_list_payload(), separators=(",", ":")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_POST(self) -> None:
                request_path = urlparse(self.path).path
                if request_path != "/v1/responses":
                    self._write_json(404, {"error": {"type": "synthetic_not_found"}})
                    return
                if self.headers.get("Authorization") != f"Bearer {FAKE_BEARER}":
                    self._write_json(401, {"error": {"type": "synthetic_auth_rejected"}})
                    return
                media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if media_type != "application/json":
                    self._write_json(415, {"error": {"type": "synthetic_bad_mime"}})
                    return
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(length)
                try:
                    parsed = json.loads(raw_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parsed = None
                authorization = self.headers.get("Authorization")
                captured = CapturedRequest(
                    method="POST",
                    path=urlparse(self.path).path,
                    header_names=tuple(sorted(name.lower() for name in self.headers.keys())),
                    authorization_scheme=authorization.split(" ", 1)[0] if authorization else None,
                    authorization_valid=authorization == f"Bearer {FAKE_BEARER}",
                    content_type=self.headers.get("Content-Type"),
                    body_sha256=hashlib.sha256(raw_body).hexdigest(),
                    json_body=parsed if isinstance(parsed, dict) else None,
                )
                with owner._condition:
                    owner.requests.append(captured)
                    owner._condition.notify_all()
                if owner.stateful and isinstance(parsed, dict):
                    previous = parsed.get("previous_response_id")
                    if previous is not None and previous not in owner.state_store.response_ids:
                        body = json.dumps(
                            {"error": {"type": "invalid_request_error", "code": "previous_response_not_found", "message": "Synthetic state is not visible."}},
                            separators=(",", ":"),
                        ).encode("utf-8")
                        self.send_response(404)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(body)
                        self.close_connection = True
                        return
                    response_id = f"resp_{owner.route_name.lower()}_{owner.request_count}"
                    owner.state_store.response_ids.add(response_id)
                    scenario = json_scenario(response_id=response_id, text=f"{owner.route_name}_STATE_OK")
                else:
                    scenario = owner.scenario_factory(captured)
                self.send_response(scenario.status)
                self.send_header("Content-Type", scenario.content_type)
                for header_name, header_value in scenario.response_headers:
                    self.send_header(header_name, header_value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                try:
                    for index, chunk in enumerate(scenario.chunks):
                        if scenario.wait_before_chunk == index and scenario.control is not None:
                            deadline = time.monotonic() + 30
                            while not scenario.control.release_terminal.wait(timeout=0.02):
                                if time.monotonic() >= deadline:
                                    return
                                try:
                                    readable, _, _ = select.select([self.connection], [], [], 0)
                                    if readable and self.connection.recv(1, socket.MSG_PEEK) == b"":
                                        scenario.control.client_disconnected.set()
                                        return
                                except (OSError, ValueError):
                                    scenario.control.client_disconnected.set()
                                    return
                        delay = (
                            scenario.chunk_delays[index]
                            if index < len(scenario.chunk_delays)
                            else scenario.delay_seconds
                        )
                        if delay:
                            time.sleep(delay)
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        if scenario.control is not None:
                            if scenario.wait_before_chunk == index + 1:
                                scenario.control.partial_sent.set()
                            if index == len(scenario.chunks) - 1:
                                scenario.control.terminal_sent_at = time.monotonic()
                                scenario.control.terminal_sent.set()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    if scenario.control is not None:
                        scenario.control.client_disconnected.set()

            def _write_json(self, status: int, value: Any) -> None:
                body = json.dumps(value, separators=(",", ":")).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                self.close_connection = True

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name=f"g2-mock-{self.route_name}", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None

    def wait_for_requests(self, count: int, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self.requests) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def __enter__(self) -> "ProgrammableResponsesMock":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()


@dataclass
class RelayRecord:
    request_hash: str
    attempts: list[dict[str, Any]] = field(default_factory=list)
    outcome: str = "pending"
    committed_source: str | None = None
    commit_started_at: float | None = None
    delivery_uncertain: bool = False


class _AttemptTask:
    def __init__(self, url: str, body: bytes, source: str, max_bytes: int) -> None:
        self.url, self.body, self.source, self.max_bytes = url, body, source, max_bytes
        self.result: ValidatedResponse | None = None
        self.error: ProtocolProbeError | None = None
        self._cancelled = threading.Event()
        self._connection: HTTPConnection | None = None
        self._socket: socket.socket | None = None
        self._thread = threading.Thread(target=self._run, name=f"g2-attempt-{source}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def cancel(self) -> None:
        self._cancelled.set()
        upstream_socket = self._socket
        if upstream_socket is not None:
            try:
                upstream_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _run(self) -> None:
        parsed = urlparse(self.url)
        connection = HTTPConnection(parsed.hostname, parsed.port, timeout=30)
        self._connection = connection
        response = None
        try:
            connection.request(
                "POST",
                parsed.path,
                body=self.body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {FAKE_BEARER}"},
            )
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "")
            response_socket = getattr(getattr(response.fp, "raw", None), "_sock", None)
            if response_socket is None:
                raise ProtocolProbeError("transport_error")
            self._socket = response_socket
            chunks: list[bytes] = []
            total = 0
            while True:
                if self._cancelled.is_set():
                    raise ProtocolProbeError("client_cancelled")
                readable, _, _ = select.select([response_socket], [], [], 0.05)
                if not readable:
                    continue
                chunk = response.read1(4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_bytes:
                    raise ProtocolProbeError("buffer_limit", "Response exceeds the G2 buffer limit.")
                chunks.append(chunk)
            self.result = validate_buffered_response(response.status, content_type, chunks, max_bytes=self.max_bytes)
        except ProtocolProbeError as exc:
            self.error = exc
        except Exception as exc:
            self.error = ProtocolProbeError("transport_error", f"Synthetic upstream transport failed: {type(exc).__name__}.")
        finally:
            if response is not None:
                response.close()
            self._socket = None
            connection.close()


class ExperimentalFullBufferRelay:
    """Test-only relay. It deliberately has no production configuration hooks."""

    def __init__(
        self,
        primary_url: str,
        backup_url: str | None = None,
        *,
        state_compatibility: str = "shared",
        max_bytes: int = 4 * 1024 * 1024,
        commit_chunk_size: int = 64 * 1024,
        commit_delay: float = 0.0,
        commit_control: CommitControl | None = None,
    ) -> None:
        if state_compatibility not in ("shared", "incompatible", "unknown"):
            raise ValueError(state_compatibility)
        self.primary_url = primary_url.rstrip("/") + "/responses"
        self.backup_url = backup_url.rstrip("/") + "/responses" if backup_url else None
        self.state_compatibility = state_compatibility
        self.max_bytes = max_bytes
        self.commit_chunk_size = commit_chunk_size
        self.commit_delay = commit_delay
        self.commit_control = commit_control
        self.records: list[RelayRecord] = []
        self.ingress_requests: list[CapturedRequest] = []
        self._condition = threading.Condition()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Relay is not running.")
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    def start(self) -> "ExperimentalFullBufferRelay":
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "GuardianG2Relay/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def handle_expect_100(self) -> bool:
                # Codex 0.144.1 does not send Expect for the probed request. The
                # lab suppresses automatic 100 responses so byte-zero assertions
                # remain authoritative.
                return True

            def do_GET(self) -> None:
                if urlparse(self.path).path.rstrip("/") not in ("/v1/models", "/models"):
                    self.send_error(404)
                    return
                self._send_json(200, model_list_payload())

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                request_body = self.rfile.read(length)
                request_hash = hashlib.sha256(request_body).hexdigest()
                record = RelayRecord(request_hash=request_hash)
                try:
                    request_json = json.loads(request_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    request_json = None
                authorization = self.headers.get("Authorization")
                captured = CapturedRequest(
                    method="POST",
                    path=urlparse(self.path).path,
                    header_names=tuple(sorted(name.lower() for name in self.headers.keys())),
                    authorization_scheme=authorization.split(" ", 1)[0] if authorization else None,
                    authorization_valid=authorization == f"Bearer {FAKE_BEARER}",
                    content_type=self.headers.get("Content-Type"),
                    body_sha256=request_hash,
                    json_body=request_json if isinstance(request_json, dict) else None,
                )
                with owner._condition:
                    owner.ingress_requests.append(captured)
                    owner._condition.notify_all()
                if captured.path != "/v1/responses":
                    record.outcome = "invalid_path"
                    self._send_error_json(404, "guardian_not_found")
                    owner._finish_record(record)
                    return
                if not captured.authorization_valid:
                    record.outcome = "invalid_auth"
                    self._send_error_json(401, "guardian_unauthorized")
                    owner._finish_record(record)
                    return
                media_type = (captured.content_type or "").split(";", 1)[0].strip().lower()
                if media_type != "application/json":
                    record.outcome = "invalid_content_type"
                    self._send_error_json(415, "guardian_unsupported_media_type")
                    owner._finish_record(record)
                    return
                if not isinstance(request_json, dict):
                    record.outcome = "invalid_request"
                    self._send_error_json(400, "guardian_invalid_request")
                    owner._finish_record(record)
                    return
                if request_json.get("previous_response_id") and owner.state_compatibility != "shared":
                    record.outcome = f"state_{owner.state_compatibility}"
                    code = (
                        "guardian_state_reference_not_portable"
                        if owner.state_compatibility == "incompatible"
                        else "guardian_state_reference_portability_unknown"
                    )
                    self._send_error_json(409, code)
                    owner._finish_record(record)
                    return

                done = threading.Event()
                client_cancelled = threading.Event()

                def monitor_client() -> None:
                    while not done.wait(0.02):
                        try:
                            readable, _, _ = select.select([self.connection], [], [], 0)
                            if readable and self.connection.recv(1, socket.MSG_PEEK) == b"":
                                client_cancelled.set()
                                return
                        except (OSError, ValueError):
                            client_cancelled.set()
                            return

                monitor = threading.Thread(target=monitor_client, name="g2-downstream-monitor", daemon=True)
                monitor.start()
                validated: ValidatedResponse | None = None
                source = ""
                for source, url in (("primary", owner.primary_url), ("backup", owner.backup_url)):
                    if url is None:
                        continue
                    task = _AttemptTask(url, request_body, source, owner.max_bytes)
                    task.start()
                    while task.is_alive():
                        task.join(0.02)
                        if client_cancelled.is_set():
                            task.cancel()
                            task.join(3)
                            if task.is_alive():
                                record.outcome = "cancel_propagation_failed"
                                done.set()
                                owner._finish_record(record)
                                return
                            record.outcome = "client_cancelled"
                            done.set()
                            owner._finish_record(record)
                            return
                    if task.result is not None:
                        validated = task.result
                        record.attempts.append({"source": source, "ok": True, "request_hash": request_hash})
                        break
                    error = task.error or ProtocolProbeError("transport_error", "Unknown transport failure.")
                    if error.code == "client_cancelled" or client_cancelled.is_set():
                        record.outcome = "client_cancelled"
                        done.set()
                        owner._finish_record(record)
                        return
                    record.attempts.append({"source": source, "ok": False, "code": error.code, "request_hash": request_hash})
                    if error.code.startswith("http_"):
                        try:
                            status = int(error.code.split("_", 1)[1])
                        except ValueError:
                            status = 0
                        if status not in (401, 403, 429, 500, 502, 503, 504):
                            break
                if validated is None:
                    done.set()
                    record.outcome = "all_routes_failed"
                    self._send_error_json(502, "guardian_all_routes_failed")
                    owner._finish_record(record)
                    return

                if owner.commit_control is not None:
                    owner.commit_control.ready.set()
                    owner.commit_control.release.wait(timeout=5)
                if client_cancelled.is_set():
                    done.set()
                    record.outcome = "client_cancelled"
                    owner._finish_record(record)
                    return

                record.committed_source = source
                record.commit_started_at = time.monotonic()
                record.outcome = "delivered"
                try:
                    self.send_response(validated.status)
                    self.send_header("Content-Type", validated.content_type)
                    self.send_header("Content-Length", str(len(validated.body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    for offset in range(0, len(validated.body), owner.commit_chunk_size):
                        if client_cancelled.is_set():
                            raise BrokenPipeError
                        self.wfile.write(validated.body[offset : offset + owner.commit_chunk_size])
                        self.wfile.flush()
                        if owner.commit_delay:
                            time.sleep(owner.commit_delay)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    record.outcome = "delivery_uncertain"
                    record.delivery_uncertain = True
                finally:
                    done.set()
                    self.close_connection = True
                    owner._finish_record(record)

            def _send_error_json(self, status: int, code: str) -> None:
                self._send_json(
                    status,
                    {
                        "error": {
                            "type": "guardian_gateway_error",
                            "code": code,
                            "message": "Synthetic G2 gateway error.",
                            "request_id": f"g2_{uuid.uuid4().hex[:12]}",
                        }
                    },
                )

            def _send_json(self, status: int, value: Any) -> None:
                body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                self.close_connection = True

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="g2-relay", daemon=True)
        self._thread.start()
        return self

    def _finish_record(self, record: RelayRecord) -> None:
        with self._condition:
            self.records.append(record)
            self._condition.notify_all()

    def wait_for_records(self, count: int, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self.records) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None

    def __enter__(self) -> "ExperimentalFullBufferRelay":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()


def model_list_payload() -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": FIXTURE_MODEL,
                "object": "model",
                "created": 1,
                "owned_by": "guardian-g2-fixture",
            }
        ],
    }


def fixture_request(*, previous_response_id: str | None = None, stream: bool = True) -> bytes:
    value: dict[str, Any] = {
        "model": FIXTURE_MODEL,
        "input": "Synthetic G2 prompt; no user content.",
        "stream": stream,
        "tools": [],
    }
    if previous_response_id is not None:
        value["previous_response_id"] = previous_response_id
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def raw_http_request(host: str, port: int, request: bytes, *, timeout: float = 5.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as client:
        client.sendall(request)
        client.settimeout(timeout)
        chunks = []
        while True:
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def raw_post_bytes(base_url: str, body: bytes) -> tuple[str, int, bytes]:
    parsed = urlparse(base_url)
    host, port = parsed.hostname or "127.0.0.1", parsed.port or 80
    path = parsed.path.rstrip("/") + "/responses"
    request = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\n"
        f"Authorization: Bearer {FAKE_BEARER}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + body
    return host, port, request


def http_post_response(base_url: str, value: dict[str, Any]) -> tuple[int, str, bytes]:
    parsed = urlparse(base_url)
    connection = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        connection.request(
            "POST",
            parsed.path.rstrip("/") + "/responses",
            body=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {FAKE_BEARER}"},
        )
        response = connection.getresponse()
        return response.status, response.getheader("Content-Type", ""), response.read()
    finally:
        connection.close()


def http_post_json(base_url: str, value: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    status, _content_type, body = http_post_response(base_url, value)
    payload = json.loads(body.decode("utf-8"))
    return status, payload
