from __future__ import annotations

import codecs
from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Iterable, Mapping

from ..models import BufferedResponse, GatewayError


TERMINAL_EVENTS = {
    "response.completed": "completed",
    "response.failed": "failed",
    "response.incomplete": "incomplete",
}

PROTOCOL_COMPATIBILITY_DEFAULTS = {
    "allow_terminal_output_omission": False,
    "allow_terminal_output_missing_item_ids": False,
    "allow_terminal_output_missing_item_status": False,
    "allow_function_call_arguments_done_missing_name": False,
}


def normalize_protocol_compatibility(value: object) -> dict[str, bool]:
    result = dict(PROTOCOL_COMPATIBILITY_DEFAULTS)
    if value is None:
        return result
    if not isinstance(value, Mapping) or not set(value).issubset(result):
        raise ValueError("responses_protocol_compatibility_invalid")
    for name, enabled in value.items():
        if type(enabled) is not bool:
            raise ValueError("responses_protocol_compatibility_invalid")
        result[str(name)] = enabled
    return result


class ResponsesProtocolError(GatewayError):
    def __init__(self, code: str, _detail: str | None = None) -> None:
        super().__init__(code, "上游响应未通过完整性校验。", http_status=502)


@dataclass(frozen=True, slots=True)
class ToolCallCapture:
    item_id: str
    call_id: str
    name: str
    arguments: str


@dataclass(frozen=True, slots=True)
class ValidatedResponsesWire:
    status: int
    content_type: str
    body: bytes
    terminal_type: str
    response_id: str
    event_types: tuple[str, ...]
    output_text: str
    tool_calls: tuple[ToolCallCapture, ...]


@dataclass(slots=True)
class _SSEFrame:
    event_name: str | None
    data: str | None
    comments: tuple[str, ...]
    fields: tuple[tuple[str, str], ...]

    @property
    def has_content(self) -> bool:
        return bool(self.data is not None or self.comments or self.fields)


class _SSEDecoder:
    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._text = ""
        self._event_name: str | None = None
        self._data: list[str] = []
        self._comments: list[str] = []
        self._fields: list[tuple[str, str]] = []

    def feed(self, chunk: bytes) -> list[_SSEFrame]:
        try:
            self._text += self._decoder.decode(chunk, final=False)
        except UnicodeDecodeError as exc:
            raise ResponsesProtocolError("invalid_utf8") from exc
        return self._drain_lines(final=False)

    def finish(self) -> list[_SSEFrame]:
        try:
            self._text += self._decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise ResponsesProtocolError("invalid_utf8") from exc
        frames = self._drain_lines(final=True)
        if self._event_name is not None or self._data or self._comments or self._fields:
            raise ResponsesProtocolError("unterminated_sse_event")
        return frames

    def _drain_lines(self, *, final: bool) -> list[_SSEFrame]:
        frames: list[_SSEFrame] = []
        while self._text:
            newline_at = -1
            newline_size = 0
            for index, character in enumerate(self._text):
                if character == "\n":
                    newline_at, newline_size = index, 1
                    break
                if character == "\r":
                    if index + 1 == len(self._text) and not final:
                        return frames
                    newline_at = index
                    newline_size = 2 if index + 1 < len(self._text) and self._text[index + 1] == "\n" else 1
                    break
            if newline_at < 0:
                if final:
                    line, self._text = self._text, ""
                    self._consume_line(line, frames)
                break
            line = self._text[:newline_at]
            self._text = self._text[newline_at + newline_size :]
            self._consume_line(line, frames)
        return frames

    def _consume_line(self, line: str, frames: list[_SSEFrame]) -> None:
        if line == "":
            if self._event_name is not None or self._data or self._comments or self._fields:
                frames.append(self._dispatch())
            return
        if line.startswith(":"):
            self._comments.append(line[1:])
            return
        if ":" in line:
            field_name, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field_name, value = line, ""
        if field_name == "event":
            self._event_name = value
        elif field_name == "data":
            self._data.append(value)
        else:
            self._fields.append((field_name, value))

    def _dispatch(self) -> _SSEFrame:
        frame = _SSEFrame(
            event_name=self._event_name,
            data="\n".join(self._data) if self._data else None,
            comments=tuple(self._comments),
            fields=tuple(self._fields),
        )
        self._event_name = None
        self._data.clear()
        self._comments.clear()
        self._fields.clear()
        return frame


@dataclass(slots=True)
class _OpenItem:
    item_id: str
    item_type: str
    output_index: int
    call_id: str = ""
    name: str = ""
    argument_parts: list[str] = field(default_factory=list)
    arguments_done: str | None = None
    item_done: bool = False
    final_status: str | None = None


@dataclass(slots=True)
class _OpenContent:
    item_id: str
    content_index: int
    delta_parts: list[str] = field(default_factory=list)
    text_done: str | None = None
    part_done: bool = False


class _ResponsesState:
    def __init__(
        self,
        *,
        allow_terminal_output_omission: bool = False,
        allow_terminal_output_missing_item_ids: bool = False,
        allow_terminal_output_missing_item_status: bool = False,
        allow_function_call_arguments_done_missing_name: bool = False,
    ) -> None:
        self.response_id = ""
        self.created = False
        self.terminal_type = ""
        self.event_types: list[str] = []
        self.output_text_parts: list[str] = []
        self.items: dict[str, _OpenItem] = {}
        self.content_parts: dict[tuple[str, int], _OpenContent] = {}
        self.last_sequence: int | None = None
        self.allow_terminal_output_omission = allow_terminal_output_omission
        self.allow_terminal_output_missing_item_ids = (
            allow_terminal_output_missing_item_ids
        )
        self.allow_terminal_output_missing_item_status = (
            allow_terminal_output_missing_item_status
        )
        self.allow_function_call_arguments_done_missing_name = (
            allow_function_call_arguments_done_missing_name
        )

    def consume(self, frame: _SSEFrame) -> None:
        if not frame.has_content:
            return
        if self.terminal_type:
            raise ResponsesProtocolError("trailing_data")
        if frame.data is None:
            return
        if frame.data == "[DONE]":
            raise ResponsesProtocolError("unverified_done")
        try:
            payload = json.loads(frame.data)
        except json.JSONDecodeError as exc:
            raise ResponsesProtocolError("invalid_sse_json") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("type"), str):
            raise ResponsesProtocolError("invalid_sse_event")
        event_type = payload["type"]
        if frame.event_name and frame.event_name != event_type:
            raise ResponsesProtocolError("event_type_mismatch")
        sequence = payload.get("sequence_number")
        if sequence is not None:
            if not isinstance(sequence, int) or (self.last_sequence is not None and sequence <= self.last_sequence):
                raise ResponsesProtocolError("sequence_regression")
            self.last_sequence = sequence
        self.event_types.append(event_type)
        self._capture_response_identity(payload)
        if event_type == "error":
            raise ResponsesProtocolError("upstream_error_event")
        if event_type == "response.created":
            if self.created:
                raise ResponsesProtocolError("duplicate_created")
            response = payload.get("response")
            if not isinstance(response, dict) or not isinstance(response.get("id"), str) or not response["id"].strip():
                raise ResponsesProtocolError("missing_response_id")
            self.created = True
            return
        if event_type == "response.output_item.added":
            self._item_added(payload)
            return
        if event_type == "response.content_part.added":
            self._message_item(payload)
            key = self._content_key(payload)
            if key in self.content_parts:
                raise ResponsesProtocolError("duplicate_content_part")
            part = payload.get("part")
            if not isinstance(part, dict) or part.get("type") != "output_text" or part.get("text") != "":
                raise ResponsesProtocolError("invalid_content_part")
            self.content_parts[key] = _OpenContent(item_id=key[0], content_index=key[1])
            return
        if event_type == "response.output_text.delta":
            self._message_item(payload)
            content = self._open_content(payload)
            if content.text_done is not None:
                raise ResponsesProtocolError("text_after_done")
            delta = payload.get("delta")
            if not isinstance(delta, str):
                raise ResponsesProtocolError("invalid_text_delta")
            content.delta_parts.append(delta)
            self.output_text_parts.append(delta)
            return
        if event_type == "response.output_text.done":
            self._message_item(payload)
            content = self._open_content(payload)
            text = payload.get("text")
            if content.text_done is not None:
                raise ResponsesProtocolError("duplicate_text_done")
            if not isinstance(text, str) or text != "".join(content.delta_parts):
                raise ResponsesProtocolError("text_done_mismatch")
            content.text_done = text
            return
        if event_type == "response.content_part.done":
            self._message_item(payload)
            content = self._open_content(payload)
            if content.text_done is None or content.part_done:
                raise ResponsesProtocolError("content_part_not_ready")
            part = payload.get("part")
            if not isinstance(part, dict) or part.get("type") != "output_text" or part.get("text") != content.text_done:
                raise ResponsesProtocolError("content_part_mismatch")
            content.part_done = True
            return
        if event_type == "response.function_call_arguments.delta":
            item = self._tool_item(payload)
            if item.arguments_done is not None:
                raise ResponsesProtocolError("tool_delta_after_done")
            delta = payload.get("delta")
            if not isinstance(delta, str):
                raise ResponsesProtocolError("invalid_tool_delta")
            item.argument_parts.append(delta)
            return
        if event_type == "response.function_call_arguments.done":
            item = self._tool_item(payload)
            arguments = payload.get("arguments")
            if "name" not in payload:
                if not self.allow_function_call_arguments_done_missing_name:
                    raise ResponsesProtocolError("tool_name_missing")
            elif payload.get("name") != item.name:
                raise ResponsesProtocolError("tool_name_mismatch")
            if not isinstance(arguments, str) or arguments != "".join(item.argument_parts):
                raise ResponsesProtocolError("tool_arguments_mismatch")
            _load_tool_arguments(arguments)
            item.arguments_done = arguments
            return
        if event_type == "response.output_item.done":
            self._item_done(payload)
            return
        if event_type in TERMINAL_EVENTS:
            self._terminal(payload, event_type)
            return
        if event_type not in {"response.in_progress"} and any(
            key in payload for key in ("item", "item_id", "output_index", "content_index", "call_id")
        ):
            raise ResponsesProtocolError("unknown_stateful_event")

    def finish(self) -> None:
        if not self.created:
            raise ResponsesProtocolError("missing_created")
        if not self.response_id:
            raise ResponsesProtocolError("missing_response_id")
        if any(not content.part_done for content in self.content_parts.values()):
            raise ResponsesProtocolError("open_content_part")
        for item in self.items.values():
            if item.item_type == "function_call" and item.arguments_done is None:
                raise ResponsesProtocolError("open_tool_arguments")
            if not item.item_done:
                raise ResponsesProtocolError("open_output_item")
        if not self.terminal_type:
            raise ResponsesProtocolError("missing_terminal")

    def tool_calls(self) -> tuple[ToolCallCapture, ...]:
        return tuple(
            ToolCallCapture(item.item_id, item.call_id, item.name, item.arguments_done or "")
            for item in self.items.values()
            if item.item_type == "function_call"
        )

    def _capture_response_identity(self, payload: dict[str, Any]) -> None:
        candidate = ""
        response = payload.get("response")
        if isinstance(response, dict) and isinstance(response.get("id"), str):
            candidate = response["id"]
        elif isinstance(payload.get("response_id"), str):
            candidate = payload["response_id"]
        if candidate:
            if self.response_id and self.response_id != candidate:
                raise ResponsesProtocolError("response_id_mismatch")
            self.response_id = candidate

    def _item_added(self, payload: dict[str, Any]) -> None:
        item = payload.get("item")
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("type"), str):
            raise ResponsesProtocolError("invalid_output_item")
        output_index = payload.get("output_index")
        if type(output_index) is not int or output_index < 0:
            raise ResponsesProtocolError("invalid_output_index")
        item_id = item["id"]
        if item_id in self.items:
            raise ResponsesProtocolError("duplicate_output_item")
        if any(existing.output_index == output_index for existing in self.items.values()):
            raise ResponsesProtocolError("duplicate_output_index")
        opened = _OpenItem(
            item_id=item_id,
            item_type=item["type"],
            output_index=output_index,
        )
        if opened.item_type == "function_call":
            if not all(isinstance(item.get(key), str) and item.get(key) for key in ("call_id", "name")):
                raise ResponsesProtocolError("invalid_tool_item")
            opened.call_id = item["call_id"]
            opened.name = item["name"]
            if any(existing.call_id == opened.call_id for existing in self.items.values()):
                raise ResponsesProtocolError("duplicate_call_id")
        self.items[item_id] = opened

    def _item_done(self, payload: dict[str, Any]) -> None:
        item = payload.get("item")
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ResponsesProtocolError("invalid_output_item_done")
        opened = self.items.get(item["id"])
        if opened is None or opened.item_done:
            raise ResponsesProtocolError("output_item_not_open")
        if payload.get("output_index") != opened.output_index:
            raise ResponsesProtocolError("output_item_index_mismatch")
        if item.get("type") != opened.item_type:
            raise ResponsesProtocolError("output_item_type_mismatch")
        if opened.item_type == "function_call":
            if (
                opened.arguments_done is None
                or item.get("arguments") != opened.arguments_done
                or item.get("call_id") != opened.call_id
                or item.get("name") != opened.name
            ):
                raise ResponsesProtocolError("tool_item_mismatch")
        if opened.item_type == "message":
            item_contents = self._completed_content_texts(opened.item_id)
            if not item_contents:
                raise ResponsesProtocolError("text_item_not_done")
            content = item.get("content")
            output_texts = [
                part.get("text")
                for part in content or []
                if isinstance(part, dict) and part.get("type") == "output_text"
            ]
            if output_texts != item_contents:
                raise ResponsesProtocolError("text_item_mismatch")
        if item.get("status") not in ("completed", "incomplete"):
            raise ResponsesProtocolError("output_item_not_completed")
        opened.item_done = True
        opened.final_status = item["status"]

    def _terminal(self, payload: dict[str, Any], event_type: str) -> None:
        response = payload.get("response")
        expected_status = TERMINAL_EVENTS[event_type]
        if not isinstance(response, dict) or response.get("status") != expected_status:
            raise ResponsesProtocolError("terminal_status_mismatch")
        terminal_id = response.get("id")
        if not isinstance(terminal_id, str) or not terminal_id.strip() or terminal_id != self.response_id:
            raise ResponsesProtocolError("missing_response_id")
        if expected_status == "failed" and not isinstance(response.get("error"), dict):
            raise ResponsesProtocolError("invalid_failed_response")
        if expected_status == "incomplete" and not isinstance(response.get("incomplete_details"), dict):
            raise ResponsesProtocolError("invalid_incomplete_response")
        if any(not content.part_done for content in self.content_parts.values()) or any(
            not item.item_done for item in self.items.values()
        ):
            raise ResponsesProtocolError("terminal_with_open_items")
        if expected_status == "completed" and any(item.final_status != "completed" for item in self.items.values()):
            raise ResponsesProtocolError("completed_with_incomplete_item")
        output = response.get("output")
        if output is None:
            if self.allow_terminal_output_omission:
                self.terminal_type = event_type
                return
            raise ResponsesProtocolError("terminal_output_omitted")
        if not isinstance(output, list):
            raise ResponsesProtocolError("terminal_output_invalid_type")
        event_items = {item.item_id: item for item in self.items.values()}
        if not output and event_items and self.allow_terminal_output_omission:
            self.terminal_type = event_type
            return
        terminal_items: dict[str, dict[str, Any]] = {}
        missing_item_ids = False
        for item in output:
            if not isinstance(item, dict):
                raise ResponsesProtocolError("terminal_output_invalid_item")
            if not isinstance(item.get("id"), str):
                missing_item_ids = True
                continue
            if item["id"] in terminal_items:
                raise ResponsesProtocolError("duplicate_terminal_output")
            terminal_items[item["id"]] = item
        if missing_item_ids:
            if not self.allow_terminal_output_missing_item_ids:
                raise ResponsesProtocolError("terminal_output_item_missing_id")
            if terminal_items:
                raise ResponsesProtocolError("terminal_output_mixed_item_ids")
            ordered_event_items = sorted(
                event_items.values(), key=lambda item: item.output_index
            )
            if len(output) != len(ordered_event_items):
                raise ResponsesProtocolError("terminal_output_item_count_mismatch")
            if [item.output_index for item in ordered_event_items] != list(
                range(len(output))
            ):
                raise ResponsesProtocolError("terminal_output_index_mismatch")
            for opened, terminal_item in zip(ordered_event_items, output, strict=True):
                self._validate_terminal_item(opened, terminal_item)
            self.terminal_type = event_type
            return
        event_item_ids = set(event_items)
        terminal_item_ids = set(terminal_items)
        if event_item_ids != terminal_item_ids:
            missing_terminal_items = event_item_ids - terminal_item_ids
            unobserved_terminal_items = terminal_item_ids - event_item_ids
            if missing_terminal_items and not unobserved_terminal_items:
                raise ResponsesProtocolError("terminal_output_missing_event_items")
            if unobserved_terminal_items and not missing_terminal_items:
                raise ResponsesProtocolError("terminal_output_unobserved_items")
            raise ResponsesProtocolError("terminal_output_item_identity_mismatch")
        for item_id, opened in event_items.items():
            self._validate_terminal_item(opened, terminal_items[item_id])
        self.terminal_type = event_type

    def _validate_terminal_item(
        self,
        opened: _OpenItem,
        terminal_item: dict[str, Any],
    ) -> None:
        if terminal_item.get("type") != opened.item_type:
            raise ResponsesProtocolError("terminal_output_item_type_mismatch")
        if "status" not in terminal_item:
            if not self.allow_terminal_output_missing_item_status:
                raise ResponsesProtocolError("terminal_output_item_status_missing")
        elif terminal_item.get("status") != opened.final_status:
            raise ResponsesProtocolError("terminal_output_item_status_mismatch")
        if opened.item_type == "function_call" and any(
            terminal_item.get(key) != expected
            for key, expected in (
                ("call_id", opened.call_id),
                ("name", opened.name),
                ("arguments", opened.arguments_done),
            )
        ):
            raise ResponsesProtocolError("terminal_output_tool_mismatch")
        if opened.item_type == "message":
            output_texts = [
                part.get("text")
                for part in terminal_item.get("content") or []
                if isinstance(part, dict) and part.get("type") == "output_text"
            ]
            if output_texts != self._completed_content_texts(opened.item_id):
                raise ResponsesProtocolError("terminal_output_text_mismatch")

    def _tool_item(self, payload: dict[str, Any]) -> _OpenItem:
        item_id = payload.get("item_id")
        if not isinstance(item_id, str):
            raise ResponsesProtocolError("missing_tool_item_id")
        item = self.items.get(item_id)
        if item is None or item.item_type != "function_call" or item.item_done:
            raise ResponsesProtocolError("tool_item_not_open")
        return item

    def _message_item(self, payload: dict[str, Any]) -> _OpenItem:
        item_id = payload.get("item_id")
        if not isinstance(item_id, str):
            raise ResponsesProtocolError("missing_message_item_id")
        item = self.items.get(item_id)
        if item is None or item.item_type != "message" or item.item_done:
            raise ResponsesProtocolError("message_item_not_open")
        return item

    def _open_content(self, payload: dict[str, Any]) -> _OpenContent:
        key = self._content_key(payload)
        content = self.content_parts.get(key)
        if content is None or content.part_done:
            raise ResponsesProtocolError("content_part_not_open")
        return content

    def _completed_content_texts(self, item_id: str) -> list[str]:
        contents = sorted(
            (content for content in self.content_parts.values() if content.item_id == item_id),
            key=lambda content: content.content_index,
        )
        if any(not content.part_done or content.text_done is None for content in contents):
            return []
        return [content.text_done or "" for content in contents]

    @staticmethod
    def _content_key(payload: dict[str, Any]) -> tuple[str, int]:
        item_id, content_index = payload.get("item_id"), payload.get("content_index")
        if not isinstance(item_id, str) or not isinstance(content_index, int):
            raise ResponsesProtocolError("invalid_content_key")
        return item_id, content_index


def _load_tool_arguments(arguments: str) -> Any:
    try:
        value = json.loads(arguments)
    except json.JSONDecodeError as exc:
        raise ResponsesProtocolError("invalid_tool_arguments") from exc
    if not isinstance(value, dict):
        raise ResponsesProtocolError("invalid_tool_arguments")
    return value


def validate_buffered_response(
    status: int,
    content_type: str,
    chunks: Iterable[bytes],
    *,
    max_bytes: int = 4 * 1024 * 1024,
    allow_terminal_output_omission: bool = False,
    allow_terminal_output_missing_item_ids: bool = False,
    allow_terminal_output_missing_item_status: bool = False,
    allow_function_call_arguments_done_missing_name: bool = False,
) -> ValidatedResponsesWire:
    if status < 200 or status >= 300:
        raise ResponsesProtocolError(f"http_{status}")
    media_type = content_type.split(";", 1)[0].strip().lower()
    body_parts: list[bytes] = []
    size = 0
    if media_type == "text/event-stream":
        decoder = _SSEDecoder()
        state = _ResponsesState(
            allow_terminal_output_omission=allow_terminal_output_omission,
            allow_terminal_output_missing_item_ids=(
                allow_terminal_output_missing_item_ids
            ),
            allow_terminal_output_missing_item_status=(
                allow_terminal_output_missing_item_status
            ),
            allow_function_call_arguments_done_missing_name=(
                allow_function_call_arguments_done_missing_name
            ),
        )
        for chunk in chunks:
            size += len(chunk)
            if size > max_bytes:
                raise ResponsesProtocolError("buffer_limit")
            body_parts.append(chunk)
            for frame in decoder.feed(chunk):
                state.consume(frame)
        for frame in decoder.finish():
            state.consume(frame)
        state.finish()
        return ValidatedResponsesWire(
            status=status,
            content_type=content_type,
            body=b"".join(body_parts),
            terminal_type=state.terminal_type,
            response_id=state.response_id,
            event_types=tuple(state.event_types),
            output_text="".join(state.output_text_parts),
            tool_calls=state.tool_calls(),
        )
    if media_type == "application/json":
        for chunk in chunks:
            size += len(chunk)
            if size > max_bytes:
                raise ResponsesProtocolError("buffer_limit")
            body_parts.append(chunk)
        body = b"".join(body_parts)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ResponsesProtocolError("invalid_json") from exc
        if not isinstance(payload, dict) or payload.get("object") != "response":
            raise ResponsesProtocolError("invalid_response_object")
        response_id, response_status = payload.get("id"), payload.get("status")
        if not isinstance(response_id, str) or not response_id.strip() or response_status not in TERMINAL_EVENTS.values():
            raise ResponsesProtocolError("nonterminal_json")
        if response_status == "failed" and not isinstance(payload.get("error"), dict):
            raise ResponsesProtocolError("invalid_failed_response")
        if response_status == "incomplete" and not isinstance(payload.get("incomplete_details"), dict):
            raise ResponsesProtocolError("invalid_incomplete_response")
        calls = []
        for item in payload.get("output", []):
            if not isinstance(item, dict):
                raise ResponsesProtocolError("invalid_output_item")
            item_status = item.get("status")
            if item_status not in ("completed", "incomplete"):
                raise ResponsesProtocolError("open_output_item")
            if response_status == "completed" and item_status != "completed":
                raise ResponsesProtocolError("completed_with_incomplete_item")
            if item.get("type") == "function_call":
                for key in ("id", "call_id", "name", "arguments"):
                    if not isinstance(item.get(key), str) or not item.get(key):
                        raise ResponsesProtocolError("invalid_tool_item")
                _load_tool_arguments(item["arguments"])
                calls.append(ToolCallCapture(item["id"], item["call_id"], item["name"], item["arguments"]))
        return ValidatedResponsesWire(
            status=status,
            content_type=content_type,
            body=body,
            terminal_type=f"response.{response_status}",
            response_id=response_id,
            event_types=(),
            output_text=_json_output_text(payload),
            tool_calls=tuple(calls),
        )
    raise ResponsesProtocolError("invalid_content_type")


def _json_output_text(payload: dict[str, Any]) -> str:
    parts = []
    for item in payload.get("output", []):
        if isinstance(item, dict) and item.get("type") == "message":
            for part in item.get("content", []):
                if isinstance(part, dict) and part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    parts.append(part["text"])
    return "".join(parts)


class ResponsesProtocolValidator:
    def __init__(
        self,
        *,
        allow_terminal_output_omission: bool = False,
        allow_terminal_output_missing_item_ids: bool = False,
        allow_terminal_output_missing_item_status: bool = False,
        allow_function_call_arguments_done_missing_name: bool = False,
    ) -> None:
        self._allow_terminal_output_omission = allow_terminal_output_omission
        self._allow_terminal_output_missing_item_ids = (
            allow_terminal_output_missing_item_ids
        )
        self._allow_terminal_output_missing_item_status = (
            allow_terminal_output_missing_item_status
        )
        self._allow_function_call_arguments_done_missing_name = (
            allow_function_call_arguments_done_missing_name
        )

    def validate(
        self,
        status: int,
        content_type: str,
        chunks: Iterable[bytes],
        *,
        max_bytes: int,
    ) -> BufferedResponse:
        validated = validate_buffered_response(
            status,
            content_type,
            chunks,
            max_bytes=max_bytes,
            allow_terminal_output_omission=self._allow_terminal_output_omission,
            allow_terminal_output_missing_item_ids=(
                self._allow_terminal_output_missing_item_ids
            ),
            allow_terminal_output_missing_item_status=(
                self._allow_terminal_output_missing_item_status
            ),
            allow_function_call_arguments_done_missing_name=(
                self._allow_function_call_arguments_done_missing_name
            ),
        )
        return BufferedResponse(
            status=validated.status,
            content_type=validated.content_type,
            body=validated.body,
            body_sha256=hashlib.sha256(validated.body).hexdigest(),
            terminal_status=validated.terminal_type.removeprefix("response."),
            response_id=validated.response_id,
            buffer_bytes=len(validated.body),
        )
