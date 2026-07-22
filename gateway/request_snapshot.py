from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .adapter import OpenAIResponsesAdapter
from .models import GatewayError, GatewayLimits, RequestSnapshot


_DROP_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_FORWARD_HEADERS = {
    "accept",
    "openai-beta",
    "openai-organization",
    "openai-project",
    "user-agent",
    "x-client-request-id",
}

_MAX_MODEL_CHARS = 256


def _has_server_side_tool_risk(payload: Mapping[str, Any]) -> bool:
    tools = payload.get("tools", [])
    if not isinstance(tools, list):
        return bool(tools)
    return any(
        not isinstance(tool, dict) or tool.get("type") != "function"
        for tool in tools
    )


def create_request_snapshot(
    body: bytes,
    headers: Mapping[str, str],
    limits: GatewayLimits,
) -> RequestSnapshot:
    if len(body) > limits.max_request_bytes:
        raise GatewayError("guardian_request_too_large", "请求超过本地网关大小上限。", http_status=413)
    normalized_headers = {name.lower(): value for name, value in headers.items()}
    media_type = normalized_headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise GatewayError("guardian_unsupported_media_type", "请求必须使用 application/json。", http_status=415)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayError("guardian_invalid_request", "请求正文不是有效 UTF-8 JSON。", http_status=400) from exc
    if not isinstance(payload, dict):
        raise GatewayError("guardian_invalid_request", "请求正文必须是 JSON 对象。", http_status=400)
    model = payload.get("model")
    if (
        not isinstance(model, str)
        or not model
        or len(model) > _MAX_MODEL_CHARS
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in model)
    ):
        raise GatewayError("guardian_invalid_model", "请求缺少有效模型名称。", http_status=400)
    stream = payload.get("stream", False)
    if not isinstance(stream, bool):
        raise GatewayError("guardian_invalid_stream", "stream 必须为布尔值。", http_status=400)
    forward_headers = {
        name.lower(): value
        for name, value in normalized_headers.items()
        if name.lower() in _FORWARD_HEADERS and name.lower() not in _DROP_HEADERS
    }
    return RequestSnapshot(
        body=bytes(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        model=model,
        stream=stream,
        forward_headers=RequestSnapshot.immutable_headers(forward_headers),
        state_dependencies=OpenAIResponsesAdapter.state_dependencies(payload),
        has_server_side_tool_risk=_has_server_side_tool_risk(payload),
    )
