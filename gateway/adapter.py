from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .models import GatewayError, RequestSnapshot


@dataclass(frozen=True, slots=True)
class UpstreamRequest:
    url: str
    headers: Mapping[str, str]
    body: bytes


class OpenAIResponsesAdapter:
    name = "openai-responses-v1"

    def __init__(self, base_url: str, *, action_required_statuses: frozenset[int] = frozenset()) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid_upstream_base_url")
        if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("non_loopback_upstream_requires_https")
        path = parsed.path.rstrip("/")
        if path.endswith("/responses"):
            path = path[: -len("/responses")]
        if path.endswith("/v1/v1"):
            raise ValueError("duplicate_upstream_v1_path")
        if not path.endswith("/v1"):
            path += "/v1"
        self._base_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        if not action_required_statuses.issubset({404}):
            raise ValueError("unsupported_adapter_action_required_status")
        self._action_required_statuses = frozenset(action_required_statuses)

    def is_action_required_status(self, status: int) -> bool:
        return status in self._action_required_statuses

    @property
    def models_url(self) -> str:
        return self._base_url + "/models"

    @staticmethod
    def state_dependencies(payload: Mapping[str, Any]) -> tuple[str, ...]:
        dependencies: set[str] = set()
        for name in ("previous_response_id", "conversation", "prompt"):
            if _has_reference_value(payload.get(name)):
                dependencies.add(name)
        _collect_input_item_dependencies(payload.get("input"), dependencies)
        _collect_nested_state_dependencies(payload, dependencies)
        return tuple(sorted(dependencies))

    def build_request(self, snapshot: RequestSnapshot, bearer: str) -> UpstreamRequest:
        if not bearer or any(ord(character) < 0x20 or ord(character) == 0x7F for character in bearer):
            raise GatewayError("guardian_upstream_credential_unavailable", "上游凭据不可用。", http_status=500)
        headers = dict(snapshot.forward_headers)
        headers["authorization"] = f"Bearer {bearer}"
        headers["content-type"] = "application/json"
        return UpstreamRequest(
            url=self._base_url + "/responses",
            headers=RequestSnapshot.immutable_headers(headers),
            body=snapshot.body,
        )


_STATE_ID_FIELDS = {
    "container_id",
    "connector_id",
    "file_id",
    "file_ids",
    "skill_id",
    "skill_ids",
    "vector_store_id",
    "vector_store_ids",
}


def _has_reference_value(value: object) -> bool:
    if isinstance(value, str):
        return bool(value)
    return isinstance(value, (dict, list)) and bool(value)


def _collect_nested_state_dependencies(value: object, dependencies: set[str]) -> None:
    if isinstance(value, list):
        for nested in value:
            _collect_nested_state_dependencies(nested, dependencies)
        return
    if not isinstance(value, dict):
        return
    item_type = value.get("type")
    if item_type == "item_reference" and _has_reference_value(value.get("id")):
        dependencies.add("item_reference")
    elif isinstance(item_type, str) and item_type.endswith("_reference"):
        dependencies.add("unknown_reference")
    for name, nested in value.items():
        if name in _STATE_ID_FIELDS and _has_reference_value(nested):
            dependencies.add(name)
        elif name == "container" and _has_container_reference(nested):
            dependencies.add(name)
        elif name.endswith("_reference") and _has_reference_value(nested):
            dependencies.add("unknown_reference")
        _collect_nested_state_dependencies(nested, dependencies)


def _collect_input_item_dependencies(value: object, dependencies: set[str]) -> None:
    if isinstance(value, list):
        for nested in value:
            _collect_input_item_dependencies(nested, dependencies)
        return
    if not isinstance(value, dict):
        return
    if isinstance(value.get("type"), str) and _has_reference_value(value.get("id")):
        dependencies.add("input_item_id")
    for nested in value.values():
        _collect_input_item_dependencies(nested, dependencies)


def _has_container_reference(value: object) -> bool:
    if isinstance(value, str):
        return bool(value and value != "auto")
    if not isinstance(value, dict) or not value:
        return False
    return value.get("type") != "auto" or _has_reference_value(value.get("id"))
