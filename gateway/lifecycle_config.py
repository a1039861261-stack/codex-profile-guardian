from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import aiohttp

from .adapter import OpenAIResponsesAdapter
from .attempts import SingleRouteAttemptRunner
from .breaker import CircuitBreakerPolicy
from .config import (
    FailoverGroupConfig,
    ProbeMode,
    ProbePolicy,
    RouteConfig,
    RouteRole,
    StateCompatibility,
    StateCompatibilityEvidence,
)
from .models import GatewayLimits
from .protocols.responses import (
    ResponsesProtocolValidator,
    normalize_protocol_compatibility,
)


class ActiveConfigError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LifecycleConfig:
    instance_id: str
    version: str
    host: str
    data_port: int
    control_port: int
    minimum_free_bytes: int
    drain_timeout_seconds: float
    active_group: FailoverGroupConfig
    limits: GatewayLimits


RunnerFactory = Callable[[Mapping[str, Any], RouteRole, GatewayLimits], object]


def load_active_config(
    path: str | Path,
    session: aiohttp.ClientSession,
    *,
    runner_factory: RunnerFactory | None = None,
    max_bytes: int = 1024 * 1024,
) -> LifecycleConfig:
    config_path = Path(path)
    try:
        payload = config_path.read_bytes()
    except OSError as exc:
        raise ActiveConfigError("gateway_config_read_failed") from exc
    if len(payload) > max_bytes:
        raise ActiveConfigError("gateway_config_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveConfigError("gateway_config_json_invalid") from exc
    if not isinstance(document, Mapping):
        raise ActiveConfigError("gateway_config_json_invalid")
    return parse_active_config(document, session, runner_factory=runner_factory)


def parse_active_config(
    document: Mapping[str, Any],
    session: aiohttp.ClientSession,
    *,
    runner_factory: RunnerFactory | None = None,
) -> LifecycleConfig:
    allowed_top_level = {
        "schema_version",
        "instance_id",
        "gateway_version",
        "listen",
        "limits",
        "lifecycle",
        "active_group",
    }
    if set(document) != allowed_top_level:
        raise ActiveConfigError("gateway_config_fields_invalid")
    if _integer(document, "schema_version") != 1:
        raise ActiveConfigError("gateway_config_schema_unsupported")
    instance_id = _string(document, "instance_id")
    version = _string(document, "gateway_version")
    listen = _mapping(document, "listen")
    _require_fields(listen, {"host", "data_port", "control_port"}, "gateway_listen_fields_invalid")
    host = _string(listen, "host")
    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ActiveConfigError("gateway_listen_host_must_be_loopback") from exc
    if parsed_host != ipaddress.ip_address("127.0.0.1"):
        raise ActiveConfigError("gateway_listen_host_must_be_loopback")
    data_port = _port(listen, "data_port")
    control_port = _port(listen, "control_port")
    if data_port == control_port:
        raise ActiveConfigError("gateway_ports_must_be_distinct")
    limits = _limits(_mapping(document, "limits"))
    lifecycle = _mapping(document, "lifecycle")
    _require_fields(
        lifecycle,
        {"minimum_free_bytes", "drain_timeout_seconds"},
        "gateway_lifecycle_fields_invalid",
    )
    minimum_free_bytes = _bounded_integer(
        lifecycle,
        "minimum_free_bytes",
        minimum=1024 * 1024,
        maximum=1024 * 1024 * 1024 * 1024,
    )
    drain_timeout_seconds = _bounded_number(
        lifecycle,
        "drain_timeout_seconds",
        minimum=0.1,
        maximum=300.0,
    )
    raw_group = _mapping(document, "active_group")
    _require_fields(
        raw_group,
        {
            "revision",
            "group_id",
            "primary",
            "backup",
            "allowed_models",
            "breaker_policy",
            "probe_policy",
            "state_compatibility",
        },
        "gateway_group_fields_invalid",
    )
    revision = _integer(raw_group, "revision")
    group_id = _string(raw_group, "group_id")
    factory = runner_factory or _default_runner_factory(session)
    primary = _route(_mapping(raw_group, "primary"), RouteRole.PRIMARY, limits, factory)
    backup = _route(_mapping(raw_group, "backup"), RouteRole.BACKUP, limits, factory)
    allowed_models_value = raw_group.get("allowed_models")
    if not isinstance(allowed_models_value, list) or not all(
        isinstance(model, str) and model for model in allowed_models_value
    ):
        raise ActiveConfigError("gateway_models_invalid")
    breaker_policy = _breaker_policy(_mapping(raw_group, "breaker_policy"))
    probe_policy = _probe_policy(_mapping(raw_group, "probe_policy"))
    compatibility = _state_compatibility(
        raw_group.get("state_compatibility", {}),
        revision,
        primary,
        backup,
    )
    try:
        group = FailoverGroupConfig(
            instance_id=instance_id,
            group_id=group_id,
            revision=revision,
            primary=primary,
            backup=backup,
            allowed_models=tuple(allowed_models_value),
            breaker_policy=breaker_policy,
            probe_policy=probe_policy,
            state_compatibility=compatibility,
        )
    except (TypeError, ValueError) as exc:
        raise ActiveConfigError(str(exc)) from exc
    return LifecycleConfig(
        instance_id=instance_id,
        version=version,
        host=host,
        data_port=data_port,
        control_port=control_port,
        minimum_free_bytes=minimum_free_bytes,
        drain_timeout_seconds=drain_timeout_seconds,
        active_group=group,
        limits=limits,
    )


def _default_runner_factory(session: aiohttp.ClientSession) -> RunnerFactory:
    def build(route: Mapping[str, Any], _role: RouteRole, limits: GatewayLimits) -> object:
        adapter = OpenAIResponsesAdapter(_validated_base_url(_string(route, "base_url")))
        compatibility = normalize_protocol_compatibility(
            route.get("protocol_compatibility")
        )
        return SingleRouteAttemptRunner(
            session,
            adapter,
            limits,
            validator=ResponsesProtocolValidator(**compatibility),
        )

    return build


def _route(
    value: Mapping[str, Any],
    role: RouteRole,
    limits: GatewayLimits,
    factory: RunnerFactory,
) -> RouteConfig:
    allowed_fields = {
        "profile_id",
        "base_url",
        "adapter_name",
        "secret_ref",
        "secret_suffix",
        "enabled",
        "protocol_compatibility",
    }
    if not set(value).issubset(allowed_fields):
        raise ActiveConfigError("gateway_route_fields_invalid")
    base_url = _validated_base_url(_string(value, "base_url"))
    adapter_name = _string(value, "adapter_name")
    if adapter_name != OpenAIResponsesAdapter.name:
        raise ActiveConfigError("gateway_adapter_unsupported")
    try:
        protocol_compatibility = normalize_protocol_compatibility(
            value.get("protocol_compatibility")
        )
    except ValueError as exc:
        raise ActiveConfigError("gateway_protocol_compatibility_invalid") from exc
    material = {
        "role": role.value,
        "profile_id": _string(value, "profile_id"),
        "base_url": base_url,
        "adapter_name": adapter_name,
        "secret_ref": _string(value, "secret_ref"),
        "protocol_compatibility": protocol_compatibility,
    }
    fingerprint = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        return RouteConfig(
            role=role,
            profile_id=material["profile_id"],
            fingerprint=fingerprint,
            adapter_name=adapter_name,
            secret_ref=material["secret_ref"],
            runner=factory(value, role, limits),
            secret_suffix=_optional_string(value, "secret_suffix", maximum=8),
            enabled=_boolean(value, "enabled", default=True),
            protocol_compatibility=protocol_compatibility,
        )
    except (TypeError, ValueError) as exc:
        raise ActiveConfigError(str(exc)) from exc


def _state_compatibility(
    value: object,
    revision: int,
    primary: RouteConfig,
    backup: RouteConfig,
) -> Mapping[str, StateCompatibilityEvidence]:
    if not isinstance(value, Mapping):
        raise ActiveConfigError("gateway_state_compatibility_invalid")
    result: dict[str, StateCompatibilityEvidence] = {}
    for model, evidence_value in value.items():
        if not isinstance(model, str) or not model or not isinstance(evidence_value, Mapping):
            raise ActiveConfigError("gateway_state_compatibility_invalid")
        _require_fields(
            evidence_value,
            {"status", "primary_to_backup", "backup_to_primary"},
            "gateway_state_compatibility_invalid",
        )
        try:
            status = StateCompatibility(_string(evidence_value, "status"))
        except ValueError as exc:
            raise ActiveConfigError("gateway_state_compatibility_invalid") from exc
        result[model] = StateCompatibilityEvidence(
            status=status,
            config_revision=revision,
            primary_fingerprint=primary.fingerprint,
            backup_fingerprint=backup.fingerprint,
            adapter_name=primary.adapter_name,
            model=model,
            primary_to_backup=_boolean(evidence_value, "primary_to_backup", default=False),
            backup_to_primary=_boolean(evidence_value, "backup_to_primary", default=False),
        )
    return MappingProxyType(result)


def _limits(value: Mapping[str, Any]) -> GatewayLimits:
    _require_fields(
        value,
        {
            "max_request_bytes",
            "max_response_bytes",
            "read_chunk_bytes",
            "max_concurrent_requests",
            "connect_timeout_seconds",
            "first_byte_timeout_seconds",
            "idle_timeout_seconds",
            "total_timeout_seconds",
        },
        "gateway_limits_fields_invalid",
    )
    try:
        return GatewayLimits(
            max_request_bytes=_bounded_integer(value, "max_request_bytes", minimum=1, maximum=64 * 1024 * 1024),
            max_response_bytes=_bounded_integer(value, "max_response_bytes", minimum=1, maximum=256 * 1024 * 1024),
            read_chunk_bytes=_bounded_integer(value, "read_chunk_bytes", minimum=1024, maximum=1024 * 1024),
            max_concurrent_requests=_bounded_integer(value, "max_concurrent_requests", minimum=1, maximum=128),
            connect_timeout_seconds=_bounded_number(value, "connect_timeout_seconds", minimum=0.1, maximum=120),
            first_byte_timeout_seconds=_bounded_number(value, "first_byte_timeout_seconds", minimum=0.1, maximum=600),
            idle_timeout_seconds=_bounded_number(value, "idle_timeout_seconds", minimum=0.1, maximum=600),
            total_timeout_seconds=_bounded_number(value, "total_timeout_seconds", minimum=0.1, maximum=3600),
        )
    except ValueError as exc:
        raise ActiveConfigError(str(exc)) from exc


def _breaker_policy(value: Mapping[str, Any]) -> CircuitBreakerPolicy:
    _require_fields(
        value,
        {
            "failure_threshold",
            "protocol_failure_threshold",
            "error_rate_threshold",
            "minimum_samples",
            "window_size",
            "recovery_success_threshold",
            "base_cooldown_seconds",
            "max_cooldown_seconds",
            "jitter_ratio",
        },
        "gateway_breaker_fields_invalid",
    )
    try:
        return CircuitBreakerPolicy(
            failure_threshold=_bounded_integer(value, "failure_threshold", minimum=1, maximum=1000),
            protocol_failure_threshold=_bounded_integer(value, "protocol_failure_threshold", minimum=1, maximum=1000),
            error_rate_threshold=_optional_number(value, "error_rate_threshold", minimum=0.01, maximum=1.0),
            minimum_samples=_bounded_integer(value, "minimum_samples", minimum=1, maximum=10000),
            window_size=_bounded_integer(value, "window_size", minimum=1, maximum=10000),
            recovery_success_threshold=_bounded_integer(value, "recovery_success_threshold", minimum=1, maximum=1000),
            base_cooldown_seconds=_bounded_number(value, "base_cooldown_seconds", minimum=0.1, maximum=86400),
            max_cooldown_seconds=_bounded_number(value, "max_cooldown_seconds", minimum=0.1, maximum=86400),
            jitter_ratio=_bounded_number(value, "jitter_ratio", minimum=0, maximum=1),
        )
    except ValueError as exc:
        raise ActiveConfigError(str(exc)) from exc


def _probe_policy(value: Mapping[str, Any]) -> ProbePolicy:
    _require_fields(
        value,
        {
            "enabled",
            "mode",
            "interval_seconds",
            "timeout_seconds",
            "allow_billable",
            "allow_action_required_auto_retest",
        },
        "gateway_probe_fields_invalid",
    )
    try:
        return ProbePolicy(
            enabled=_boolean(value, "enabled", default=False),
            mode=ProbeMode(_string(value, "mode")),
            interval_seconds=_bounded_number(value, "interval_seconds", minimum=30, maximum=7 * 24 * 60 * 60),
            timeout_seconds=_bounded_number(value, "timeout_seconds", minimum=0.1, maximum=60),
            allow_billable=_boolean(value, "allow_billable", default=False),
            allow_action_required_auto_retest=_boolean(
                value,
                "allow_action_required_auto_retest",
                default=False,
            ),
        )
    except ValueError as exc:
        raise ActiveConfigError(str(exc)) from exc


def _validated_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ActiveConfigError("gateway_base_url_invalid")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ActiveConfigError("gateway_base_url_invalid")
    if parsed.scheme == "http":
        try:
            is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            is_loopback = parsed.hostname.lower() == "localhost"
        if not is_loopback:
            raise ActiveConfigError("gateway_insecure_nonloopback_base_url")
    return value


def _mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    result = value.get(name)
    if not isinstance(result, Mapping):
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return result


def _string(value: Mapping[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result or len(result) > 512 or any(ord(char) < 0x20 for char in result):
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return result


def _optional_string(value: Mapping[str, Any], name: str, *, maximum: int) -> str:
    result = value.get(name, "")
    if not isinstance(result, str) or len(result) > maximum or any(ord(char) < 0x20 for char in result):
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return result


def _integer(value: Mapping[str, Any], name: str) -> int:
    result = value.get(name)
    if type(result) is not int:
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return result


def _bounded_integer(value: Mapping[str, Any], name: str, *, minimum: int, maximum: int) -> int:
    result = _integer(value, name)
    if not minimum <= result <= maximum:
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return result


def _port(value: Mapping[str, Any], name: str) -> int:
    return _bounded_integer(value, name, minimum=1024, maximum=65535)


def _bounded_number(value: Mapping[str, Any], name: str, *, minimum: float, maximum: float) -> float:
    result = value.get(name)
    if isinstance(result, bool) or not isinstance(result, (int, float)):
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    numeric = float(result)
    if not minimum <= numeric <= maximum:
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return numeric


def _optional_number(
    value: Mapping[str, Any],
    name: str,
    *,
    minimum: float,
    maximum: float,
) -> float | None:
    if value.get(name) is None:
        return None
    return _bounded_number(value, name, minimum=minimum, maximum=maximum)


def _boolean(value: Mapping[str, Any], name: str, *, default: bool) -> bool:
    result = value.get(name, default)
    if type(result) is not bool:
        raise ActiveConfigError(f"gateway_config_{name}_invalid")
    return result


def _require_fields(value: Mapping[str, Any], expected: set[str], error: str) -> None:
    if set(value) != expected:
        raise ActiveConfigError(error)
