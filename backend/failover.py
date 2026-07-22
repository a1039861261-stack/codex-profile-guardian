from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock, RLock
from typing import Any, Protocol
from urllib.parse import urlsplit
import uuid

from gateway.protocols.responses import normalize_protocol_compatibility


SCHEMA_VERSION = 1
SUPPORTED_ADAPTER = "openai-responses-v1"
MAX_DOCUMENT_BYTES = 1024 * 1024

DEFAULT_BREAKER_POLICY: dict[str, object] = {
    "failure_threshold": 3,
    "protocol_failure_threshold": 3,
    "error_rate_threshold": 0.5,
    "minimum_samples": 10,
    "window_size": 20,
    "recovery_success_threshold": 2,
    "base_cooldown_seconds": 30.0,
    "max_cooldown_seconds": 300.0,
    "jitter_ratio": 0.1,
}

DEFAULT_PROBE_POLICY: dict[str, object] = {
    "enabled": False,
    "mode": "models",
    "interval_seconds": 300.0,
    "timeout_seconds": 5.0,
    "allow_billable": False,
    "allow_action_required_auto_retest": False,
}

_GROUP_FIELDS = {
    "id",
    "name",
    "enabled",
    "primary_profile_id",
    "backup_profile_id",
    "allowed_models",
    "adapter_name",
    "breaker_policy",
    "probe_policy",
}
_STORED_GROUP_FIELDS = _GROUP_FIELDS | {"updated_revision"}
_CREATE_FIELDS = _GROUP_FIELDS - {"id"}
_PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_PUBLIC_FORBIDDEN_FIELDS = {
    "authorization",
    "base_url",
    "control_endpoint",
    "control_token",
    "executable_path",
    "fingerprint",
    "ingress_token",
    "raw_error",
    "request_body",
    "response_body",
    "secret_ref",
    "token_hash",
}

_PATH_LOCKS_GUARD = Lock()
_PATH_LOCKS: dict[Path, RLock] = {}

_ROUTE_STATE_LABELS = {
    "closed": "健康可用",
    "unknown": "尚未验证",
    "open_temporary": "临时熔断",
    "half_open": "恢复探测",
    "open_action_required": "需要处理",
    "disabled": "已停用",
}

_EVENT_PRESENTATION = {
    "fixture_loaded": ("预览已加载", "合成状态已就绪"),
    "fixture_scenario_changed": ("场景已切换", "合成状态已更新"),
    "config_prepared": ("配置已准备", "候选配置尚未生效"),
    "config_activated": ("配置已发布", "网关已切换到新 revision"),
    "config_activation_rolled_back": ("发布已回滚", "网关已恢复旧配置"),
    "route_retested": ("线路复测完成", "合成复测未产生网络请求"),
    "request_received": ("请求已进入网关", "正在选择可用线路"),
    "attempt_finished": ("线路尝试已结束", "已记录脱敏线路结果"),
    "commit_finished": ("响应提交已结束", "已记录本轮交付结果"),
    "request_cancelled": ("请求已取消", "客户端取消后未继续重放"),
    "breaker_transition": ("线路状态已变化", "熔断器状态已更新"),
    "models_probe_finished": ("线路复测已结束", "非计费模型目录探测已完成"),
    "gateway_started": ("后台网关已启动", "生产数据面正在运行"),
    "gateway_stopped": ("后台网关已停止", "生产数据面已停止接收请求"),
    "gateway_config_activated": ("配置已发布", "生产网关已切换到新 revision"),
    "gateway_config_aborted": ("候选配置已撤销", "当前活动配置未改变"),
}


class FailoverError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FailoverStoreError(FailoverError):
    pass


class FailoverValidationError(FailoverError):
    pass


class FailoverConflictError(FailoverError):
    pass


class FailoverNotFoundError(FailoverError):
    pass


class FailoverPublishError(FailoverError):
    pass


class FailoverActivationUncertain(FailoverPublishError):
    def __init__(self, code: str, receipt: "GatewayActivationReceipt") -> None:
        super().__init__(code)
        self.receipt = receipt


@dataclass(frozen=True, slots=True)
class PreparedGatewayConfig:
    revision: int
    group_id: str
    handle: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class GatewayActivationReceipt:
    previous_revision: int
    previous_group_id: str | None
    revision: int
    group_id: str
    handle: str = field(repr=False)
    previous_candidate: Mapping[str, object] | None = field(default=None, repr=False)
    activated_config_sha256: str = field(default="", repr=False)
    previous_config_sha256: str = field(default="", repr=False)
    process_instance_id: str = field(default="", repr=False)


class GatewayController(Protocol):
    def prepare(self, candidate: Mapping[str, object]) -> PreparedGatewayConfig: ...

    def activate(self, prepared: PreparedGatewayConfig) -> GatewayActivationReceipt: ...

    def rollback(self, receipt: GatewayActivationReceipt) -> GatewayActivationReceipt | None: ...

    def abort(self, prepared: PreparedGatewayConfig) -> None: ...

    def snapshot(self) -> Mapping[str, object]: ...

    def events(self) -> tuple[Mapping[str, object], ...]: ...

    def retest(self, group_id: str, route_role: str) -> Mapping[str, object]: ...

    def referenced_profile_ids(self) -> frozenset[str]: ...

    def provider_status(self) -> Mapping[str, object]: ...


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _path_lock(path: Path) -> RLock:
    resolved = path.resolve()
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(resolved, RLock())


@contextmanager
def _interprocess_file_lock(document_path: Path):
    lock_path = document_path.with_name(f".{document_path.name}.lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        stream = lock_path.open("a+b")
    except OSError as exc:
        raise FailoverStoreError("failover_store_lock_unavailable") from exc
    try:
        if os.name == "nt":
            import msvcrt

            if lock_path.stat().st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield
    except OSError as exc:
        raise FailoverStoreError("failover_store_lock_failed") from exc
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        stream.close()


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _uuid(value: object, code: str) -> str:
    if not isinstance(value, str):
        raise FailoverValidationError(code)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise FailoverValidationError(code) from exc
    canonical = str(parsed)
    if value != canonical:
        raise FailoverValidationError(code)
    return canonical


def _profile_id(value: object, code: str = "failover_profile_id_invalid") -> str:
    if not isinstance(value, str) or _PROFILE_ID.fullmatch(value) is None:
        raise FailoverValidationError(code)
    return value


def _text(value: object, code: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise FailoverValidationError(code)
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 0x20 for char in normalized):
        raise FailoverValidationError(code)
    return normalized


def _integer(value: object, code: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FailoverValidationError(code)
    return value


def _number(value: object, code: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FailoverValidationError(code)
    result = float(value)
    if not minimum <= result <= maximum:
        raise FailoverValidationError(code)
    return result


def _boolean(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise FailoverValidationError(code)
    return value


def _validate_base_url(value: object) -> tuple[str, str]:
    url = _text(value, "failover_profile_base_url_invalid", maximum=512).rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise FailoverValidationError("failover_profile_base_url_invalid")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname.lower() == "localhost"
        if not loopback:
            raise FailoverValidationError("failover_profile_insecure_base_url")
    return url, parsed.hostname.lower()


def _models(value: object, code: str = "failover_models_invalid") -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise FailoverValidationError(code)
    result: list[str] = []
    for item in value:
        model = _text(item, code, maximum=160)
        if model not in result:
            result.append(model)
    if not result:
        raise FailoverValidationError(code)
    return tuple(result)


def _adapter(profile: Mapping[str, object]) -> str:
    raw = profile.get("adapter_name")
    if raw is None and profile.get("wire_api") == "responses":
        raw = SUPPORTED_ADAPTER
    capabilities = profile.get("capabilities")
    if raw is None and isinstance(capabilities, Mapping):
        raw = capabilities.get("adapter_name")
    value = _text(raw, "failover_adapter_invalid", maximum=80)
    if value != SUPPORTED_ADAPTER:
        raise FailoverValidationError("failover_adapter_unsupported")
    return value


def _profile_models(profile: Mapping[str, object]) -> tuple[str, ...]:
    capabilities = profile.get("capabilities")
    if isinstance(capabilities, Mapping) and capabilities.get("models") is not None:
        return _models(capabilities.get("models"), "failover_profile_models_invalid")
    if profile.get("models") is not None:
        return _models(profile.get("models"), "failover_profile_models_invalid")
    model = profile.get("model")
    if isinstance(model, str) and model.strip():
        return (_text(model, "failover_profile_models_invalid", maximum=160),)
    raise FailoverValidationError("failover_profile_models_unavailable")


def _credential_hint(profile: Mapping[str, object]) -> str:
    value = profile.get("secret_hint", profile.get("credential_hint", ""))
    if not isinstance(value, str) or len(value) > 16 or any(ord(char) < 0x20 for char in value):
        return ""
    suffix = value.replace("*", "").replace("•", "").strip()
    if not suffix or len(suffix) > 8 or not suffix.isalnum():
        return ""
    return "••••" + suffix


def _credential_revision(profile: Mapping[str, object]) -> int:
    value = profile.get("credential_revision", 1)
    if type(value) is not int or value <= 0 or value > 2**63 - 1:
        raise FailoverValidationError("failover_profile_credential_revision_invalid")
    return value


def _protocol_compatibility(profile: Mapping[str, object]) -> dict[str, bool]:
    raw = profile.get("protocol_compatibility")
    capabilities = profile.get("capabilities")
    if raw is None and isinstance(capabilities, Mapping):
        raw = capabilities.get("protocol_compatibility")
    try:
        return normalize_protocol_compatibility(raw)
    except ValueError as exc:
        raise FailoverValidationError(
            "failover_profile_protocol_compatibility_invalid"
        ) from exc


def _normalize_profile(profile: Mapping[str, object]) -> dict[str, object]:
    profile_id = _profile_id(profile.get("id"))
    if profile.get("type") != "api":
        raise FailoverValidationError("failover_profile_must_be_api")
    name = _text(profile.get("name"), "failover_profile_name_invalid", maximum=80)
    if not profile.get("secret_file") and profile.get("has_secret") is not True:
        raise FailoverValidationError("failover_profile_credential_unavailable")
    base_url, base_host = _validate_base_url(profile.get("base_url"))
    return {
        "id": profile_id,
        "name": name,
        "base_url": base_url,
        "base_host": base_host,
        "adapter_name": _adapter(profile),
        "models": _profile_models(profile),
        "credential_hint": _credential_hint(profile),
        "credential_revision": _credential_revision(profile),
        "protocol_compatibility": _protocol_compatibility(profile),
    }


def _breaker_policy(value: object) -> dict[str, object]:
    if value is None:
        return dict(DEFAULT_BREAKER_POLICY)
    if not isinstance(value, Mapping) or set(value) != set(DEFAULT_BREAKER_POLICY):
        raise FailoverValidationError("failover_breaker_policy_invalid")
    threshold = _integer(value["failure_threshold"], "failover_breaker_policy_invalid", minimum=1, maximum=1000)
    protocol_threshold = _integer(
        value["protocol_failure_threshold"],
        "failover_breaker_policy_invalid",
        minimum=1,
        maximum=1000,
    )
    window_size = _integer(value["window_size"], "failover_breaker_policy_invalid", minimum=1, maximum=10000)
    minimum_samples = _integer(
        value["minimum_samples"],
        "failover_breaker_policy_invalid",
        minimum=1,
        maximum=window_size,
    )
    error_rate = value["error_rate_threshold"]
    if error_rate is not None:
        error_rate = _number(error_rate, "failover_breaker_policy_invalid", minimum=0.01, maximum=1.0)
    base_cooldown = _number(
        value["base_cooldown_seconds"],
        "failover_breaker_policy_invalid",
        minimum=0.1,
        maximum=86400.0,
    )
    max_cooldown = _number(
        value["max_cooldown_seconds"],
        "failover_breaker_policy_invalid",
        minimum=base_cooldown,
        maximum=86400.0,
    )
    return {
        "failure_threshold": threshold,
        "protocol_failure_threshold": protocol_threshold,
        "error_rate_threshold": error_rate,
        "minimum_samples": minimum_samples,
        "window_size": window_size,
        "recovery_success_threshold": _integer(
            value["recovery_success_threshold"],
            "failover_breaker_policy_invalid",
            minimum=1,
            maximum=1000,
        ),
        "base_cooldown_seconds": base_cooldown,
        "max_cooldown_seconds": max_cooldown,
        "jitter_ratio": _number(
            value["jitter_ratio"],
            "failover_breaker_policy_invalid",
            minimum=0.0,
            maximum=1.0,
        ),
    }


def _probe_policy(value: object) -> dict[str, object]:
    if value is None:
        return dict(DEFAULT_PROBE_POLICY)
    if not isinstance(value, Mapping) or set(value) != set(DEFAULT_PROBE_POLICY):
        raise FailoverValidationError("failover_probe_policy_invalid")
    enabled = _boolean(value["enabled"], "failover_probe_policy_invalid")
    mode = value["mode"]
    if mode not in {"models", "responses"}:
        raise FailoverValidationError("failover_probe_policy_invalid")
    allow_billable = _boolean(value["allow_billable"], "failover_probe_policy_invalid")
    if enabled and mode == "responses" and not allow_billable:
        raise FailoverValidationError("failover_billable_probe_opt_in_required")
    if mode == "models" and allow_billable:
        raise FailoverValidationError("failover_nonbillable_probe_invalid")
    return {
        "enabled": enabled,
        "mode": mode,
        "interval_seconds": _number(
            value["interval_seconds"],
            "failover_probe_policy_invalid",
            minimum=30.0,
            maximum=7 * 24 * 60 * 60,
        ),
        "timeout_seconds": _number(
            value["timeout_seconds"],
            "failover_probe_policy_invalid",
            minimum=0.1,
            maximum=60.0,
        ),
        "allow_billable": allow_billable,
        "allow_action_required_auto_retest": _boolean(
            value["allow_action_required_auto_retest"],
            "failover_probe_policy_invalid",
        ),
    }


def _validate_group_document(group: object) -> dict[str, object]:
    if not isinstance(group, Mapping) or set(group) != _STORED_GROUP_FIELDS:
        raise FailoverStoreError("failover_group_document_invalid")
    try:
        group_id = _uuid(group.get("id"), "failover_group_id_invalid")
        name = _text(group.get("name"), "failover_group_name_invalid", maximum=80)
        enabled = _boolean(group.get("enabled"), "failover_group_enabled_invalid")
        primary = _profile_id(group.get("primary_profile_id"))
        backup = _profile_id(group.get("backup_profile_id"))
        if primary == backup:
            raise FailoverValidationError("failover_routes_must_be_distinct")
        allowed_models = _models(group.get("allowed_models"))
        adapter_name = _text(group.get("adapter_name"), "failover_adapter_invalid", maximum=80)
        if adapter_name != SUPPORTED_ADAPTER:
            raise FailoverValidationError("failover_adapter_unsupported")
        breaker_policy = _breaker_policy(group.get("breaker_policy"))
        probe_policy = _probe_policy(group.get("probe_policy"))
        updated_revision = _integer(
            group.get("updated_revision"),
            "failover_group_revision_invalid",
            minimum=1,
            maximum=2**63 - 1,
        )
    except FailoverValidationError as exc:
        raise FailoverStoreError("failover_group_document_invalid") from exc
    return {
        "id": group_id,
        "name": name,
        "enabled": enabled,
        "primary_profile_id": primary,
        "backup_profile_id": backup,
        "allowed_models": list(allowed_models),
        "adapter_name": adapter_name,
        "breaker_policy": breaker_policy,
        "probe_policy": probe_policy,
        "updated_revision": updated_revision,
    }


def _validate_document(document: object) -> dict[str, object]:
    if not isinstance(document, Mapping) or set(document) != {
        "schema_version",
        "revision",
        "instance_id",
        "active_group_id",
        "groups",
    }:
        raise FailoverStoreError("failover_document_invalid")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise FailoverStoreError("failover_schema_unsupported")
    revision = document.get("revision")
    if type(revision) is not int or revision < 0:
        raise FailoverStoreError("failover_revision_invalid")
    try:
        instance_id = _uuid(document.get("instance_id"), "failover_instance_id_invalid")
    except FailoverValidationError as exc:
        raise FailoverStoreError("failover_instance_id_invalid") from exc
    groups_value = document.get("groups")
    if not isinstance(groups_value, list):
        raise FailoverStoreError("failover_groups_invalid")
    groups = [_validate_group_document(group) for group in groups_value]
    group_ids = [str(group["id"]) for group in groups]
    if len(group_ids) != len(set(group_ids)):
        raise FailoverStoreError("failover_group_id_duplicate")
    active_group_id = document.get("active_group_id")
    if active_group_id is not None:
        try:
            active_group_id = _uuid(active_group_id, "failover_active_group_invalid")
        except FailoverValidationError as exc:
            raise FailoverStoreError("failover_active_group_invalid") from exc
        if active_group_id not in set(group_ids):
            raise FailoverStoreError("failover_active_group_invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": revision,
        "instance_id": instance_id,
        "active_group_id": active_group_id,
        "groups": groups,
    }


def _public_snapshot_summary(snapshot: Mapping[str, object]) -> dict[str, object]:
    action = snapshot.get("required_action")
    carrier = snapshot.get("carrier") if snapshot.get("carrier") in {"primary", "backup"} else None
    if action == "check_primary":
        tone, headline, supporting = (
            "danger",
            "P1 需要人工处理",
            "P2 可继续承载，请检查 P1 的凭据、分组绑定或模型权限。",
        )
        alert = {
            "code": "guardian_route_action_required",
            "persistent": True,
            "route_role": "primary",
            "failure_category": "auth_rejected",
            "http_status": 401,
            "next_action": "请检查 P1 的 Key、分组绑定和模型权限。",
        }
    elif action == "repair_route":
        tone, headline, supporting = (
            "danger",
            "主备线路均不可用",
            "本轮已明确失败，原任务保持不变。",
        )
        alert = {
            "code": "guardian_all_routes_failed",
            "persistent": True,
            "route_role": "",
            "failure_category": "all_routes_failed",
            "http_status": None,
            "next_action": "修复任一线路后重新测试。",
        }
    elif carrier == "backup":
        tone, headline, supporting = (
            "warning",
            "已自动切换到 P2",
            "P1 正在冷却或恢复探测，后续新请求暂由 P2 承载。",
        )
        alert = None
    elif carrier == "primary":
        tone, headline, supporting = (
            "good",
            "主线路运行正常",
            "请求由 P1 承载，P2 保持待命。",
        )
        alert = None
    else:
        tone, headline, supporting = (
            "neutral",
            "线路状态尚未确定",
            "等待新的完整业务结果。",
        )
        alert = None
    return {
        "tone": tone,
        "headline": headline,
        "supporting": supporting,
        "required_action": action if action in {"none", "check_primary", "repair_route", "reload"} else "reload",
        "carrier": carrier,
        "carrier_basis": (
            "production_last_business_result"
            if snapshot.get("source") == "production"
            else "fixture_last_business_result"
        ),
        "alert": alert,
    }


def _public_event(value: Mapping[str, object]) -> dict[str, object]:
    event = value.get("event")
    event_name = event if isinstance(event, str) and event in _EVENT_PRESENTATION else "gateway_event"
    title, detail = _EVENT_PRESENTATION.get(
        event_name,
        ("网关状态更新", "已记录一条脱敏状态事件"),
    )
    event_id = value.get("event_id")
    if not isinstance(event_id, str) or not 1 <= len(event_id) <= 128 or re.fullmatch(r"[A-Za-z0-9_-]+", event_id) is None:
        event_id = hashlib.sha256(
            json.dumps(
                {
                    "event": event_name,
                    "timestamp": value.get("timestamp", ""),
                    "route_role": value.get("route_role", ""),
                },
                ensure_ascii=True,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:32]
    timestamp = value.get("timestamp")
    if not isinstance(timestamp, str) or len(timestamp) > 64 or any(ord(char) < 0x20 for char in timestamp):
        timestamp = ""
    route_role = value.get("route_role")
    if route_role not in {"primary", "backup", ""}:
        route_role = ""
    status = value.get("status")
    if status not in {
        "ready",
        "running",
        "success",
        "fixture_success",
        "stopped",
        "failed",
        "unknown",
        "closed",
        "open_temporary",
        "half_open",
        "open_action_required",
        "disabled",
        "completed",
        "delivered",
        "delivery_uncertain",
        "auth_rejected",
        "rate_limited",
        "upstream_5xx",
        "network_error",
    }:
        status = "unknown"
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "kind": "configuration" if event_name.startswith("config_") else "status",
        "event": event_name,
        "title": title,
        "detail": detail,
        "status": status,
        "route_role": route_role,
        "source": "production" if value.get("source") == "production" else "fixture",
    }


class AtomicFailoverDocumentStore:
    def __init__(self, path: str | Path, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> None:
        self.path = Path(path).resolve()
        if max_bytes <= 0:
            raise ValueError("failover_store_max_bytes_invalid")
        self.max_bytes = max_bytes
        self._lock = _path_lock(self.path)
        self.uncertain_path = self.path.with_name(f"{self.path.name}.state-uncertain.json")

    def initialize(self) -> dict[str, object]:
        with self._lock, _interprocess_file_lock(self.path):
            if self.path.exists():
                return self._load_locked()
            document: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "revision": 0,
                "instance_id": str(uuid.uuid4()),
                "active_group_id": None,
                "groups": [],
            }
            self._write_locked(document)
            return _json_clone(document)

    def load(self) -> dict[str, object]:
        with self._lock, _interprocess_file_lock(self.path):
            return self._load_locked()

    def save(self, document: Mapping[str, object], *, expected_revision: int) -> dict[str, object]:
        _integer(expected_revision, "failover_expected_revision_invalid", minimum=0, maximum=2**63 - 2)
        with self._lock, _interprocess_file_lock(self.path):
            current = self._load_locked()
            if current["revision"] != expected_revision:
                raise FailoverConflictError("failover_revision_conflict")
            normalized = _validate_document(document)
            if normalized["instance_id"] != current["instance_id"]:
                raise FailoverConflictError("failover_instance_id_immutable")
            if normalized["revision"] != expected_revision + 1:
                raise FailoverConflictError("failover_revision_must_increment")
            self._write_locked(normalized)
            return _json_clone(normalized)

    def save_compensation(
        self,
        document: Mapping[str, object],
        *,
        expected_revision: int,
        compensation_revision: int,
    ) -> dict[str, object]:
        _integer(expected_revision, "failover_expected_revision_invalid", minimum=0, maximum=2**63 - 3)
        if compensation_revision != expected_revision + 2:
            raise FailoverConflictError("failover_compensation_revision_invalid")
        with self._lock, _interprocess_file_lock(self.path):
            current = self._load_locked()
            if current["revision"] != expected_revision:
                raise FailoverConflictError("failover_revision_conflict")
            normalized = _validate_document(document)
            if normalized["instance_id"] != current["instance_id"]:
                raise FailoverConflictError("failover_instance_id_immutable")
            if normalized["revision"] != compensation_revision:
                raise FailoverConflictError("failover_compensation_revision_invalid")
            self._write_locked(normalized)
            return _json_clone(normalized)

    def assert_publish_allowed(self) -> None:
        if self.uncertain_path.exists():
            raise FailoverConflictError("failover_state_uncertain_locked")

    def mark_state_uncertain(self, code: str) -> None:
        safe_code = (
            code
            if isinstance(code, str)
            and re.fullmatch(r"[a-z0-9_]{1,96}", code) is not None
            else "failover_state_uncertain"
        )
        payload = (
            json.dumps(
                {
                    "schema_version": 1,
                    "state": "uncertain",
                    "code": safe_code,
                    "recorded_at": _utc_now(),
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        parent = self.uncertain_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        temporary = parent / f".{self.uncertain_path.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.uncertain_path)
            try:
                os.chmod(self.uncertain_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        except OSError as exc:
            raise FailoverStoreError("failover_state_uncertain_lock_failed") from exc
        finally:
            try:
                temporary.unlink()
            except OSError:
                pass

    def _load_locked(self) -> dict[str, object]:
        try:
            size = self.path.stat().st_size
            if size > self.max_bytes:
                raise FailoverStoreError("failover_document_too_large")
            payload = self.path.read_bytes()
        except FileNotFoundError as exc:
            raise FailoverStoreError("failover_document_missing") from exc
        except FailoverStoreError:
            raise
        except OSError as exc:
            raise FailoverStoreError("failover_document_read_failed") from exc
        if len(payload) > self.max_bytes:
            raise FailoverStoreError("failover_document_too_large")
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FailoverStoreError("failover_document_invalid") from exc
        return _validate_document(document)

    def _write_locked(self, document: Mapping[str, object]) -> None:
        normalized = _validate_document(document)
        try:
            payload = (
                json.dumps(
                    normalized,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise FailoverStoreError("failover_document_serialize_failed") from exc
        if len(payload) > self.max_bytes:
            raise FailoverStoreError("failover_document_too_large")
        parent = self.path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(parent, stat.S_IRWXU)
            except OSError:
                pass
        except OSError as exc:
            raise FailoverStoreError("failover_document_directory_failed") from exc
        temporary = parent / f".{self.path.name}.{uuid.uuid4().hex}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            try:
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            self._fsync_directory(parent)
        except OSError as exc:
            raise FailoverStoreError("failover_document_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)


_SCENARIOS: dict[str, dict[str, object]] = {
    "healthy": {
        "view_state": "ready",
        "tone": "good",
        "headline": "主线路运行正常",
        "supporting": "请求由 P1 承载，P2 保持待命。",
        "required_action": "none",
        "carrier": "primary",
        "routes": {
            "primary": {
                "state": "closed",
                "state_label": "健康可用",
                "tone": "good",
                "carrying": True,
                "last_result": "fixture_complete",
                "cooldown_seconds": None,
                "http_status": 200,
            },
            "backup": {
                "state": "closed",
                "state_label": "待命可用",
                "tone": "neutral",
                "carrying": False,
                "last_result": "fixture_probe_ready",
                "cooldown_seconds": None,
                "http_status": 200,
            },
        },
        "alert": None,
    },
    "degraded": {
        "view_state": "ready",
        "tone": "warning",
        "headline": "已自动切换到 P2",
        "supporting": "P1 因 429 暂停，将自动复测。",
        "required_action": "none",
        "carrier": "backup",
        "routes": {
            "primary": {
                "state": "open_temporary",
                "state_label": "临时熔断",
                "tone": "warning",
                "carrying": False,
                "last_result": "fixture_rate_limited",
                "cooldown_seconds": 24,
                "http_status": 429,
            },
            "backup": {
                "state": "closed",
                "state_label": "实际承载",
                "tone": "good",
                "carrying": True,
                "last_result": "fixture_complete",
                "cooldown_seconds": None,
                "http_status": 200,
            },
        },
        "alert": {
            "code": "guardian_fixture_failover_temporary",
            "persistent": False,
            "tone": "warning",
            "title": "临时故障转移",
            "next_action": "等待自动复测",
        },
    },
    "action": {
        "view_state": "ready",
        "tone": "danger",
        "headline": "P1 需要人工处理",
        "supporting": "P2 正在承载，请检查 P1 的凭据或模型权限。",
        "required_action": "check_primary",
        "carrier": "backup",
        "routes": {
            "primary": {
                "state": "open_action_required",
                "state_label": "凭据异常",
                "tone": "danger",
                "carrying": False,
                "last_result": "fixture_auth_rejected",
                "cooldown_seconds": None,
                "http_status": 401,
            },
            "backup": {
                "state": "closed",
                "state_label": "实际承载",
                "tone": "good",
                "carrying": True,
                "last_result": "fixture_complete",
                "cooldown_seconds": None,
                "http_status": 200,
            },
        },
        "alert": {
            "code": "guardian_fixture_route_action_required",
            "persistent": True,
            "tone": "danger",
            "title": "P1 需要人工处理",
            "next_action": "检查凭据、分组绑定和模型权限",
        },
    },
    "failed": {
        "view_state": "ready",
        "tone": "danger",
        "headline": "主备线路均不可用",
        "supporting": "本轮已明确失败，原任务保持不变。",
        "required_action": "repair_route",
        "carrier": None,
        "routes": {
            "primary": {
                "state": "open_temporary",
                "state_label": "连接失败",
                "tone": "danger",
                "carrying": False,
                "last_result": "fixture_transport_error",
                "cooldown_seconds": 30,
                "http_status": None,
            },
            "backup": {
                "state": "open_temporary",
                "state_label": "上游不可用",
                "tone": "danger",
                "carrying": False,
                "last_result": "fixture_upstream_5xx",
                "cooldown_seconds": 30,
                "http_status": 503,
            },
        },
        "alert": {
            "code": "guardian_fixture_all_routes_failed",
            "persistent": True,
            "tone": "danger",
            "title": "没有可承载线路",
            "next_action": "修复任一线路后重新测试",
        },
    },
    "loading": {
        "view_state": "loading",
        "tone": "neutral",
        "headline": "正在读取线路状态",
        "supporting": "请稍候。",
        "required_action": "none",
        "carrier": None,
        "routes": {},
        "alert": None,
    },
    "empty": {
        "view_state": "empty",
        "tone": "neutral",
        "headline": "还没有容灾组",
        "supporting": "可以从已保存的 API 档案创建。",
        "required_action": "create_group",
        "carrier": None,
        "routes": {},
        "alert": None,
    },
    "error": {
        "view_state": "error",
        "tone": "danger",
        "headline": "状态读取失败",
        "supporting": "无法读取合成线路状态。",
        "required_action": "reload",
        "carrier": None,
        "routes": {},
        "alert": {
            "code": "guardian_fixture_status_unavailable",
            "persistent": False,
            "tone": "danger",
            "title": "状态暂时不可用",
            "next_action": "重新加载",
        },
    },
}


class FixtureGatewayController:
    source = "fixture"

    def __init__(
        self,
        scenario: str = "healthy",
        *,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        if scenario not in _SCENARIOS:
            raise ValueError("fixture_scenario_invalid")
        self._scenario = scenario
        self._clock = clock
        self._prepared: dict[str, dict[str, object]] = {}
        self._active_revision = 0
        self._active_group_id: str | None = None
        self._active_candidate: dict[str, object] | None = None
        self._retired_profile_ids: set[str] = set()
        self._events: list[dict[str, object]] = []
        self._lock = RLock()
        self._fail_prepare = False
        self._fail_activate = False
        self._fail_after_activate = False
        self.call_log: list[str] = []
        self.network_calls = 0
        self._append_event("fixture_loaded", "ready", route_role="")

    @property
    def active_revision(self) -> int:
        with self._lock:
            return self._active_revision

    @property
    def active_group_id(self) -> str | None:
        with self._lock:
            return self._active_group_id

    def fail_next_prepare(self) -> None:
        with self._lock:
            self._fail_prepare = True

    def fail_next_activate(self) -> None:
        with self._lock:
            self._fail_activate = True

    def fail_next_activate_after_commit(self) -> None:
        with self._lock:
            self._fail_after_activate = True

    def set_scenario(self, scenario: str) -> None:
        if scenario not in _SCENARIOS:
            raise ValueError("fixture_scenario_invalid")
        with self._lock:
            self._scenario = scenario
            self._append_event("fixture_scenario_changed", "ready", route_role="")

    def prepare(self, candidate: Mapping[str, object]) -> PreparedGatewayConfig:
        with self._lock:
            self.call_log.append("prepare")
            if self._fail_prepare:
                self._fail_prepare = False
                raise FailoverPublishError("gateway_fixture_prepare_failed")
            revision = candidate.get("revision")
            group_id = candidate.get("group_id")
            if type(revision) is not int or revision <= self._active_revision:
                raise FailoverPublishError("gateway_fixture_revision_invalid")
            try:
                normalized_group_id = _uuid(group_id, "gateway_fixture_group_invalid")
            except FailoverValidationError as exc:
                raise FailoverPublishError("gateway_fixture_group_invalid") from exc
            handle = uuid.uuid4().hex
            self._prepared[handle] = _json_clone(dict(candidate))
            self._append_event("config_prepared", "ready", route_role="")
            return PreparedGatewayConfig(revision, normalized_group_id, handle)

    def activate(self, prepared: PreparedGatewayConfig) -> GatewayActivationReceipt:
        with self._lock:
            self.call_log.append("activate")
            candidate = self._prepared.get(prepared.handle)
            if candidate is None:
                raise FailoverPublishError("gateway_fixture_prepare_missing")
            if self._fail_activate:
                self._fail_activate = False
                raise FailoverPublishError("gateway_fixture_activate_failed")
            receipt = GatewayActivationReceipt(
                previous_revision=self._active_revision,
                previous_group_id=self._active_group_id,
                revision=prepared.revision,
                group_id=prepared.group_id,
                handle=uuid.uuid4().hex,
                previous_candidate=(
                    None
                    if self._active_candidate is None
                    else _json_clone(self._active_candidate)
                ),
            )
            self._retired_profile_ids.update(
                _candidate_profile_ids(self._active_candidate)
            )
            self._active_revision = prepared.revision
            self._active_group_id = prepared.group_id
            self._active_candidate = _json_clone(candidate)
            self._prepared.pop(prepared.handle, None)
            self._append_event("config_activated", "ready", route_role="")
            if self._fail_after_activate:
                self._fail_after_activate = False
                raise FailoverActivationUncertain(
                    "gateway_fixture_activate_result_uncertain",
                    receipt,
                )
            return receipt

    def rollback(self, receipt: GatewayActivationReceipt) -> None:
        with self._lock:
            self.call_log.append("rollback")
            if self._active_revision != receipt.revision or self._active_group_id != receipt.group_id:
                raise FailoverPublishError("gateway_fixture_rollback_conflict")
            self._retired_profile_ids.update(
                _candidate_profile_ids(self._active_candidate)
            )
            self._active_revision = receipt.previous_revision
            self._active_group_id = receipt.previous_group_id
            self._active_candidate = (
                None
                if receipt.previous_candidate is None
                else _json_clone(receipt.previous_candidate)
            )
            self._append_event("config_activation_rolled_back", "ready", route_role="")

    def abort(self, prepared: PreparedGatewayConfig) -> None:
        with self._lock:
            self.call_log.append("abort")
            self._prepared.pop(prepared.handle, None)

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            scenario = _json_clone(_SCENARIOS[self._scenario])
            scenario.update(
                {
                    "source": "fixture",
                    "stale": self._scenario == "error",
                    "collected_at": self._clock(),
                    "online": self._scenario not in {"error"},
                    "phase": "unavailable" if self._scenario == "error" else "running",
                    "config_revision": self._active_revision,
                    "active_group_id": self._active_group_id,
                }
            )
            return scenario

    def events(self) -> tuple[Mapping[str, object], ...]:
        with self._lock:
            return tuple(_json_clone(item) for item in reversed(self._events))

    def retest(self, group_id: str, route_role: str) -> Mapping[str, object]:
        normalized_group = _uuid(group_id, "failover_group_id_invalid")
        if route_role not in {"primary", "backup"}:
            raise FailoverValidationError("failover_route_role_invalid")
        with self._lock:
            self.call_log.append(f"retest:{route_role}")
            if self._active_group_id is not None and normalized_group != self._active_group_id:
                raise FailoverConflictError("failover_group_not_active")
            if route_role == "primary":
                self._scenario = "healthy"
            self._append_event("route_retested", "fixture_success", route_role=route_role)
            return self.snapshot()

    def referenced_profile_ids(self) -> frozenset[str]:
        with self._lock:
            result = set(self._retired_profile_ids)
            result.update(_candidate_profile_ids(self._active_candidate))
            for candidate in self._prepared.values():
                result.update(_candidate_profile_ids(candidate))
            return frozenset(result)

    def provider_status(self) -> Mapping[str, object]:
        with self._lock:
            ready = self._active_revision > 0 and self._active_group_id is not None
            return {
                "ok": ready,
                "phase": "running" if ready else "created",
                "host": "127.0.0.1",
                "data_port": 18766,
                "config_revision": self._active_revision,
                "instance_id": "fixture-gateway",
                "models_ready": ready,
            }

    def _append_event(self, event: str, status: str, *, route_role: str) -> None:
        self._events.append(
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": self._clock(),
                "event": event,
                "status": status,
                "route_role": route_role,
                "source": "fixture",
            }
        )


ProfileSource = Callable[[], Iterable[Mapping[str, object]]]
ProviderStatus = Callable[[], Mapping[str, object]]


class FailoverManagementService:
    def __init__(
        self,
        store: AtomicFailoverDocumentStore,
        profiles: ProfileSource | Iterable[Mapping[str, object]],
        controller: GatewayController,
        *,
        clock: Callable[[], str] = _utc_now,
        provider_status: ProviderStatus | None = None,
    ) -> None:
        self.store = store
        if callable(profiles):
            self._profile_source = profiles
        else:
            frozen_profiles = tuple(deepcopy(dict(item)) for item in profiles)
            self._profile_source = lambda: frozen_profiles
        self.controller = controller
        self._provider_status = provider_status
        self._clock = clock
        self._lock = RLock()
        self.store.initialize()

    def list_groups(self) -> dict[str, object]:
        document = self.store.load()
        snapshot = dict(self.controller.snapshot())
        result = {
            "schema_version": SCHEMA_VERSION,
            "revision": document["revision"],
            "active_group_id": document["active_group_id"],
            "groups": [
                _public_group(
                    group,
                    document_revision=int(document["revision"]),
                    gateway_group_id=snapshot.get("active_group_id"),
                    gateway_revision=snapshot.get("config_revision"),
                )
                for group in document["groups"]
            ],
        }
        _ensure_public_safe(result)
        return result

    def create_group(self, values: Mapping[str, object], *, expected_revision: int) -> dict[str, object]:
        with self._lock:
            document = self._load_expected(expected_revision)
            if not isinstance(values, Mapping) or set(values) - _CREATE_FIELDS:
                raise FailoverValidationError("failover_group_payload_invalid")
            group = self._normalize_group(values, group_id=str(uuid.uuid4()))
            next_document = _json_clone(document)
            next_document["revision"] = expected_revision + 1
            group["updated_revision"] = next_document["revision"]
            next_document["groups"].append(group)
            saved = self.store.save(next_document, expected_revision=expected_revision)
            return self._mutation_result(saved, group["id"])

    def update_group(
        self,
        group_id: str,
        values: Mapping[str, object],
        *,
        expected_revision: int,
    ) -> dict[str, object]:
        normalized_id = _uuid(group_id, "failover_group_id_invalid")
        with self._lock:
            document = self._load_expected(expected_revision)
            current = _find_group(document, normalized_id)
            if not isinstance(values, Mapping) or set(values) - _GROUP_FIELDS:
                raise FailoverValidationError("failover_group_payload_invalid")
            supplied_id = values.get("id")
            if supplied_id is not None and supplied_id != normalized_id:
                raise FailoverConflictError("failover_group_id_immutable")
            merged = {key: value for key, value in current.items() if key != "updated_revision"}
            merged.update({key: value for key, value in values.items() if key != "id"})
            normalized = self._normalize_group(merged, group_id=normalized_id)
            if (
                document["active_group_id"] == normalized_id
                and current.get("enabled") is True
                and normalized.get("enabled") is False
            ):
                raise FailoverConflictError("failover_active_group_disable_forbidden")
            current_content = {
                key: value for key, value in current.items() if key != "updated_revision"
            }
            if normalized == current_content:
                return self._mutation_result(document, normalized_id)
            next_document = _json_clone(document)
            next_document["revision"] = expected_revision + 1
            normalized["updated_revision"] = next_document["revision"]
            next_document["groups"] = [
                normalized if group["id"] == normalized_id else group
                for group in next_document["groups"]
            ]
            saved = self.store.save(next_document, expected_revision=expected_revision)
            return self._mutation_result(saved, normalized_id)

    def delete_group(self, group_id: str, *, expected_revision: int) -> dict[str, object]:
        normalized_id = _uuid(group_id, "failover_group_id_invalid")
        with self._lock:
            document = self._load_expected(expected_revision)
            _find_group(document, normalized_id)
            if document["active_group_id"] == normalized_id:
                raise FailoverConflictError("failover_active_group_delete_forbidden")
            next_document = _json_clone(document)
            next_document["revision"] = expected_revision + 1
            next_document["groups"] = [
                group for group in next_document["groups"] if group["id"] != normalized_id
            ]
            saved = self.store.save(next_document, expected_revision=expected_revision)
            overview = self.overview()
            result = {
                "schema_version": SCHEMA_VERSION,
                "revision": saved["revision"],
                "active_group_id": saved["active_group_id"],
                "deleted_group_id": normalized_id,
                "overview": overview,
            }
            _ensure_public_safe(result)
            return result

    def publish_group(self, group_id: str, *, expected_revision: int) -> dict[str, object]:
        normalized_id = _uuid(group_id, "failover_group_id_invalid")
        with self._lock:
            self.store.assert_publish_allowed()
            document = self._load_expected(expected_revision)
            group = _find_group(document, normalized_id)
            if not group["enabled"]:
                raise FailoverConflictError("failover_group_disabled")
            normalized = self._normalize_group(group, group_id=normalized_id)
            next_revision = expected_revision + 1
            candidate = self._materialize_candidate(document, normalized, revision=next_revision)
            prepared: PreparedGatewayConfig | None = None
            receipt: GatewayActivationReceipt | None = None
            try:
                prepared = self.controller.prepare(candidate)
                receipt = self.controller.activate(prepared)
                next_document = _json_clone(document)
                next_document["revision"] = next_revision
                next_document["active_group_id"] = normalized_id
                saved = self.store.save(next_document, expected_revision=expected_revision)
            except Exception as exc:
                if receipt is None and isinstance(exc, FailoverActivationUncertain):
                    receipt = exc.receipt
                if receipt is not None:
                    try:
                        compensation = self.controller.rollback(receipt)
                    except Exception as rollback_exc:
                        self.store.mark_state_uncertain("failover_compensation_failed")
                        raise FailoverPublishError("failover_publish_state_uncertain") from rollback_exc
                    if compensation is not None:
                        compensated_document = _json_clone(document)
                        compensated_document["revision"] = compensation.revision
                        try:
                            saved = self.store.save_compensation(
                                compensated_document,
                                expected_revision=expected_revision,
                                compensation_revision=compensation.revision,
                            )
                        except Exception as compensation_save_exc:
                            self.store.mark_state_uncertain(
                                "failover_compensation_document_sync_failed"
                            )
                            raise FailoverPublishError("failover_publish_state_uncertain") from compensation_save_exc
                        raise FailoverPublishError("failover_publish_compensated") from exc
                elif prepared is not None:
                    try:
                        self.controller.abort(prepared)
                    except Exception as abort_exc:
                        self.store.mark_state_uncertain("failover_abort_failed")
                        raise FailoverPublishError("failover_publish_state_uncertain") from abort_exc
                if isinstance(exc, FailoverError):
                    raise
                raise FailoverPublishError("failover_publish_failed") from exc
            overview = self.overview(normalized_id)
            result = {
                "schema_version": SCHEMA_VERSION,
                "revision": saved["revision"],
                "active_group_id": normalized_id,
                "published": True,
                "source": getattr(self.controller, "source", "fixture"),
                "overview": overview,
            }
            _ensure_public_safe(result)
            return result

    def overview(self, group_id: str | None = None) -> dict[str, object]:
        with self._lock:
            document = self.store.load()
            profiles = self._public_profile_options()
            snapshot = dict(self.controller.snapshot())
            view_state = str(snapshot.get("view_state", "error"))
            selected_group = None
            if group_id:
                selected_group = _find_group(
                    document,
                    _uuid(group_id, "failover_group_id_invalid"),
                )
            elif document["active_group_id"] is not None:
                selected_group = _find_group(document, str(document["active_group_id"]))
            elif document["groups"]:
                selected_group = document["groups"][0]
            if view_state == "empty":
                selected_group = None
            selected_snapshot = snapshot
            if (
                selected_group is not None
                and (
                    snapshot.get("active_group_id") != selected_group.get("id")
                    or not isinstance(snapshot.get("config_revision"), int)
                    or int(snapshot["config_revision"])
                    < int(selected_group["updated_revision"])
                )
            ):
                selected_snapshot = {
                    **snapshot,
                    "view_state": "ready",
                    "carrier": None,
                    "required_action": "none",
                    "routes": {},
                    "alert": None,
                }
            group_public = None
            if selected_group is not None:
                group_public = self._public_group_overview(
                    selected_group,
                    selected_snapshot,
                    document_revision=int(document["revision"]),
                )
            gateway_revision = snapshot.get("config_revision")
            gateway_group_id = snapshot.get("active_group_id")
            group_summaries = [
                _public_group(
                    group,
                    document_revision=int(document["revision"]),
                    gateway_group_id=gateway_group_id,
                    gateway_revision=gateway_revision,
                )
                for group in document["groups"]
            ]
            provider = {
                "provider_id": "guardian_gateway",
                "status": "direct",
                "gateway_revision": None,
                "activated_at": None,
                "restored_at": None,
            }
            if self._provider_status is not None:
                try:
                    projected = dict(self._provider_status())
                    if projected.get("provider_id") == "guardian_gateway" and projected.get("status") in {
                        "direct",
                        "active",
                        "restored",
                    }:
                        provider.update(projected)
                except Exception:
                    pass
            provider_active = provider["status"] == "active"
            result: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "source": (
                    "production" if snapshot.get("source") == "production" else "fixture"
                ),
                "stale": bool(snapshot.get("stale", False)),
                "collected_at": self._clock(),
                "view_state": view_state,
                "revision": document["revision"],
                "active_group_id": document["active_group_id"],
                "selected_group_id": None if selected_group is None else selected_group["id"],
                "profile_options": profiles,
                "groups": group_summaries,
                "group": group_public,
                "summary": _public_snapshot_summary(selected_snapshot),
                "capabilities": {
                    "manage_groups": True,
                    "publish_config": True,
                    "publish_target": (
                        "production" if snapshot.get("source") == "production" else "fixture"
                    ),
                    "retest_routes": True,
                    "activate_provider": bool(
                        document["active_group_id"] is not None
                        and snapshot.get("online") is True
                        and not provider_active
                    ),
                    "restore_direct": provider_active,
                },
                "provider": {
                    "mode": (
                        "production" if snapshot.get("source") == "production" else "fixture"
                    ),
                    "configured": provider_active,
                    "fixed_gateway_provider": provider_active,
                    "status": provider["status"],
                    "provider_id": "guardian_gateway",
                    "activation_state": (
                        "已启用" if provider_active else "直连模式"
                    ),
                    "gateway_revision": provider.get("gateway_revision"),
                    "activated_at": provider.get("activated_at"),
                    "restored_at": provider.get("restored_at"),
                },
                "gateway": {
                    "source": (
                        "production" if snapshot.get("source") == "production" else "fixture"
                    ),
                    "online": bool(snapshot.get("online", False)),
                    "phase": snapshot.get("phase", "unavailable"),
                    "state": (
                        (
                            "production_running"
                            if snapshot.get("source") == "production"
                            else "fixture_running"
                        )
                        if snapshot.get("phase") == "running"
                        else (
                            "production_unavailable"
                            if snapshot.get("source") == "production"
                            else "fixture_unavailable"
                        )
                    ),
                    "version": snapshot.get("version", "1.7.0-fixture"),
                    "config_revision": gateway_revision,
                    "active_group_id": gateway_group_id,
                    "configuration_drift": (
                        gateway_group_id != document["active_group_id"]
                        or (
                            document["active_group_id"] is not None
                            and (
                                not isinstance(gateway_revision, int)
                                or gateway_revision
                                < int(
                                    _find_group(
                                        document,
                                        str(document["active_group_id"]),
                                    )["updated_revision"]
                                )
                            )
                        )
                    ),
                },
            }
            _ensure_public_safe(result)
            return result

    def list_events(
        self,
        *,
        group_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, object]:
        if group_id:
            _find_group(
                self.store.load(),
                _uuid(group_id, "failover_group_id_invalid"),
            )
        offset_value = _integer(offset, "failover_event_offset_invalid", minimum=0, maximum=2**31 - 1)
        limit_value = _integer(limit, "failover_event_limit_invalid", minimum=1, maximum=100)
        events = tuple(self.controller.events())
        items = [
            _public_event(item)
            for item in events[offset_value : offset_value + limit_value]
            if isinstance(item, Mapping)
        ]
        next_offset = offset_value + len(items)
        has_more = next_offset < len(events)
        result: dict[str, object] = {
            "source": getattr(self.controller, "source", "fixture"),
            "stale": False,
            "collected_at": self._clock(),
            "offset": offset_value,
            "limit": limit_value,
            "total": len(events),
            "next_offset": next_offset if has_more else None,
            "items": items,
            "page": {
                "offset": offset_value,
                "limit": limit_value,
                "has_more": has_more,
            },
        }
        _ensure_public_safe(result)
        return result

    def retest_route(
        self,
        group_id: str,
        route_role: str,
        *,
        expected_revision: int,
    ) -> dict[str, object]:
        normalized_id = _uuid(group_id, "failover_group_id_invalid")
        with self._lock:
            document = self._load_expected(expected_revision)
            _find_group(document, normalized_id)
            self.controller.retest(normalized_id, route_role)
            overview = self.overview(normalized_id)
            return {
                **overview,
                "tested_role": route_role,
                "overview": overview,
            }

    def referenced_profile_ids(self) -> frozenset[str]:
        document = self.store.load()
        result = {
            str(group[field])
            for group in document["groups"]
            for field in ("primary_profile_id", "backup_profile_id")
        }
        controller_refs = getattr(self.controller, "referenced_profile_ids", None)
        if callable(controller_refs):
            result.update(controller_refs())
        return frozenset(result)

    def _load_expected(self, expected_revision: int) -> dict[str, object]:
        _integer(expected_revision, "failover_expected_revision_invalid", minimum=0, maximum=2**63 - 2)
        document = self.store.load()
        if document["revision"] != expected_revision:
            raise FailoverConflictError("failover_revision_conflict")
        return document

    def _raw_profiles(self) -> tuple[Mapping[str, object], ...]:
        try:
            values = tuple(self._profile_source())
        except Exception as exc:
            raise FailoverValidationError("failover_profiles_unavailable") from exc
        if not all(isinstance(item, Mapping) for item in values):
            raise FailoverValidationError("failover_profiles_invalid")
        return values

    def _profiles_by_id(self) -> dict[str, Mapping[str, object]]:
        result: dict[str, Mapping[str, object]] = {}
        for profile in self._raw_profiles():
            profile_id = profile.get("id")
            if isinstance(profile_id, str):
                result[profile_id] = profile
        return result

    def _resolve_api_profile(self, profile_id: str) -> dict[str, object]:
        raw = self._profiles_by_id().get(profile_id)
        if raw is None:
            raise FailoverNotFoundError("failover_profile_not_found")
        return _normalize_profile(raw)

    def _normalize_group(self, values: Mapping[str, object], *, group_id: str) -> dict[str, object]:
        if set(values) - _STORED_GROUP_FIELDS:
            raise FailoverValidationError("failover_group_payload_invalid")
        primary_id = _profile_id(values.get("primary_profile_id"))
        backup_id = _profile_id(values.get("backup_profile_id"))
        if primary_id == backup_id:
            raise FailoverValidationError("failover_routes_must_be_distinct")
        primary = self._resolve_api_profile(primary_id)
        backup = self._resolve_api_profile(backup_id)
        if primary["adapter_name"] != backup["adapter_name"]:
            raise FailoverValidationError("failover_route_adapters_must_match")
        adapter_name = values.get("adapter_name", primary["adapter_name"])
        if adapter_name != primary["adapter_name"] or adapter_name != SUPPORTED_ADAPTER:
            raise FailoverValidationError("failover_adapter_unsupported")
        intersection = tuple(
            model for model in primary["models"] if model in set(backup["models"])
        )
        if not intersection:
            raise FailoverValidationError("failover_model_intersection_empty")
        requested = values.get("allowed_models")
        allowed_models = intersection if requested is None else _models(requested)
        if any(model not in intersection for model in allowed_models):
            raise FailoverValidationError("failover_model_not_in_intersection")
        return {
            "id": _uuid(group_id, "failover_group_id_invalid"),
            "name": _text(values.get("name"), "failover_group_name_invalid", maximum=80),
            "enabled": _boolean(values.get("enabled", True), "failover_group_enabled_invalid"),
            "primary_profile_id": primary_id,
            "backup_profile_id": backup_id,
            "allowed_models": list(allowed_models),
            "adapter_name": SUPPORTED_ADAPTER,
            "breaker_policy": _breaker_policy(values.get("breaker_policy")),
            "probe_policy": _probe_policy(values.get("probe_policy")),
        }

    def _materialize_candidate(
        self,
        document: Mapping[str, object],
        group: Mapping[str, object],
        *,
        revision: int,
    ) -> dict[str, object]:
        primary = self._resolve_api_profile(str(group["primary_profile_id"]))
        backup = self._resolve_api_profile(str(group["backup_profile_id"]))
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": revision,
            "instance_id": document["instance_id"],
            "group_id": group["id"],
            "allowed_models": list(group["allowed_models"]),
            "adapter_name": group["adapter_name"],
            "primary": {
                "profile_id": primary["id"],
                "base_url": primary["base_url"],
                "credential_revision": primary["credential_revision"],
                "protocol_compatibility": dict(primary["protocol_compatibility"]),
            },
            "backup": {
                "profile_id": backup["id"],
                "base_url": backup["base_url"],
                "credential_revision": backup["credential_revision"],
                "protocol_compatibility": dict(backup["protocol_compatibility"]),
            },
            "breaker_policy": dict(group["breaker_policy"]),
            "probe_policy": dict(group["probe_policy"]),
        }

    def _public_profile_options(self) -> list[dict[str, object]]:
        options: list[dict[str, object]] = []
        for raw in self._raw_profiles():
            if raw.get("type") != "api":
                continue
            try:
                profile = _normalize_profile(raw)
            except FailoverValidationError:
                profile_id = raw.get("id")
                name = raw.get("name")
                if not isinstance(profile_id, str) or _PROFILE_ID.fullmatch(profile_id) is None:
                    continue
                options.append(
                    {
                        "id": profile_id,
                        "name": name if isinstance(name, str) and name else "不可用 API 档案",
                        "eligible": False,
                        "reason": "profile_validation_failed",
                        "base_host": "",
                        "credential_hint": "",
                        "key_suffix": "",
                        "adapter_name": "",
                        "models": [],
                        "model": "",
                        "protocol_compatibility": {},
                    }
                )
                continue
            options.append(
                {
                    "id": profile["id"],
                    "name": profile["name"],
                    "eligible": True,
                    "reason": None,
                    "base_host": profile["base_host"],
                    "credential_hint": profile["credential_hint"],
                    "key_suffix": str(profile["credential_hint"]).replace("•", ""),
                    "adapter_name": profile["adapter_name"],
                    "models": list(profile["models"]),
                    "model": profile["models"][0],
                    "protocol_compatibility": dict(
                        profile["protocol_compatibility"]
                    ),
                }
            )
        return options

    def _public_group_overview(
        self,
        group: Mapping[str, object],
        snapshot: Mapping[str, object],
        *,
        document_revision: int,
    ) -> dict[str, object]:
        primary = self._resolve_api_profile(str(group["primary_profile_id"]))
        backup = self._resolve_api_profile(str(group["backup_profile_id"]))
        route_states = snapshot.get("routes")
        if not isinstance(route_states, Mapping):
            route_states = {}
        routes = []
        for role, label, profile in (
            ("primary", "P1", primary),
            ("backup", "P2", backup),
        ):
            state = route_states.get(role, {})
            if not isinstance(state, Mapping):
                state = {}
            http_status = state.get("http_status")
            status_category = state.get("last_status_category")
            if state.get("action_required"):
                category = "auth_rejected"
            elif http_status == 429:
                category = "rate_limited"
            elif status_category == "4xx":
                category = "upstream_http_error"
            elif isinstance(http_status, int) and http_status >= 500:
                category = "upstream_5xx"
            elif status_category == "5xx":
                category = "upstream_5xx"
            elif state.get("carrying"):
                category = "success"
            else:
                category = "unknown"
            route_state = str(state.get("state", "unknown"))
            route_tone = state.get("tone")
            if route_tone not in {"good", "warning", "danger", "neutral"}:
                route_tone = (
                    "good"
                    if route_state == "closed"
                    else "warning"
                    if route_state in {
                        "open_temporary",
                        "half_open",
                        "open_action_required",
                    }
                    else "neutral"
                )
            routes.append(
                {
                    "role": role,
                    "label": label,
                    "profile_id": profile["id"],
                    "name": profile["name"],
                    "profile_name": profile["name"],
                    "base_host": profile["base_host"],
                    "credential_hint": profile["credential_hint"],
                    "key_suffix": str(profile["credential_hint"]).replace("•", ""),
                    "adapter_name": profile["adapter_name"],
                    "models": list(profile["models"]),
                    "model": group["allowed_models"][0],
                    "state": route_state,
                    "breaker_state": route_state,
                    "state_label": _ROUTE_STATE_LABELS.get(
                        str(state.get("state", "unknown")),
                        "尚未验证",
                    ),
                    "tone": route_tone,
                    "carrying": bool(state.get("carrying", False)),
                    "last_result": state.get("last_result", "fixture_unknown"),
                    "cooldown_seconds": state.get("cooldown_seconds"),
                    "http_status": state.get("http_status"),
                }
            )
            routes[-1]["last_result"] = {
                "category": category,
                "http_status": http_status,
                "signal": "business",
                "at": snapshot.get("collected_at", self._clock()),
                "detail": _ROUTE_STATE_LABELS.get(
                    str(state.get("state", "unknown")),
                    "尚未验证",
                ),
            }
        primary_models = set(primary["models"])
        backup_models = set(backup["models"])
        carrier = snapshot.get("carrier")
        required_action = snapshot.get("required_action")
        if snapshot.get("view_state") != "ready":
            overall_state = "unknown"
        elif required_action == "check_primary":
            overall_state = "action_required"
        elif carrier == "backup":
            overall_state = "degraded"
        elif carrier == "primary":
            overall_state = "healthy"
        elif required_action == "repair_route":
            overall_state = "unavailable"
        else:
            overall_state = "ready"
        public_summary = _public_snapshot_summary(snapshot)
        alert = public_summary.get("alert")
        return {
            **_public_group(
                group,
                document_revision=document_revision,
                gateway_group_id=snapshot.get("active_group_id"),
                gateway_revision=snapshot.get("config_revision"),
            ),
            "routes": routes,
            "overall_state": overall_state,
            "current_carrier": carrier,
            "requires_action": required_action in {"check_primary", "repair_route"},
            "alerts": [dict(alert)] if isinstance(alert, Mapping) else [],
            "capabilities": {
                "adapter_name": group["adapter_name"],
                "model_intersection": sorted(primary_models & backup_models),
                "allowed_models": list(group["allowed_models"]),
                "state_compatibility": "fixture_unknown",
            },
        }

    def _mutation_result(self, document: Mapping[str, object], group_id: object) -> dict[str, object]:
        group = _find_group(document, str(group_id))
        overview = self.overview(str(group_id))
        result = {
            "schema_version": SCHEMA_VERSION,
            "revision": document["revision"],
            "active_group_id": document["active_group_id"],
            "group": _public_group(group),
            "overview": overview,
        }
        _ensure_public_safe(result)
        return result


def _find_group(document: Mapping[str, object], group_id: str) -> dict[str, object]:
    groups = document.get("groups", [])
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, dict) and group.get("id") == group_id:
                return group
    raise FailoverNotFoundError("failover_group_not_found")


def _candidate_profile_ids(candidate: Mapping[str, object] | None) -> set[str]:
    if not isinstance(candidate, Mapping):
        return set()
    result: set[str] = set()
    for role in ("primary", "backup"):
        route = candidate.get(role)
        if isinstance(route, Mapping):
            profile_id = route.get("profile_id")
            if isinstance(profile_id, str) and _PROFILE_ID.fullmatch(profile_id):
                result.add(profile_id)
    return result


def _public_group(
    group: Mapping[str, object],
    *,
    document_revision: int | None = None,
    gateway_group_id: object = None,
    gateway_revision: object = None,
) -> dict[str, object]:
    result = {
        "id": group["id"],
        "name": group["name"],
        "enabled": group["enabled"],
        "primary_profile_id": group["primary_profile_id"],
        "backup_profile_id": group["backup_profile_id"],
        "allowed_models": list(group["allowed_models"]),
        "adapter_name": group["adapter_name"],
        "breaker_policy": dict(group["breaker_policy"]),
        "probe_policy": dict(group["probe_policy"]),
    }
    if document_revision is not None:
        applied_revision = (
            gateway_revision
            if gateway_group_id == group["id"] and type(gateway_revision) is int
            else None
        )
        updated_revision = int(group.get("updated_revision", document_revision))
        result.update(
            {
                "revision": document_revision,
                "applied_revision": applied_revision,
                "publication_state": (
                    "applied"
                    if isinstance(applied_revision, int)
                    and applied_revision >= updated_revision
                    else "draft"
                ),
            }
        )
    return result


def _ensure_public_safe(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str) or key.lower() in _PUBLIC_FORBIDDEN_FIELDS:
                raise RuntimeError("failover_public_contract_violation")
            _ensure_public_safe(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _ensure_public_safe(nested)
        return
    if isinstance(value, str):
        lowered = value.lower()
        if (
            "://" in lowered
            or "bearer " in lowered
            or "authorization:" in lowered
            or "secret_ref" in lowered
            or "fingerprint" in lowered
        ):
            raise RuntimeError("failover_public_contract_violation")


__all__ = [
    "AtomicFailoverDocumentStore",
    "FailoverConflictError",
    "FailoverError",
    "FailoverManagementService",
    "FailoverNotFoundError",
    "FailoverPublishError",
    "FailoverStoreError",
    "FailoverValidationError",
    "FixtureGatewayController",
    "GatewayActivationReceipt",
    "GatewayController",
    "PreparedGatewayConfig",
]
