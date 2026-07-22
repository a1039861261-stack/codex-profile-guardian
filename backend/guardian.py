from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
import uuid

from .claude_desktop import ClaudeDesktopError, ClaudeDesktopIntegration
from .failover_diagnostics import (
    DiagnosticBundle,
    DiagnosticBundleError,
    MAX_EVENTS as MAX_DIAGNOSTIC_EVENTS,
    build_diagnostic_bundle,
)
from .gateway_controller import ProductionGatewayController
from .provider_activation import ProviderActivationCoordinator, ProviderActivationError
from .remote_gateway_status import (
    RemoteGatewayStatusCollector,
    RemoteGatewayStatusService,
)
from .remote_sync import discover_remote_hosts, sync_api_profile_to_remotes, sync_official_to_remotes
from .updater import GitHubReleaseUpdater, UpdateError
from .failover import (
    AtomicFailoverDocumentStore,
    FailoverManagementService,
    FixtureGatewayController,
    GatewayController,
)
from gateway.protocols.responses import normalize_protocol_compatibility


APP_NAME = "Codex Profile Guardian"
APP_VERSION = "1.9.1"
SCHEMA_VERSION = 1
MANAGED_START = "# BEGIN CODEX PROFILE GUARDIAN MANAGED"
MANAGED_END = "# END CODEX PROFILE GUARDIAN MANAGED"


class GuardianError(RuntimeError):
    pass


class GuardianDiagnosticError(GuardianError):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[DATA_BLOB, Any]:
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def dpapi_protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise GuardianError("DPAPI 仅支持 Windows。")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, keepalive = _blob(data)
    out_blob = DATA_BLOB()
    description = APP_NAME
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob), description, None, None, None, 0x01, ctypes.byref(out_blob)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)
        del keepalive


def dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise GuardianError("DPAPI 仅支持 Windows。")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, keepalive = _blob(data)
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0x01, ctypes.byref(out_blob)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)
        del keepalive


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    temp.write_bytes(data)
    os.replace(temp, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )


def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def loads_json_line(line: str) -> Any:
    return json.loads(line.lstrip("\ufeff"))


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def update_top_level_toml(text: str, values: dict[str, str | None]) -> str:
    """Update only root TOML keys and preserve every app-managed table verbatim."""
    lines = text.lstrip("\ufeff").splitlines()
    first_table = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(r"^\s*\[\[?[^]]+\]\]?\s*(?:#.*)?$", line)
        ),
        len(lines),
    )
    root_lines = lines[:first_table]
    table_lines = lines[first_table:]
    emitted: set[str] = set()
    updated_root: list[str] = []
    for line in root_lines:
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*=", line)
        key = match.group(1) if match else None
        if key not in values:
            updated_root.append(line)
            continue
        if key not in emitted and values[key] is not None:
            updated_root.append(f"{key} = {toml_string(str(values[key]))}")
        emitted.add(str(key))
    for key, value in values.items():
        if key not in emitted and value is not None:
            updated_root.append(f"{key} = {toml_string(value)}")
    if table_lines and updated_root and updated_root[-1].strip():
        updated_root.append("")
    result = "\n".join(updated_root + table_lines).rstrip() + "\n"
    try:
        tomllib.loads(result)
    except tomllib.TOMLDecodeError as exc:
        raise GuardianError(f"Codex config.toml 校验失败：{exc}") from exc
    return result


def safe_provider_id(profile_id: str) -> str:
    return "guardian_" + re.sub(r"[^a-z0-9_]", "", profile_id.lower())[:12]


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or token.count(".") != 2:
        return {}
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        value = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return {}


def official_auth_metadata(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuardianError("官方登录凭据不是有效的 auth.json。") from exc
    if not isinstance(value, dict):
        raise GuardianError("官方登录凭据格式无效。")
    tokens = value.get("tokens")
    if not isinstance(tokens, dict):
        raise GuardianError("auth.json 缺少官方账号 tokens。")
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise GuardianError("auth.json 缺少 access_token，请先重新登录 Codex。")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise GuardianError("auth.json 缺少 refresh_token，请先重新登录 Codex。")
    claims = _decode_jwt_claims(access_token)
    identity = (
        tokens.get("account_id")
        or claims.get("chatgpt_account_id")
        or claims.get("sub")
        or _decode_jwt_claims(str(tokens.get("id_token") or "")).get("sub")
    )
    if not identity:
        raise GuardianError("无法识别该官方账号，请在 Codex 重新登录后再保存。")
    return {
        "account_fingerprint": hashlib.sha256(str(identity).encode("utf-8")).hexdigest(),
        "last_refresh": str(value.get("last_refresh") or ""),
        "access_fingerprint": hashlib.sha256(access_token.encode("utf-8")).hexdigest(),
        "refresh_fingerprint": hashlib.sha256(refresh_token.encode("utf-8")).hexdigest(),
    }


def quota_plan_label(plan_type: str | None, limit_name: str | None = None) -> str:
    """Return the public Codex plan label without exposing account identity."""
    raw_plan = str(plan_type or "unknown").strip().lower()
    raw_limit = str(limit_name or "").strip()
    normalized_limit = raw_limit.lower().replace(" ", "")
    if "20x" in normalized_limit:
        return "Pro 20x"
    if "5x" in normalized_limit:
        return "Pro 5x"
    return {
        "free": "Free",
        "go": "Go",
        "plus": "Plus",
        # Codex exposes the lower Pro allowance as `prolite` and the full
        # allowance as `pro` in the app-server PlanType enum.
        "prolite": "Pro 5x",
        "pro": "Pro 20x",
        "team": "Team",
        "self_serve_business_usage_based": "Business",
        "business": "Business",
        "enterprise_cbp_usage_based": "Enterprise",
        "enterprise": "Enterprise",
        "edu": "Edu",
        "unknown": "ChatGPT",
    }.get(raw_plan, str(plan_type or "ChatGPT"))


def normalize_quota_response(
    response: dict[str, Any], account_plan_type: str | None = None
) -> dict[str, Any]:
    """Keep only the current Codex weekly allowance and reset-card balance."""
    snapshots = response.get("rateLimitsByLimitId")
    snapshot = None
    if isinstance(snapshots, dict):
        candidate = snapshots.get("codex")
        if isinstance(candidate, dict):
            snapshot = candidate
        if snapshot is None:
            snapshot = next(
                (
                    item
                    for item in snapshots.values()
                    if isinstance(item, dict) and item.get("limitId") == "codex"
                ),
                None,
            )
    if snapshot is None and isinstance(response.get("rateLimits"), dict):
        snapshot = response["rateLimits"]
    if not isinstance(snapshot, dict):
        raise GuardianError("Codex 未返回可识别的账号额度。")

    windows = [
        item
        for item in (snapshot.get("primary"), snapshot.get("secondary"))
        if isinstance(item, dict)
    ]

    def window_for(minutes: int, fallback_index: int) -> dict[str, Any] | None:
        value = next(
            (item for item in windows if item.get("windowDurationMins") == minutes),
            None,
        )
        if value is None and fallback_index < len(windows):
            fallback = windows[fallback_index]
            if fallback.get("windowDurationMins") is None:
                value = fallback
        if value is None:
            return None
        try:
            raw_used = value["usedPercent"]
            if isinstance(raw_used, bool):
                return None
            used = max(0, min(100, int(raw_used)))
        except (TypeError, ValueError):
            return None
        except KeyError:
            return None
        reset_at = value.get("resetsAt")
        try:
            reset_at = int(reset_at) if reset_at is not None else None
        except (TypeError, ValueError):
            reset_at = None
        return {
            "window_minutes": minutes,
            "used_percent": used,
            "remaining_percent": 100 - used,
            "resets_at": reset_at,
        }

    weekly = window_for(10080, 0)

    reset_cards = None
    raw_reset_cards = response.get("rateLimitResetCredits")
    if isinstance(raw_reset_cards, dict):
        raw_count = raw_reset_cards.get("availableCount")
        try:
            if isinstance(raw_count, bool):
                raise ValueError
            available_count = max(0, min(9999, int(raw_count)))
        except (TypeError, ValueError):
            available_count = None
        expires_at_values: list[int] = []
        raw_credits = raw_reset_cards.get("credits")
        if isinstance(raw_credits, list):
            for item in raw_credits[:100]:
                if not isinstance(item, dict):
                    continue
                reset_type = str(item.get("resetType") or "")
                if reset_type and reset_type != "codexRateLimits":
                    continue
                try:
                    expires_at = int(item.get("expiresAt"))
                except (TypeError, ValueError):
                    continue
                if expires_at > 0:
                    expires_at_values.append(expires_at)
        if available_count is None and isinstance(raw_credits, list):
            available_count = len(expires_at_values)
        if available_count is not None:
            reset_cards = {
                "available_count": available_count,
                "next_expires_at": min(expires_at_values) if expires_at_values else None,
            }

    if weekly is None and reset_cards is None:
        raise GuardianError("Codex 未返回每周额度或重置卡信息。")
    plan_type = str(account_plan_type or snapshot.get("planType") or "unknown")
    limit_name = str(snapshot.get("limitName") or "").strip() or None
    return {
        "status": "ready",
        "plan_type": plan_type,
        "plan_label": quota_plan_label(plan_type, limit_name),
        "limit_id": str(snapshot.get("limitId") or "codex"),
        "limit_name": limit_name,
        "weekly": weekly,
        "reset_cards": reset_cards,
        "fetched_at": utc_now(),
        "stale": False,
    }


class GuardianService:
    def __init__(
        self,
        codex_home: str | Path | None = None,
        data_dir: str | Path | None = None,
        helper_command: list[str] | None = None,
        failover_controller: GatewayController | None = None,
        enable_failover_fixture: bool | None = None,
        claude_local_appdata: str | Path | None = None,
        cc_switch_home: str | Path | None = None,
        gateway_install_root: str | Path | None = None,
        gateway_expected_executable: str | Path | None = None,
        gateway_expected_version: str | None = None,
        gateway_process_identity_reader=None,
        remote_gateway_status_collector: RemoteGatewayStatusCollector | None = None,
        provider_auth_command: list[str] | tuple[str, ...] | None = None,
        updater: GitHubReleaseUpdater | None = None,
    ) -> None:
        default_codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        self.codex_home = Path(codex_home or default_codex_home).expanduser().resolve()
        local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        self.data_dir = Path(data_dir or local_app_data / APP_NAME).expanduser().resolve()
        self.profiles_path = self.data_dir / "profiles.json"
        self.secrets_dir = self.data_dir / "secrets"
        self.backups_dir = self.data_dir / "backups"
        self.logs_path = self.data_dir / "events.jsonl"
        self.updater = updater or GitHubReleaseUpdater(APP_VERSION, self.data_dir)
        self.helper_command = helper_command or self._default_helper_command()
        self.lock = threading.RLock()
        self.quota_refresh_lock = threading.Lock()
        self.is_fixture = self.codex_home != default_codex_home.expanduser().resolve()
        self.claude_desktop = ClaudeDesktopIntegration(
            local_appdata=claude_local_appdata,
            data_dir=self.data_dir / "claude",
            cc_switch_home=cc_switch_home,
            protect=dpapi_protect,
            unprotect=dpapi_unprotect,
        )
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self._cleanup_quota_temp_dirs()
        if not self.profiles_path.exists():
            atomic_json(self.profiles_path, self._empty_state())
        fixture_enabled = self.is_fixture if enable_failover_fixture is None else enable_failover_fixture
        production_values = (
            gateway_install_root,
            gateway_expected_executable,
            gateway_expected_version,
        )
        if any(value is not None for value in production_values) and not all(
            value is not None for value in production_values
        ):
            raise GuardianError("生产 Gateway 身份参数必须完整提供。")
        if failover_controller is None and all(value is not None for value in production_values):
            failover_controller = ProductionGatewayController(
                install_root=gateway_install_root,
                expected_executable=gateway_expected_executable,
                expected_version=str(gateway_expected_version),
                credential_source=self._failover_protected_credential,
                unprotect=dpapi_unprotect,
                process_identity_reader=gateway_process_identity_reader,
            )
        if failover_controller is None and fixture_enabled:
            failover_controller = FixtureGatewayController(
                scenario=os.environ.get("GUARDIAN_FAILOVER_FIXTURE_SCENARIO", "healthy")
            )
        self.provider_activation: ProviderActivationCoordinator | None = None
        if failover_controller is not None:
            auth_command = tuple(provider_auth_command or ("guardian-helper", "gateway-ingress", str(self.data_dir)))
            self.provider_activation = ProviderActivationCoordinator(
                codex_home=self.codex_home,
                data_dir=self.data_dir,
                gateway_status=failover_controller.provider_status,
                auth_command=auth_command,
            )
        self.failover: FailoverManagementService | None = None
        if failover_controller is not None:
            self.failover = FailoverManagementService(
                AtomicFailoverDocumentStore(
                    self.data_dir / "gateway" / "config" / "failover-groups.json"
                ),
                self._failover_profile_source,
                failover_controller,
                provider_status=(
                    None
                    if self.provider_activation is None
                    else self.provider_activation.status
                ),
            )
        self.remote_gateway_status = RemoteGatewayStatusService(
            cache_path=self.data_dir / "gateway" / "remote-status-cache.json",
            hosts_provider=lambda: discover_remote_hosts(
                self.codex_home / ".codex-global-state.json"
            ),
            local_snapshot_provider=self._local_gateway_host_snapshot,
            collector=remote_gateway_status_collector or RemoteGatewayStatusCollector(),
        )

    def _failover_profile_source(self) -> tuple[dict[str, Any], ...]:
        state = self._load_state()
        return tuple(dict(profile) for profile in state.get("profiles", []))

    def _failover_protected_credential(self, profile_id: str) -> bytes:
        profile = self._get_profile(profile_id)
        if profile.get("type") != "api":
            raise GuardianError("容灾线路只允许使用 API 档案。")
        filename = profile.get("secret_file")
        if not isinstance(filename, str) or not filename:
            raise GuardianError("API 档案没有可用凭据。")
        path = (self.secrets_dir / filename).resolve()
        if path.parent != self.secrets_dir.resolve() or not path.is_file():
            raise GuardianError("API 档案凭据文件无效。")
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise GuardianError("API 档案凭据无法读取。") from exc
        if not payload or len(payload) > 1024 * 1024:
            raise GuardianError("API 档案凭据文件无效。")
        return payload

    def require_failover(self) -> FailoverManagementService:
        if self.failover is None:
            raise GuardianError("API 容灾管理需要隔离预览或已验证的生产 Gateway。")
        return self.failover

    def require_provider_activation(self) -> ProviderActivationCoordinator:
        if self.provider_activation is None:
            raise GuardianError("固定 provider 只在已验证的 Gateway 环境中可用。")
        return self.provider_activation

    def activate_failover_provider(
        self,
        *,
        expected_revision: int,
        confirmed: bool,
    ) -> dict[str, object]:
        if not confirmed:
            raise GuardianError("启用固定 provider 需要明确确认。")
        was_running = self.codex_running()
        self._ensure_codex_closed()
        try:
            provider = self.require_provider_activation().activate(
                expected_revision=expected_revision
            )
            self._log("failover.provider.activate", "success", "已启用本地固定 provider")
        except ProviderActivationError as exc:
            if was_running and self._load_state().get("settings", {}).get("auto_launch_codex", True):
                self.launch_codex()
            raise GuardianError(exc.args[0] if exc.args else "固定 provider 启用失败。") from exc
        launched = False
        if self._load_state().get("settings", {}).get("auto_launch_codex", True):
            launched = self.launch_codex()
        return {
            "provider": provider,
            "launched": launched,
            "overview": self.require_failover().overview(),
        }

    def restore_direct_provider(self, *, confirmed: bool) -> dict[str, object]:
        if not confirmed:
            raise GuardianError("恢复直连需要明确确认。")
        was_running = self.codex_running()
        self._ensure_codex_closed()
        try:
            provider = self.require_provider_activation().restore()
            self._log("failover.provider.restore", "success", "已恢复切入前 provider")
        except ProviderActivationError as exc:
            if was_running and self._load_state().get("settings", {}).get("auto_launch_codex", True):
                self.launch_codex()
            raise GuardianError(exc.args[0] if exc.args else "恢复直连失败。") from exc
        launched = False
        if self._load_state().get("settings", {}).get("auto_launch_codex", True):
            launched = self.launch_codex()
        return {
            "provider": provider,
            "launched": launched,
            "overview": self.require_failover().overview(),
        }

    def _local_gateway_host_snapshot(self) -> dict[str, object]:
        failover = self.require_failover()
        snapshot = dict(failover.controller.snapshot())
        if not isinstance(snapshot.get("version"), str):
            snapshot["version"] = str(
                getattr(failover.controller, "expected_version", "v1.7.0-fixture")
            )
        return snapshot

    def gateway_hosts_status(self) -> dict[str, object]:
        return self.remote_gateway_status.snapshot()

    def export_failover_diagnostics(self) -> DiagnosticBundle:
        failover = self.require_failover()
        overview = failover.overview()
        events = failover.list_events(offset=0, limit=MAX_DIAGNOSTIC_EVENTS)
        hosts = self.gateway_hosts_status()
        try:
            return build_diagnostic_bundle(
                gateway_status=self._diagnostic_gateway_status(overview),
                gateway_events=self._diagnostic_gateway_events(events),
                gateway_hosts=self._diagnostic_gateway_hosts(hosts),
                generated_at=utc_now(),
            )
        except DiagnosticBundleError as exc:
            raise GuardianDiagnosticError("guardian_diagnostics_failed") from exc

    @staticmethod
    def _diagnostic_gateway_status(overview: dict[str, object]) -> dict[str, object]:
        summary = overview.get("summary") if isinstance(overview.get("summary"), dict) else {}
        gateway = overview.get("gateway") if isinstance(overview.get("gateway"), dict) else {}
        group = overview.get("group") if isinstance(overview.get("group"), dict) else {}
        route_items = group.get("routes") if isinstance(group.get("routes"), list) else []
        routes_by_role = {
            item.get("role"): item
            for item in route_items
            if isinstance(item, dict) and item.get("role") in {"primary", "backup"}
        }

        def route(role: str) -> dict[str, object]:
            value = routes_by_role.get(role, {})
            last_result = value.get("last_result") if isinstance(value.get("last_result"), dict) else {}
            state = value.get("state")
            if state not in {
                "unknown",
                "closed",
                "open_temporary",
                "half_open",
                "open_action_required",
                "disabled",
            }:
                state = "unknown"
            category = last_result.get("category")
            if not isinstance(category, str) or re.fullmatch(r"[a-z0-9_]{1,96}", category) is None:
                category = "unknown"
            cooldown = value.get("cooldown_seconds")
            if type(cooldown) is not int or cooldown < 0:
                cooldown = None
            return {
                "state": state,
                "carrying": value.get("carrying") is True,
                "cooldown_seconds": cooldown,
                "status_category": category,
                "action_required": state == "open_action_required",
            }

        revision = gateway.get("config_revision")
        if type(revision) is not int or revision < 0:
            revision = 0
        return {
            "schema_version": 1,
            "source": "production" if overview.get("source") == "production" else "fixture",
            "stale": overview.get("stale") is True,
            "collected_at": overview.get("collected_at") if isinstance(overview.get("collected_at"), str) else None,
            "view_state": overview.get("view_state") if overview.get("view_state") in {"ready", "loading", "empty", "error"} else "error",
            "summary": {
                "tone": summary.get("tone") if summary.get("tone") in {"good", "warning", "danger", "neutral"} else "neutral",
                "headline": summary.get("headline") if isinstance(summary.get("headline"), str) else "线路状态不可用",
                "supporting": summary.get("supporting") if isinstance(summary.get("supporting"), str) else "请刷新状态后重试。",
                "required_action": summary.get("required_action") if summary.get("required_action") in {"none", "check_primary", "repair_route", "reload"} else "reload",
                "carrier": summary.get("carrier") if summary.get("carrier") in {"primary", "backup"} else None,
            },
            "gateway": {
                "source": "production" if gateway.get("source") == "production" else "fixture",
                "online": gateway.get("online") is True,
                "phase": gateway.get("phase") if isinstance(gateway.get("phase"), str) else "unavailable",
                "state": gateway.get("state") if isinstance(gateway.get("state"), str) else "unavailable",
                "version": gateway.get("version") if isinstance(gateway.get("version"), str) else "unknown",
                "config_revision": revision,
                "configuration_drift": gateway.get("configuration_drift") is True,
            },
            "routes": {"primary": route("primary"), "backup": route("backup")},
        }

    @staticmethod
    def _diagnostic_gateway_events(events: dict[str, object]) -> dict[str, object]:
        source = "production" if events.get("source") == "production" else "fixture"
        items = events.get("items") if isinstance(events.get("items"), list) else []
        projected = []
        for item in items[:MAX_DIAGNOSTIC_EVENTS]:
            if not isinstance(item, dict):
                continue
            role = item.get("route_role")
            projected.append(
                {
                    "timestamp": item.get("timestamp") if isinstance(item.get("timestamp"), str) else None,
                    "event": item.get("event") if isinstance(item.get("event"), str) else "gateway_event",
                    "status": item.get("status") if isinstance(item.get("status"), str) else "unknown",
                    "route_role": role if role in {"", "primary", "backup"} else "",
                    "source": "production" if item.get("source") == "production" else source,
                }
            )
        return {
            "schema_version": 1,
            "source": source,
            "stale": events.get("stale") is True,
            "collected_at": events.get("collected_at") if isinstance(events.get("collected_at"), str) else None,
            "items": projected,
        }

    @staticmethod
    def _diagnostic_gateway_hosts(hosts: dict[str, object]) -> dict[str, object]:
        items = hosts.get("items") if isinstance(hosts.get("items"), list) else []
        projected = []
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            routes = item.get("routes") if isinstance(item.get("routes"), dict) else {}
            revision = item.get("config_revision")
            if type(revision) is not int or revision < 0:
                revision = None
            error_code = item.get("error_code")
            projected.append(
                {
                    "host_index": index,
                    "kind": "nas" if item.get("kind") == "nas" else "windows",
                    "online": item.get("online") is True,
                    "stale": item.get("stale") is True,
                    "collected_at": item.get("collected_at") if isinstance(item.get("collected_at"), str) else None,
                    "version": item.get("version") if isinstance(item.get("version"), str) else None,
                    "config_revision": revision,
                    "phase": item.get("phase") if isinstance(item.get("phase"), str) else "unavailable",
                    "carrier": item.get("carrier") if item.get("carrier") in {"primary", "backup"} else None,
                    "routes": {
                        "primary": routes.get("primary") if isinstance(routes.get("primary"), str) else "unknown",
                        "backup": routes.get("backup") if isinstance(routes.get("backup"), str) else "unknown",
                    },
                    "error_code": error_code if isinstance(error_code, str) else None,
                }
            )
        return {
            "schema_version": 1,
            "checked_at": hosts.get("checked_at") if isinstance(hosts.get("checked_at"), str) else None,
            "items": projected,
        }

    def refresh_gateway_hosts_status(self, *, confirm_read_only: bool) -> dict[str, object]:
        if confirm_read_only is not True:
            raise GuardianError("刷新远端状态需要明确确认只读 SSH 检查。")
        result = self.remote_gateway_status.refresh()
        items = result.get("items")
        remote_items = [
            item
            for item in items if isinstance(item, dict) and item.get("kind") == "nas"
        ] if isinstance(items, list) else []
        self._log(
            "gateway.remote_status_refresh",
            "success",
            "已完成远端 Gateway 只读状态刷新",
            host_count=len(remote_items),
            success_count=sum(item.get("online") is True for item in remote_items),
        )
        return result

    def claude_desktop_status(self) -> dict[str, Any]:
        try:
            return self.claude_desktop.status()
        except ClaudeDesktopError as exc:
            raise GuardianError("Claude Desktop 配置暂时无法读取。") from exc

    @staticmethod
    def _claude_error(exc: ClaudeDesktopError) -> GuardianError:
        code = str(exc)
        messages = {
            "claude_provider_name_required": "请填写 Claude 供应商名称。",
            "claude_provider_base_url_invalid": "Claude 接口地址无效。",
            "claude_provider_https_required": "Claude 远程接口必须使用 HTTPS。",
            "claude_provider_api_key_invalid": "Claude API Key 无效。",
            "claude_provider_model_id_invalid": "Claude 模型 ID 必须以 claude- 开头。",
            "claude_provider_not_found": "找不到该 Claude 供应商。",
            "claude_provider_current_delete_forbidden": "当前 Claude 供应商不能直接删除，请先恢复官方模式或切换其他供应商。",
            "claude_provider_apply_confirmation_required": "启用 Claude 供应商需要明确确认。",
            "claude_restore_confirmation_required": "恢复 Claude 官方模式需要明确确认。",
            "claude_cc_import_confirmation_required": "从 CC Switch 迁移需要明确确认。",
            "claude_cc_import_source_missing": "没有找到可迁移的 CC Switch 当前供应商。",
            "claude_cc_import_format_unsupported": "当前 CC Switch 供应商不是原生 Anthropic 格式，无法无路由迁移。",
            "claude_cc_import_credentials_missing": "CC Switch 当前供应商缺少可迁移的接口或凭据。",
        }
        return GuardianError(messages.get(code, "Claude Desktop 操作失败，已保持原配置。"))

    def create_claude_profile(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self.claude_desktop.create_profile(
                payload.get("name"),
                payload.get("base_url"),
                payload.get("api_key"),
                payload.get("models"),
            )
        except ClaudeDesktopError as exc:
            raise self._claude_error(exc) from exc
        self._log("claude.profile.create", "success", "已保存 Claude 供应商")
        return result

    def edit_claude_profile(self, profile_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self.claude_desktop.edit_profile(profile_id, payload)
        except ClaudeDesktopError as exc:
            raise self._claude_error(exc) from exc
        self._log("claude.profile.edit", "success", "已更新 Claude 供应商")
        return result

    def delete_claude_profile(self, profile_id: str) -> dict[str, Any]:
        try:
            result = self.claude_desktop.delete_profile(profile_id)
        except ClaudeDesktopError as exc:
            raise self._claude_error(exc) from exc
        self._log("claude.profile.delete", "success", "已删除 Claude 供应商")
        return result

    def apply_claude_profile(self, profile_id: str, *, confirmed: bool) -> dict[str, Any]:
        try:
            result = self.claude_desktop.apply_profile(profile_id, confirmed=confirmed)
        except ClaudeDesktopError as exc:
            raise self._claude_error(exc) from exc
        self._log("claude.profile.apply", "success", "已启用 Guardian Claude 供应商")
        return result

    def restore_claude_official(self, *, confirmed: bool) -> dict[str, Any]:
        try:
            result = self.claude_desktop.restore_official(confirmed=confirmed)
        except ClaudeDesktopError as exc:
            raise self._claude_error(exc) from exc
        self._log("claude.restore_official", "success", "已恢复 Claude 官方模式")
        return result

    def import_claude_from_cc_switch(self, *, confirmed: bool) -> dict[str, Any]:
        try:
            result = self.claude_desktop.import_cc_switch(confirmed=confirmed)
        except ClaudeDesktopError as exc:
            raise self._claude_error(exc) from exc
        self._log("claude.import_cc_switch", "success", "已将 CC Switch 当前供应商迁移到 Guardian")
        return result

    def restart_claude_desktop(self) -> dict[str, Any]:
        try:
            result = self.claude_desktop.restart_claude()
        except (ClaudeDesktopError, OSError, subprocess.SubprocessError) as exc:
            raise GuardianError("Claude Desktop 重启失败。") from exc
        self._log("claude.restart", "success", "已请求重启 Claude Desktop")
        return result

    def _cleanup_quota_temp_dirs(self) -> None:
        """Remove only abandoned isolated quota homes directly under app data."""
        data_root = self.data_dir.resolve()
        for candidate in self.data_dir.glob("quota-*"):
            try:
                if candidate.is_symlink() or candidate.resolve().parent != data_root:
                    continue
                if candidate.is_dir():
                    shutil.rmtree(candidate)
            except OSError:
                # A still-running old query may briefly own files. Its own
                # TemporaryDirectory cleanup gets another chance on exit.
                continue

    def _default_helper_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            bundled_helper = Path(sys.executable).resolve().with_name(
                "CodexProfileGuardianSecret.exe"
            )
            return [str(self._install_stable_helper(bundled_helper))]
        main_path = Path(__file__).resolve().parent.parent / "main.py"
        return [str(Path(sys.executable).resolve()), str(main_path)]

    def _install_stable_helper(self, source: Path) -> Path:
        """Keep the Codex auth helper outside ZIP extraction and build folders."""
        bin_dir = self.data_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        if source.is_file():
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            target = bin_dir / f"CodexProfileGuardianSecret-{digest[:12]}.exe"
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                temporary = bin_dir / f".{target.name}.{uuid.uuid4().hex}.tmp"
                try:
                    shutil.copy2(source, temporary)
                    os.replace(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
            return target.resolve()

        candidates = sorted(
            bin_dir.glob("CodexProfileGuardianSecret-*.exe"),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )
        legacy = bin_dir / "CodexProfileGuardianSecret.exe"
        if legacy.is_file():
            candidates.append(legacy)
        if candidates:
            return candidates[0].resolve()
        raise GuardianError(
            "找不到 CodexProfileGuardianSecret.exe。请先完整解压安装包，"
            "并确保两个 EXE 位于同一目录后再启动。"
        )

    def _empty_state(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "updated_at": utc_now(),
            "current_profile": None,
            "profiles": [],
            "settings": {
                "auto_close_codex": True,
                "auto_launch_codex": True,
                "backup_limit": 10,
                "sync_ssh_official": False,
                "sync_ssh_api": False,
                "auto_update_enabled": True,
            },
            "remote_status": None,
        }

    def _load_state(self) -> dict[str, Any]:
        try:
            state = read_json_file(self.profiles_path)
        except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuardianError(f"配置库损坏：{exc}") from exc
        if state.get("schema_version") != SCHEMA_VERSION:
            raise GuardianError("配置库版本不受支持。")
        return state

    def _save_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        atomic_json(self.profiles_path, state)

    def _log(self, action: str, status: str, message: str, **details: Any) -> None:
        event = {
            "timestamp": utc_now(),
            "action": action,
            "status": status,
            "message": message,
            "details": details,
        }
        self.logs_path.parent.mkdir(parents=True, exist_ok=True)
        with self.logs_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

    def list_profiles(self) -> list[dict[str, Any]]:
        state = self._load_state()
        current = state.get("current_profile")
        result = []
        for profile in state.get("profiles", []):
            result.append(self._public_profile(profile, current))
        return result

    def _public_profile(self, profile: dict[str, Any], current: str | None = None) -> dict[str, Any]:
        private_keys = {
            "secret_file",
            "config_secret_file",
            "account_fingerprint",
            "credential_last_refresh",
        }
        public = {key: value for key, value in profile.items() if key not in private_keys}
        public["current"] = profile["id"] == current
        public["has_secret"] = bool(profile.get("secret_file"))
        public["settings_snapshot"] = False
        public["settings_mode"] = "shared"
        if profile.get("type") == "official":
            public["credential_status"] = (
                "reauth" if profile.get("requires_reauth") else
                "imported" if profile.get("credential_source") == "cockpit_import" else
                "synced"
            )
        return public

    def _get_profile(self, profile_id: str) -> dict[str, Any]:
        state = self._load_state()
        for profile in state.get("profiles", []):
            if profile.get("id") == profile_id:
                return profile
        raise GuardianError("找不到该账号配置。")

    def _secret_path(self, profile_id: str) -> Path:
        return self.secrets_dir / f"{profile_id}.dpapi"

    def _store_secret(self, profile_id: str, secret: bytes) -> str:
        target = self._secret_path(profile_id)
        atomic_write(target, dpapi_protect(secret))
        return target.name

    def _store_config_snapshot(self, profile_id: str, content: bytes) -> str:
        target = self.secrets_dir / f"{profile_id}.config.dpapi"
        atomic_write(target, dpapi_protect(content))
        return target.name

    def _read_config_snapshot(self, profile: dict[str, Any]) -> bytes | None:
        filename = profile.get("config_secret_file")
        if not filename:
            return None
        path = self.secrets_dir / str(filename)
        if not path.is_file():
            return None
        return dpapi_unprotect(path.read_bytes())

    def _capture_profile_config(self, profile_id: str) -> bool:
        path = self.codex_home / "config.toml"
        if not path.is_file():
            return False
        state = self._load_state()
        profile = next((item for item in state["profiles"] if item["id"] == profile_id), None)
        if not profile:
            return False
        profile["config_secret_file"] = self._store_config_snapshot(profile_id, path.read_bytes())
        profile["config_updated_at"] = utc_now()
        self._save_state(state)
        return True

    def _sync_current_profile_environment(self) -> str | None:
        # Credentials can rotate while Codex is running. Global Codex settings are
        # deliberately not captured per account: plugins, MCP, projects and future
        # app-managed keys must remain shared across every profile.
        return self._sync_live_official_profile()

    def _restore_profile_config(self, profile: dict[str, Any]) -> bool:
        content = self._read_config_snapshot(profile)
        if content is None:
            return False
        atomic_write(self.codex_home / "config.toml", content)
        return True

    def decrypt_secret(self, profile_id: str) -> bytes:
        profile = self._get_profile(profile_id)
        secret_file = profile.get("secret_file")
        if not secret_file:
            raise GuardianError("该配置没有保存凭据。")
        return dpapi_unprotect((self.secrets_dir / secret_file).read_bytes())

    def _codex_cli_is_runnable(self, executable: Path) -> bool:
        try:
            probe = subprocess.run(
                [str(executable), "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        output = f"{probe.stdout or ''}\n{probe.stderr or ''}".strip().lower()
        return probe.returncode == 0 and "codex-cli" in output

    def _cached_windows_store_codex_cli(self) -> Path | None:
        if os.name != "nt":
            return None
        try:
            discovered = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "$package = Get-AppxPackage -Name OpenAI.Codex | "
                    "Sort-Object Version -Descending | Select-Object -First 1; "
                    "if ($package) { [pscustomobject]@{ version = [string]$package.Version; "
                    "install_location = [string]$package.InstallLocation } | "
                    "ConvertTo-Json -Compress }",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=0x08000000,
            )
            if discovered.returncode != 0:
                return None
            lines = [line.strip() for line in (discovered.stdout or "").splitlines() if line.strip()]
            payload = json.loads(lines[-1]) if lines else None
            if not isinstance(payload, dict):
                return None
            version = str(payload.get("version") or "").strip()
            location = str(payload.get("install_location") or "").strip()
            if not re.fullmatch(r"[0-9A-Za-z._-]{1,64}", version) or not location:
                return None
            package_root = Path(location).resolve(strict=True)
            source = (package_root / "app" / "resources" / "codex.exe").resolve(strict=True)
            if package_root not in source.parents or not source.is_file():
                return None
            source_stat = source.stat()
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return None

        cache_root = (self.data_dir / "runtime" / "codex").resolve()
        destination = (cache_root / version / "codex.exe").resolve()
        if cache_root not in destination.parents:
            return None
        metadata_path = destination.with_name("source.json")
        expected_metadata = {
            "package_version": version,
            "source": str(source),
            "source_size": int(source_stat.st_size),
            "source_mtime_ns": int(source_stat.st_mtime_ns),
        }
        if destination.is_file() and metadata_path.is_file():
            try:
                if read_json_file(metadata_path) == expected_metadata and self._codex_cli_is_runnable(
                    destination
                ):
                    return destination
            except (OSError, ValueError, json.JSONDecodeError):
                pass

        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.stem}.{uuid.uuid4().hex}.tmp.exe")
        try:
            shutil.copy2(source, temporary)
            if not self._codex_cli_is_runnable(temporary):
                return None
            os.replace(temporary, destination)
            atomic_json(metadata_path, expected_metadata)
            return destination
        except OSError:
            return None
        finally:
            temporary.unlink(missing_ok=True)

    def _codex_app_server_command(self) -> list[str]:
        override = os.environ.get("CODEX_GUARDIAN_CLI", "").strip()
        if override:
            executable = Path(override).expanduser().resolve()
            if not executable.is_file():
                raise GuardianError("指定的 Codex CLI 不存在。")
            return [str(executable), "app-server", "--stdio"]

        if os.name == "nt":
            appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
            package_root = appdata / "npm" / "node_modules" / "@openai" / "codex"
            native_candidates = []
            for package_name in ("codex-win32-x64", "codex-win32-arm64"):
                native_candidates.extend(
                    (package_root / "node_modules" / "@openai" / package_name).glob(
                        "vendor/*/bin/codex.exe"
                    )
                )
            for executable in native_candidates:
                if executable.is_file():
                    return [str(executable), "app-server", "--stdio"]

        command = shutil.which("codex") or shutil.which("codex.cmd")
        if command and not (
            os.name == "nt" and Path(command).suffix.lower() in {".cmd", ".bat"}
        ):
            is_store_resource = (
                os.name == "nt"
                and "\\windowsapps\\openai.codex_" in str(Path(command)).lower()
            )
            if not is_store_resource:
                return [command, "app-server", "--stdio"]
            try:
                probe = subprocess.run(
                    [command, "--version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=6,
                    creationflags=0x08000000,
                )
                if probe.returncode == 0:
                    return [command, "app-server", "--stdio"]
            except (OSError, subprocess.SubprocessError):
                command = None

        # A custom npm prefix can put codex.cmd outside %APPDATA%\npm. Resolve
        # the native executable beside that shim before falling back to cmd.exe.
        if command and os.name == "nt":
            custom_package = Path(command).resolve().parent / "node_modules" / "@openai" / "codex"
            for package_name in ("codex-win32-x64", "codex-win32-arm64"):
                for executable in (
                    custom_package / "node_modules" / "@openai" / package_name
                ).glob("vendor/*/bin/codex.exe"):
                    if executable.is_file():
                        return [str(executable), "app-server", "--stdio"]

        # Windows Store ACLs allow reading the packaged CLI but can deny direct
        # execution from WindowsApps. Cache that exact version in Guardian's
        # user-writable runtime directory before starting app-server.
        packaged = self._cached_windows_store_codex_cli()
        if packaged is not None:
            return [str(packaged), "app-server", "--stdio"]

        if command and os.name == "nt":
            invocation = subprocess.list2cmdline([command, "app-server", "--stdio"])
            return ["cmd.exe", "/d", "/s", "/c", invocation]
        if command:
            return [command, "app-server", "--stdio"]
        raise GuardianError("未找到 Codex CLI，无法读取官方账号额度。")

    def _query_official_quota(
        self, profile: dict[str, Any]
    ) -> tuple[dict[str, Any], bytes | None]:
        auth_bytes = self.decrypt_secret(str(profile["id"]))
        original_meta = official_auth_metadata(auth_bytes)
        with tempfile.TemporaryDirectory(prefix="quota-", dir=self.data_dir) as temporary:
            isolated_home = Path(temporary)
            auth_path = isolated_home / "auth.json"
            atomic_write(auth_path, auth_bytes)
            atomic_write(isolated_home / "config.toml", b'model_provider = "openai"\n')
            environment = os.environ.copy()
            environment["CODEX_HOME"] = str(isolated_home)
            app_server_command = self._codex_app_server_command()
            process = subprocess.Popen(
                app_server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(isolated_home),
                env=environment,
                creationflags=0x08000000 if os.name == "nt" else 0,
                bufsize=1,
            )
            responses: queue.Queue[dict[str, Any]] = queue.Queue()
            pending: dict[int, dict[str, Any]] = {}

            def read_responses() -> None:
                if process.stdout is None:
                    return
                for line in process.stdout:
                    try:
                        item = loads_json_line(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict):
                        responses.put(item)

            reader = threading.Thread(target=read_responses, daemon=True)
            reader.start()
            deadline = time.monotonic() + 30

            def send(item: dict[str, Any]) -> None:
                if process.stdin is None or process.poll() is not None:
                    raise GuardianError("Codex 额度查询进程提前退出。")
                process.stdin.write(
                    json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
                process.stdin.flush()

            def wait_for(
                request_id: int, request_deadline: float | None = None
            ) -> dict[str, Any]:
                if request_id in pending:
                    return pending.pop(request_id)
                effective_deadline = min(deadline, request_deadline or deadline)
                while time.monotonic() < effective_deadline:
                    remaining = max(0.01, effective_deadline - time.monotonic())
                    try:
                        item = responses.get(timeout=min(0.25, remaining))
                    except queue.Empty:
                        if process.poll() is not None:
                            break
                        continue
                    item_id = item.get("id")
                    if item_id == request_id:
                        return item
                    if isinstance(item_id, int):
                        pending[item_id] = item
                raise subprocess.TimeoutExpired(app_server_command, 30)

            try:
                send(
                    {
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "clientInfo": {
                                "name": "codex-profile-guardian",
                                "title": APP_NAME,
                                "version": APP_VERSION,
                            }
                        },
                    }
                )
                initialize = wait_for(1)
                if not isinstance(initialize.get("result"), dict):
                    raise GuardianError("Codex 额度查询初始化失败，请确认 CLI 已更新。")
                send({"method": "initialized", "params": {}})
                send(
                    {
                        "id": 2,
                        "method": "account/read",
                        "params": {"refreshToken": False},
                    }
                )
                send({"id": 3, "method": "account/rateLimits/read", "params": None})
                quota_item = wait_for(3)
                try:
                    account_item = wait_for(2, time.monotonic() + 2)
                except subprocess.TimeoutExpired:
                    # Older app-server versions can still return rate limits
                    # without implementing account/read. Snapshot planType is
                    # the safe fallback in that case.
                    account_item = {}
                quota_response = quota_item.get("result")
                quota_error = (
                    quota_item.get("error", {}).get("message")
                    if isinstance(quota_item.get("error"), dict)
                    else None
                )
                if not isinstance(quota_response, dict):
                    if quota_error and any(
                        marker in str(quota_error).lower()
                        for marker in ("auth", "login", "token", "unauthorized")
                    ):
                        raise GuardianError("官方登录已失效，请先更新登录。")
                    raise GuardianError("Codex 未返回账号额度，请确认 CLI 已更新。")
                account_plan_type = None
                account_response = account_item.get("result")
                if isinstance(account_response, dict):
                    account = account_response.get("account")
                    if isinstance(account, dict) and account.get("type") == "chatgpt":
                        account_plan_type = str(account.get("planType") or "") or None
                quota = normalize_quota_response(quota_response, account_plan_type)
            finally:
                if process.stdin is not None:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                if process.poll() is None:
                    try:
                        if os.name == "nt":
                            subprocess.run(
                                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=5,
                                creationflags=0x08000000,
                            )
                        else:
                            process.terminate()
                        process.wait(timeout=3)
                    except (OSError, subprocess.SubprocessError):
                        try:
                            process.kill()
                            process.wait(timeout=2)
                        except (OSError, subprocess.SubprocessError):
                            pass
                reader.join(timeout=0.5)
                if process.stdout is not None:
                    try:
                        process.stdout.close()
                    except OSError:
                        pass
            refreshed_auth = auth_path.read_bytes() if auth_path.is_file() else auth_bytes
            auth_path.unlink(missing_ok=True)

        if refreshed_auth == auth_bytes:
            return quota, None
        refreshed_meta = official_auth_metadata(refreshed_auth)
        if refreshed_meta["account_fingerprint"] != original_meta["account_fingerprint"]:
            raise GuardianError("额度查询返回了不匹配的账号凭据，已拒绝保存。")
        return quota, refreshed_auth

    def refresh_official_quotas(self, profile_id: str | None = None) -> dict[str, Any]:
        if not self.quota_refresh_lock.acquire(blocking=False):
            return {
                "updated_count": 0,
                "failed_count": 0,
                "in_flight": True,
                "status": self.status(),
            }
        try:
            return self._refresh_official_quotas(profile_id)
        finally:
            self.quota_refresh_lock.release()

    def _refresh_official_quotas(self, profile_id: str | None = None) -> dict[str, Any]:
        with self.lock:
            state = self._load_state()
            targets = [
                dict(profile)
                for profile in state.get("profiles", [])
                if profile.get("type") == "official"
                and (profile_id is None or profile.get("id") == profile_id)
            ]
            if profile_id is not None and not targets:
                raise GuardianError("找不到该官方账号。")
        updated = 0
        failed = 0
        for profile in targets:
            try:
                quota, refreshed_auth = self._query_official_quota(profile)
                with self.lock:
                    current_state = self._load_state()
                    target = next(
                        (
                            item
                            for item in current_state["profiles"]
                            if item.get("id") == profile["id"]
                        ),
                        None,
                    )
                    if target is None:
                        raise GuardianError("额度同步期间账号已被删除。")
                    if refreshed_auth is not None:
                        self._save_official_auth(
                            current_state,
                            target,
                            refreshed_auth,
                            official_auth_metadata(refreshed_auth),
                            source="quota_refresh",
                        )
                        current_state = self._load_state()
                        target = next(
                            item
                            for item in current_state["profiles"]
                            if item.get("id") == profile["id"]
                        )
                    target["quota"] = quota
                    self._save_state(current_state)
                updated += 1
            except subprocess.TimeoutExpired:
                message = "额度查询超时"
                failed += 1
                with self.lock:
                    self._record_quota_error(str(profile["id"]), message)
            except GuardianError as exc:
                message = str(exc)
                failed += 1
                with self.lock:
                    self._record_quota_error(str(profile["id"]), message)
            except Exception:
                message = "额度暂时无法获取"
                failed += 1
                with self.lock:
                    self._record_quota_error(str(profile["id"]), message)
        with self.lock:
            self._log(
                "quota.refresh",
                "success" if not failed else "warning",
                f"官方账号额度已更新：{updated}/{len(targets)}",
                updated_count=updated,
                failed_count=failed,
            )
            return {
                "updated_count": updated,
                "failed_count": failed,
                "status": self.status(),
            }

    def _record_quota_error(self, profile_id: str, message: str) -> None:
        state = self._load_state()
        target = next(
            (item for item in state.get("profiles", []) if item.get("id") == profile_id),
            None,
        )
        if target is None:
            return
        existing = target.get("quota")
        if isinstance(existing, dict) and existing.get("status") == "ready":
            existing["stale"] = True
            existing["error"] = message[:120]
            existing["checked_at"] = utc_now()
        else:
            target["quota"] = {
                "status": "unavailable",
                "error": message[:120],
                "checked_at": utc_now(),
            }
        self._save_state(state)

    def _profile_account_fingerprint(self, profile: dict[str, Any]) -> str | None:
        fingerprint = profile.get("account_fingerprint")
        if fingerprint:
            return str(fingerprint)
        if profile.get("type") != "official" or not profile.get("secret_file"):
            return None
        try:
            return str(official_auth_metadata(self.decrypt_secret(profile["id"]))["account_fingerprint"])
        except (GuardianError, OSError):
            return None

    def _find_official_profile_by_fingerprint(
        self, state: dict[str, Any], fingerprint: str
    ) -> dict[str, Any] | None:
        current_id = state.get("current_profile")
        profiles = sorted(
            state.get("profiles", []),
            key=lambda item: item.get("id") != current_id,
        )
        for profile in profiles:
            if profile.get("type") == "official" and self._profile_account_fingerprint(profile) == fingerprint:
                return profile
        return None

    def _save_official_auth(
        self,
        state: dict[str, Any],
        profile: dict[str, Any],
        auth_bytes: bytes,
        metadata: dict[str, Any],
        *,
        source: str,
    ) -> None:
        profile["secret_file"] = self._store_secret(profile["id"], auth_bytes)
        profile["account_fingerprint"] = metadata["account_fingerprint"]
        profile["credential_updated_at"] = utc_now()
        profile["credential_last_refresh"] = metadata.get("last_refresh") or None
        profile["credential_source"] = source
        profile["requires_reauth"] = False
        profile.pop("reauth_reason", None)
        self._save_state(state)

    def _sync_live_official_profile(self) -> str | None:
        auth_path = self.codex_home / "auth.json"
        if not auth_path.is_file():
            return None
        try:
            auth_bytes = auth_path.read_bytes()
            metadata = official_auth_metadata(auth_bytes)
        except (GuardianError, OSError):
            return None
        state = self._load_state()
        profile = self._find_official_profile_by_fingerprint(
            state, str(metadata["account_fingerprint"])
        )
        if not profile:
            return None
        old_refresh = None
        try:
            old_refresh = official_auth_metadata(self.decrypt_secret(profile["id"])).get(
                "refresh_fingerprint"
            )
        except (GuardianError, OSError):
            pass
        self._save_official_auth(state, profile, auth_bytes, metadata, source="codex_live_sync")
        changed = old_refresh != metadata.get("refresh_fingerprint")
        self._log(
            "profile.sync_live",
            "success",
            f"已回存当前官方账号最新凭据：{profile['name']}",
            profile_id=profile["id"],
            token_rotated=changed,
        )
        return str(profile["id"])

    def capture_official(self, name: str, model: str = "") -> dict[str, Any]:
        with self.lock:
            auth_path = self.codex_home / "auth.json"
            if not auth_path.is_file():
                raise GuardianError("未找到当前官方登录。请先在 Codex 完成官方账号登录。")
            auth_bytes = auth_path.read_bytes()
            metadata = official_auth_metadata(auth_bytes)
            name = (name or "官方账号").strip()[:80]
            model = (model or "").strip()[:120]
            state = self._load_state()
            existing = self._find_official_profile_by_fingerprint(
                state, str(metadata["account_fingerprint"])
            )
            if existing:
                existing["name"] = name
                existing["model"] = model
                state["current_profile"] = existing["id"]
                self._save_official_auth(
                    state, existing, auth_bytes, metadata, source="current_auth"
                )
                self._log(
                    "profile.capture",
                    "success",
                    f"已更新官方账号最新凭据：{name}",
                    profile_id=existing["id"],
                )
                return {
                    key: value
                    for key, value in existing.items()
                    if key not in {"secret_file", "config_secret_file", "account_fingerprint"}
                }
            profile_id = uuid.uuid4().hex
            secret_file = self._store_secret(profile_id, auth_bytes)
            profile = {
                "id": profile_id,
                "type": "official",
                "name": name,
                "provider_id": "openai",
                "model": model,
                "plan": "ChatGPT",
                "source": "current_auth",
                "secret_file": secret_file,
                "account_fingerprint": metadata["account_fingerprint"],
                "credential_updated_at": utc_now(),
                "credential_last_refresh": metadata.get("last_refresh") or None,
                "credential_source": "current_auth",
                "requires_reauth": False,
                "created_at": utc_now(),
                "last_used_at": None,
            }
            state["profiles"].append(profile)
            state["current_profile"] = profile_id
            self._save_state(state)
            self._log("profile.capture", "success", f"已保存官方账号：{name}", profile_id=profile_id)
            return {
                key: value
                for key, value in profile.items()
                if key not in {"secret_file", "config_secret_file", "account_fingerprint"}
            }

    def import_cockpit(self) -> dict[str, Any]:
        with self.lock:
            source_root = self.codex_home / "account_backup"
            metadata_path = source_root / "profiles.json"
            if not metadata_path.is_file():
                raise GuardianError("没有发现 Cockpit Tools 账号备份。")
            metadata = read_json_file(metadata_path)
            candidates = metadata.get("profiles") or []
            state = self._load_state()
            existing_sources = {p.get("source_ref") for p in state.get("profiles", [])}
            existing_fingerprints = {
                fingerprint
                for profile in state.get("profiles", [])
                if (fingerprint := self._profile_account_fingerprint(profile))
            }
            imported = []
            skipped = []
            for candidate in candidates:
                folder = str(candidate.get("folder_name") or "").strip()
                auth_path = source_root / folder / "auth.json"
                source_ref = f"cockpit:{folder}"
                if not folder or not auth_path.is_file() or source_ref in existing_sources:
                    skipped.append(folder or "unknown")
                    continue
                auth_bytes = auth_path.read_bytes()
                try:
                    metadata = official_auth_metadata(auth_bytes)
                except GuardianError:
                    skipped.append(folder)
                    continue
                if metadata["account_fingerprint"] in existing_fingerprints:
                    skipped.append(folder)
                    continue
                profile_id = uuid.uuid4().hex
                secret_file = self._store_secret(profile_id, auth_bytes)
                profile = {
                    "id": profile_id,
                    "type": "official",
                    "name": str(candidate.get("account_label") or f"Cockpit {folder}")[:80],
                    "provider_id": "openai",
                    "model": "",
                    "plan": str(candidate.get("plan_name") or "ChatGPT")[:40],
                    "source": "cockpit_import",
                    "source_ref": source_ref,
                    "secret_file": secret_file,
                    "account_fingerprint": metadata["account_fingerprint"],
                    "credential_updated_at": utc_now(),
                    "credential_last_refresh": metadata.get("last_refresh") or None,
                    "credential_source": "cockpit_import",
                    "requires_reauth": False,
                    "created_at": utc_now(),
                    "last_used_at": None,
                }
                state["profiles"].append(profile)
                existing_fingerprints.add(str(metadata["account_fingerprint"]))
                imported.append(profile["name"])
            self._save_state(state)
            self._log(
                "profile.import_cockpit",
                "success",
                f"从 Cockpit 导入 {len(imported)} 个账号",
                imported_count=len(imported),
                skipped_count=len(skipped),
            )
            return {"imported": imported, "skipped": skipped}

    def create_api_profile(
        self,
        name: str,
        base_url: str,
        api_key: str,
        model: str,
        protocol_compatibility: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            name = name.strip()[:80]
            base_url = base_url.strip().rstrip("/")
            model = (model or "").strip()[:120]
            api_key = api_key.strip()
            if not name or not base_url or not api_key:
                raise GuardianError("名称、基础地址和 API Key 都不能为空；模型 ID 可以留空。")
            if not re.match(r"^https?://", base_url, re.I):
                raise GuardianError("基础地址必须以 http:// 或 https:// 开头。")
            profile_id = uuid.uuid4().hex
            profile = {
                "id": profile_id,
                "type": "api",
                "name": name,
                "provider_id": safe_provider_id(profile_id),
                "base_url": base_url,
                "model": model,
                "wire_api": "responses",
                "secret_hint": "••••" + api_key[-4:] if len(api_key) >= 4 else "已加密",
                "source": "manual",
                "secret_file": self._store_secret(profile_id, api_key.encode("utf-8")),
                "credential_revision": 1,
                "protocol_compatibility": normalize_protocol_compatibility(
                    protocol_compatibility
                ),
                "created_at": utc_now(),
                "last_used_at": None,
                "last_test": None,
            }
            state = self._load_state()
            state["profiles"].append(profile)
            self._save_state(state)
            self._log("profile.create_api", "success", f"已添加第三方 API：{name}", profile_id=profile_id)
            return {
                key: value
                for key, value in profile.items()
                if key not in {"secret_file", "config_secret_file"}
            }

    def delete_profile(self, profile_id: str) -> None:
        with self.lock:
            state = self._load_state()
            profile = next((p for p in state["profiles"] if p["id"] == profile_id), None)
            if not profile:
                raise GuardianError("找不到该账号配置。")
            if state.get("current_profile") == profile_id:
                raise GuardianError("不能删除当前正在使用的配置。请先切换到其他账号。")
            if self.failover is not None and profile_id in self.failover.referenced_profile_ids():
                raise GuardianError("该 API 档案仍被容灾组引用，请先编辑或删除对应容灾组。")
            state["profiles"] = [p for p in state["profiles"] if p["id"] != profile_id]
            self._save_state(state)
            secret = self._secret_path(profile_id)
            if secret.exists():
                secret.unlink()
            config_secret = self.secrets_dir / f"{profile_id}.config.dpapi"
            if config_secret.exists():
                config_secret.unlink()
            self._log("profile.delete", "success", f"已删除配置：{profile['name']}", profile_id=profile_id)

    def edit_profile(self, profile_id: str, values: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            state = self._load_state()
            profile = next((p for p in state["profiles"] if p.get("id") == profile_id), None)
            if not profile:
                raise GuardianError("找不到该账号配置。")
            original_profile = json.loads(json.dumps(profile))
            original_remote_status = json.loads(json.dumps(state.get("remote_status")))
            original_secret_path = self._secret_path(profile_id)
            original_secret = original_secret_path.read_bytes() if original_secret_path.is_file() else None
            is_current = state.get("current_profile") == profile_id
            remote_sync_required = False
            remote_host_count = 0
            backup = None
            launched = False
            try:
                name = str(values.get("name", profile.get("name", ""))).strip()[:80]
                if not name:
                    raise GuardianError("账号名称不能为空。")
                profile["name"] = name
                if profile.get("type") == "official":
                    model = str(values.get("model", profile.get("model", "")) or "").strip()[:120]
                    profile["model"] = model
                elif profile.get("type") == "api":
                    base_url = str(values.get("base_url", profile.get("base_url", ""))).strip().rstrip("/")
                    model = str(values.get("model", profile.get("model", "")) or "").strip()[:120]
                    api_key = str(values.get("api_key", "") or "").strip()
                    if not base_url:
                        raise GuardianError("基础地址不能为空。")
                    if not re.match(r"^https?://", base_url, re.I):
                        raise GuardianError("基础地址必须以 http:// 或 https:// 开头。")
                    profile["base_url"] = base_url
                    profile["model"] = model
                    profile["wire_api"] = "responses"
                    if "protocol_compatibility" in values:
                        try:
                            profile["protocol_compatibility"] = (
                                normalize_protocol_compatibility(
                                    values.get("protocol_compatibility")
                                )
                            )
                        except ValueError as exc:
                            raise GuardianError("协议兼容设置无效。") from exc
                    profile["last_test"] = None
                    if api_key:
                        profile["secret_file"] = self._store_secret(profile_id, api_key.encode("utf-8"))
                        profile["secret_hint"] = "••••" + api_key[-4:] if len(api_key) >= 4 else "已加密"
                        profile["credential_revision"] = int(
                            profile.get("credential_revision") or 1
                        ) + 1
                else:
                    raise GuardianError("未知账号类型，无法编辑。")
                profile["updated_at"] = utc_now()
                remote_runtime_changed = any(
                    original_profile.get(field) != profile.get(field)
                    for field in (
                        ("model",)
                        if profile.get("type") == "official"
                        else ("name", "base_url", "model", "credential_revision")
                    )
                )
                settings = state.get("settings", {})
                remote_sync_enabled = (
                    settings.get("sync_ssh_official", False)
                    if profile.get("type") == "official"
                    else settings.get("sync_ssh_api", False)
                )
                if is_current and remote_runtime_changed and remote_sync_enabled:
                    remote_host_count = len(
                        discover_remote_hosts(self.codex_home / ".codex-global-state.json")
                    )
                    remote_sync_required = remote_host_count > 0
                    if remote_sync_required:
                        previous_remote = state.get("remote_status")
                        previous_synced_at = (
                            previous_remote.get("synced_at")
                            if isinstance(previous_remote, dict)
                            else None
                        )
                        state["remote_status"] = {
                            "host_count": remote_host_count,
                            "success_count": 0,
                            "results": [],
                            "stale": True,
                            "stale_reason": "current_profile_updated",
                            "stale_at": utc_now(),
                            "previous_synced_at": previous_synced_at,
                        }
                if is_current:
                    self._ensure_codex_closed()
                    backup = self.create_backup("before-profile-edit")
                self._save_state(state)
                if is_current:
                    self._update_config(profile)
                    if self._load_state().get("settings", {}).get("auto_launch_codex", True):
                        launched = self.launch_codex()
                self._log(
                    "profile.edit",
                    "success",
                    f"已更新账号配置：{profile['name']}",
                    profile_id=profile_id,
                    current_applied=is_current,
                    backup=backup["name"] if backup else None,
                    api_key_updated=bool(values.get("api_key")) if profile.get("type") == "api" else False,
                )
                fresh = self._get_profile(profile_id)
                return {
                    "profile": self._public_profile(fresh, self._load_state().get("current_profile")),
                    "current_applied": is_current,
                    "backup": backup,
                    "launched": launched,
                    "remote_sync_required": remote_sync_required,
                    "remote_host_count": remote_host_count,
                }
            except Exception:
                rollback_state = self._load_state()
                rollback_state["remote_status"] = original_remote_status
                for index, item in enumerate(rollback_state.get("profiles", [])):
                    if item.get("id") == profile_id:
                        rollback_state["profiles"][index] = original_profile
                        break
                self._save_state(rollback_state)
                if original_secret is not None:
                    atomic_write(original_secret_path, original_secret)
                elif original_secret_path.exists():
                    original_secret_path.unlink()
                if backup:
                    self._restore_files_from_backup(self.backups_dir / backup["name"])
                raise

    def test_api_profile(self, profile_id: str) -> dict[str, Any]:
        profile = self._get_profile(profile_id)
        if profile.get("type") != "api":
            raise GuardianError("官方账号不使用 API 连通性测试。")
        key = self.decrypt_secret(profile_id).decode("utf-8")
        endpoint = profile["base_url"].rstrip("/") + "/models"
        req = urlrequest.Request(endpoint, headers={"Authorization": f"Bearer {key}"})
        started = time.perf_counter()
        try:
            with urlrequest.urlopen(req, timeout=8) as response:
                payload = response.read(1024 * 1024)
                status = int(response.status)
        except urlerror.HTTPError as exc:
            status = int(exc.code)
            payload = exc.read(4096)
        except Exception as exc:
            self._record_test(profile_id, False, None, str(exc))
            raise GuardianError(f"连接失败：{exc}") from exc
        latency_ms = round((time.perf_counter() - started) * 1000)
        ok = 200 <= status < 300
        warning = False
        message = f"HTTP {status}"
        if not ok and status in {403, 404, 405}:
            warning = True
            message = f"模型列表未开放 HTTP {status}"
        model_count = None
        try:
            decoded = json.loads(payload.decode("utf-8", errors="replace"))
            if isinstance(decoded, dict) and isinstance(decoded.get("data"), list):
                model_count = len(decoded["data"])
        except json.JSONDecodeError:
            pass
        self._record_test(profile_id, ok, latency_ms, message, warning=warning)
        self._log(
            "profile.test_api",
            "success" if ok else "warning" if warning else "error",
            f"API 测试 HTTP {status}",
            profile_id=profile_id,
            latency_ms=latency_ms,
        )
        return {
            "ok": ok,
            "warning": warning,
            "status": status,
            "latency_ms": latency_ms,
            "model_count": model_count,
            "message": message,
        }

    def _record_test(
        self,
        profile_id: str,
        ok: bool,
        latency_ms: int | None,
        message: str,
        *,
        warning: bool = False,
    ) -> None:
        state = self._load_state()
        for profile in state["profiles"]:
            if profile["id"] == profile_id:
                profile["last_test"] = {
                    "at": utc_now(),
                    "ok": ok,
                    "warning": warning,
                    "latency_ms": latency_ms,
                    "message": message[:160],
                }
                break
        self._save_state(state)

    def _read_config_provider(self) -> tuple[str, str]:
        config = self.codex_home / "config.toml"
        if not config.exists():
            return "openai", ""
        text = config.read_text(encoding="utf-8-sig", errors="replace")
        try:
            value = tomllib.loads(text)
            return str(value.get("model_provider") or "openai"), str(value.get("model") or "")
        except tomllib.TOMLDecodeError:
            pass
        provider_match = re.search(r'(?m)^model_provider\s*=\s*"([^"]+)"', text)
        model_match = re.search(r'(?m)^model\s*=\s*"([^"]+)"', text)
        return (
            provider_match.group(1) if provider_match else "openai",
            model_match.group(1) if model_match else "",
        )

    def _database_status(self) -> dict[str, Any]:
        db = self.codex_home / "state_5.sqlite"
        if not db.is_file():
            return {
                "exists": False,
                "integrity": "missing",
                "total": 0,
                "active": 0,
                "archived": 0,
                "providers": {},
            }
        connection = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=5)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            total = connection.execute("SELECT COUNT(*) FROM threads").fetchone()[0]
            active = connection.execute("SELECT COUNT(*) FROM threads WHERE archived=0").fetchone()[0]
            archived = connection.execute("SELECT COUNT(*) FROM threads WHERE archived=1").fetchone()[0]
            providers = {
                row[0]: row[1]
                for row in connection.execute(
                    "SELECT model_provider, COUNT(*) FROM threads GROUP BY model_provider"
                )
            }
            return {
                "exists": True,
                "integrity": integrity,
                "total": total,
                "active": active,
                "archived": archived,
                "providers": providers,
            }
        finally:
            connection.close()

    def status(self) -> dict[str, Any]:
        state = self._load_state()
        settings = state.setdefault("settings", {})
        settings.setdefault("sync_ssh_official", False)
        settings.setdefault("sync_ssh_api", False)
        settings.setdefault("auto_update_enabled", True)
        provider, model = self._read_config_provider()
        database = self._database_status()
        shared_history_ready = (
            database["total"] == 0
            or (
                len(database["providers"]) == 1
                and int(database["providers"].get(provider, 0)) == database["total"]
            )
        )
        profiles = self.list_profiles()
        current_profile = next((p for p in profiles if p["current"]), None)
        backups = self.list_backups()
        safe = (
            database["integrity"] == "ok"
            and self.codex_home.exists()
            and shared_history_ready
        )
        return {
            "app": {"name": APP_NAME, "version": APP_VERSION},
            "codex_home": str(self.codex_home),
            "codex_running": self.codex_running() if not self.is_fixture else False,
            "config_provider": provider,
            "config_model": model,
            "current_profile": current_profile,
            "profiles": profiles,
            "database": database,
            "backup_count": len(backups),
            "last_backup": backups[0] if backups else None,
            "health": {
                "safe": safe,
                "auth_present": (self.codex_home / "auth.json").is_file(),
                "config_present": (self.codex_home / "config.toml").is_file(),
                "archive_preserved": True,
                "shared_history_ready": shared_history_ready,
                "global_settings_shared": True,
                "chatgpt_process_compatible": True,
            },
            "settings": settings,
            "remote": {
                "host_count": len(
                    discover_remote_hosts(self.codex_home / ".codex-global-state.json")
                ),
                "last_sync": state.get("remote_status"),
            },
            "update": self.updater.status(),
        }

    def update_status(self) -> dict[str, object]:
        return self.updater.status()

    def check_for_updates(self) -> dict[str, object]:
        result = self.updater.check()
        self._log("update.check", "success" if result["state"] != "error" else "error", "软件版本检查完成", error_code=result.get("error_code"))
        return result

    def download_update(self) -> dict[str, object]:
        try:
            result = self.updater.download()
        except UpdateError as exc:
            raise GuardianError(f"更新下载失败：{exc.code}") from exc
        self._log("update.download", "success", "新版安装包已校验并下载", version=result.get("latest_version"))
        return result

    def install_update(self, *, confirmed: bool) -> dict[str, object]:
        try:
            result = self.updater.install(confirmed=confirmed)
        except UpdateError as exc:
            raise GuardianError(f"更新启动失败：{exc.code}") from exc
        self._log("update.install", "success", "已启动经过校验的新版安装程序", version=result.get("latest_version"))
        return result

    def automatic_update_cycle(self) -> dict[str, object]:
        if self.is_fixture:
            return self.updater.status()
        settings = self._load_state().get("settings", {})
        if not settings.get("auto_update_enabled", True):
            return self.updater.status()
        return self.updater.check_and_download()

    @staticmethod
    def _windows_codex_process_filter() -> str:
        # New Store builds use ChatGPT.exe while keeping the OpenAI.Codex package.
        # This filter intentionally identifies the visible desktop process only.
        return (
            "(($_.Name -ieq 'ChatGPT.exe') -or ($_.Name -ieq 'Codex.exe')) -and ("
            "$_.ExecutablePath -match '\\\\WindowsApps\\\\OpenAI\\.Codex_[^\\\\]+\\\\app\\\\(ChatGPT|Codex)\\.exe$' -or "
            "$_.CommandLine -match '--remote-debugging-port=')"
        )

    @classmethod
    def _windows_codex_related_process_filter(cls) -> str:
        # Closing must also account for an orphaned packaged app-server. A plain
        # codex CLI process outside the Store package is deliberately excluded.
        app_server = (
            "(($_.Name -ieq 'codex.exe') -and "
            "$_.ExecutablePath -match '\\\\WindowsApps\\\\OpenAI\\.Codex_[^\\\\]+\\\\app\\\\resources\\\\codex\\.exe$' -and "
            "$_.CommandLine -match '(^|\\s)app-server(\\s|$)')"
        )
        return f"(({cls._windows_codex_process_filter()}) -or ({app_server}))"

    @staticmethod
    def _windows_processes_running(process_filter: str) -> bool:
        script = (
            "$p=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
            "Where-Object { " + process_filter + " }); "
            "@($p).Count"
        )
        command = ["powershell.exe", "-NoProfile", "-Command", script]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=0x08000000,
            )
            return int((result.stdout or "0").strip().splitlines()[-1]) > 0
        except Exception:
            return False

    def codex_running(self) -> bool:
        if os.name != "nt":
            return False
        return self._windows_processes_running(self._windows_codex_process_filter())

    def _codex_related_running(self) -> bool:
        if os.name != "nt":
            return False
        return self._windows_processes_running(
            self._windows_codex_related_process_filter()
        )

    def request_close_codex(self, timeout_seconds: int = 15) -> bool:
        if self.is_fixture or not self._codex_related_running():
            return True
        discover = (
            "$all=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
            "Where-Object { " + self._windows_codex_related_process_filter() + " }); "
            "$ids=@($all.ProcessId); "
            "$roots=@($all | Where-Object { $ids -notcontains $_.ParentProcessId }); "
        )
        graceful_script = discover + (
            "foreach($p in $roots){ & taskkill.exe /PID $p.ProcessId /T 2>$null | Out-Null }"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", graceful_script],
            capture_output=True,
            timeout=8,
            creationflags=0x08000000,
        )
        graceful_deadline = time.time() + min(5, max(2, timeout_seconds // 2))
        while time.time() < graceful_deadline:
            if not self._codex_related_running():
                return True
            time.sleep(0.4)

        force_script = (
            "$all=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
            "Where-Object { " + self._windows_codex_related_process_filter() + " }); "
            "foreach($p in $all){ & taskkill.exe /F /PID $p.ProcessId /T 2>$null | Out-Null }"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", force_script],
            capture_output=True,
            timeout=8,
            creationflags=0x08000000,
        )
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if not self._codex_related_running():
                return True
            time.sleep(0.4)
        return False

    def launch_codex(self) -> bool:
        if self.is_fixture or os.name != "nt":
            return False
        script = (
            "$a=Get-StartApps | Where-Object {"
            "$_.AppID -like 'OpenAI.Codex_*!App' -or $_.Name -in @('ChatGPT','Codex')"
            "} | Select-Object -First 1; "
            "if(-not $a){exit 2}; "
            "Start-Process ('shell:AppsFolder\\'+$a.AppID); exit 0"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", script],
                capture_output=True,
                timeout=8,
                creationflags=0x08000000,
            )
            if result.returncode != 0:
                return False
            deadline = time.time() + 12
            while time.time() < deadline:
                if self.codex_running():
                    return True
                time.sleep(0.3)
            return False
        except Exception:
            return False

    def _ensure_codex_closed(self) -> None:
        settings = self._load_state().get("settings", {})
        if self.is_fixture:
            return
        if not self._codex_related_running():
            return
        if settings.get("auto_close_codex", True) and self.request_close_codex():
            return
        raise GuardianError("Codex 进程仍在运行，自动关闭失败。请保存工作后完全退出 Codex，再重试。")

    def _copy_backup_file(self, source: Path, backup_root: Path) -> str:
        try:
            relative = source.resolve().relative_to(self.codex_home)
        except ValueError:
            raise GuardianError(f"拒绝备份 Codex 目录之外的文件：{source}")
        destination = backup_root / "files" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return str(relative)

    def _copy_encrypted_backup_file(self, source: Path, backup_root: Path) -> str:
        try:
            relative = source.resolve().relative_to(self.codex_home)
        except ValueError:
            raise GuardianError(f"拒绝备份 Codex 目录之外的文件：{source}")
        plaintext = source.read_bytes()
        if not plaintext or len(plaintext) > 4 * 1024 * 1024:
            raise GuardianError("敏感备份文件为空或超过安全上限。")
        encrypted_relative = Path(str(relative) + ".dpapi")
        destination = backup_root / "files" / encrypted_relative
        atomic_write(destination, dpapi_protect(plaintext))
        try:
            if dpapi_unprotect(destination.read_bytes()) != plaintext:
                raise GuardianError("敏感备份文件 DPAPI 自检失败。")
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return str(encrypted_relative)

    def _rollout_files(self) -> list[Path]:
        return sorted(
            set((self.codex_home / "sessions").rglob("*.jsonl"))
            | set((self.codex_home / "archived_sessions").rglob("*.jsonl")),
            key=lambda item: str(item).lower(),
        )

    def _snapshot_rollout_first_lines(self, backup_root: Path, rollout_files: list[Path]) -> dict[str, Any]:
        snapshot_path = backup_root / "rollout-first-lines.jsonl"
        count = 0
        byte_count = 0
        with snapshot_path.open("w", encoding="utf-8") as handle:
            for path in rollout_files:
                try:
                    relative = path.resolve().relative_to(self.codex_home)
                except ValueError:
                    continue
                with path.open("rb") as source:
                    first_line = source.readline()
                stat = path.stat()
                handle.write(
                    json.dumps(
                        {
                            "relative": str(relative),
                            "size": stat.st_size,
                            "mtime_ns": stat.st_mtime_ns,
                            "first_line_b64": base64.b64encode(first_line).decode("ascii"),
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                count += 1
                byte_count += len(first_line)
        return {"path": snapshot_path.name, "count": count, "bytes": byte_count}

    def _replace_first_line(self, path: Path, first_line: bytes) -> None:
        temp = path.with_name(path.name + ".guardian.tmp")
        with path.open("rb") as source, temp.open("wb") as target_file:
            source.readline()
            target_file.write(first_line)
            shutil.copyfileobj(source, target_file, length=1024 * 1024)
            target_file.flush()
            os.fsync(target_file.fileno())
        os.replace(temp, path)

    def _restore_rollout_first_lines(self, backup_root: Path) -> int:
        snapshot_path = backup_root / "rollout-first-lines.jsonl"
        if not snapshot_path.is_file():
            return 0
        restored = 0
        for line in snapshot_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                item = loads_json_line(line)
                relative = Path(str(item["relative"]))
                first_line = base64.b64decode(str(item["first_line_b64"]))
            except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                continue
            destination = (self.codex_home / relative).resolve()
            if self.codex_home not in destination.parents and destination != self.codex_home:
                raise GuardianError("备份路径越界。")
            if not destination.is_file() or destination.suffix != ".jsonl":
                continue
            self._replace_first_line(destination, first_line)
            restored += 1
        return restored

    def _backup_rollout_copy_relative(self, path: Path, backup_root: Path) -> Path | None:
        try:
            relative = path.relative_to(backup_root)
        except ValueError:
            return None
        parts = relative.parts
        if (
            len(parts) >= 2
            and parts[0] == "files"
            and parts[1] in {"sessions", "archived_sessions"}
            and path.suffix == ".jsonl"
        ):
            return Path(*parts[1:])
        if len(parts) >= 1 and parts[0] in {"sessions", "archived_sessions"} and path.suffix == ".jsonl":
            return relative
        return None

    def _compact_legacy_backup(self, backup_root: Path) -> int:
        backup_root = backup_root.resolve()
        if not (backup_root / "manifest.json").is_file():
            return 0
        rollout_copies: list[tuple[Path, Path]] = []
        for path in backup_root.rglob("*.jsonl"):
            if path.name == "rollout-first-lines.jsonl":
                continue
            relative = self._backup_rollout_copy_relative(path, backup_root)
            if relative is not None:
                rollout_copies.append((path, relative))
        if not rollout_copies:
            return 0

        snapshot_path = backup_root / "rollout-first-lines.jsonl"
        existing = set()
        if snapshot_path.is_file():
            for line in snapshot_path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    existing.add(loads_json_line(line).get("relative"))
                except (TypeError, json.JSONDecodeError):
                    pass
        mode = "a" if snapshot_path.is_file() else "w"
        with snapshot_path.open(mode, encoding="utf-8") as handle:
            for path, relative in rollout_copies:
                relative_text = str(relative)
                if relative_text in existing:
                    continue
                with path.open("rb") as source:
                    first_line = source.readline()
                stat = path.stat()
                handle.write(
                    json.dumps(
                        {
                            "relative": relative_text,
                            "size": stat.st_size,
                            "mtime_ns": stat.st_mtime_ns,
                            "first_line_b64": base64.b64encode(first_line).decode("ascii"),
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )

        freed = sum(path.stat().st_size for path, _ in rollout_copies if path.exists())
        for folder in [
            backup_root / "files" / "sessions",
            backup_root / "files" / "archived_sessions",
            backup_root / "sessions",
            backup_root / "archived_sessions",
        ]:
            if folder.exists():
                resolved = folder.resolve()
                if backup_root not in resolved.parents:
                    raise GuardianError("备份路径越界。")
                shutil.rmtree(resolved)

        manifest_path = backup_root / "manifest.json"
        manifest = read_json_file(manifest_path)
        manifest["backup_mode"] = "lightweight-first-line-compacted"
        manifest["compacted_duplicate_rollout_bytes"] = (
            int(manifest.get("compacted_duplicate_rollout_bytes") or 0) + freed
        )
        manifest["compacted_at"] = utc_now()
        copied = manifest.get("copied_files") or []
        manifest["copied_files"] = [
            item
            for item in copied
            if not (str(item).startswith("sessions") or str(item).startswith("archived_sessions"))
        ]
        atomic_json(manifest_path, manifest)
        return freed

    def create_backup(self, reason: str, *, prune: bool = True) -> dict[str, Any]:
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup_root = self.backups_dir / f"{timestamp}-{reason}"
        backup_root.mkdir(parents=True, exist_ok=False)
        copied: list[str] = []
        encrypted_files: list[dict[str, str]] = []
        auth_path = self.codex_home / "auth.json"
        if auth_path.is_file():
            copied.append(self._copy_encrypted_backup_file(auth_path, backup_root))
            encrypted_files.append(
                {
                    "source": "auth.json",
                    "stored": "auth.json.dpapi",
                    "protection": "windows-dpapi-current-user",
                }
            )
        for filename in ["config.toml", "session_index.jsonl", ".codex-global-state.json"]:
            path = self.codex_home / filename
            if path.is_file():
                copied.append(self._copy_backup_file(path, backup_root))
        rollout_files = self._rollout_files()
        rollout_snapshot = self._snapshot_rollout_first_lines(backup_root, rollout_files)
        db = self.codex_home / "state_5.sqlite"
        archived_flags: dict[str, int] = {}
        if db.is_file():
            source = sqlite3.connect(db, timeout=30)
            destination = sqlite3.connect(backup_root / "state_5.sqlite")
            try:
                source.backup(destination)
                archived_flags = {
                    row[0]: int(row[1]) for row in source.execute("SELECT id, archived FROM threads")
                }
            finally:
                destination.close()
                source.close()
        manifest = {
            "name": backup_root.name,
            "created_at": utc_now(),
            "reason": reason,
            "codex_home": str(self.codex_home),
            "backup_mode": "lightweight-first-line",
            "copied_files": copied,
            "sensitive_files_encrypted": encrypted_files,
            "rollout_file_count": len(rollout_files),
            "rollout_snapshot": rollout_snapshot,
            "archived_flags": archived_flags,
            "archived_count": sum(archived_flags.values()),
            "active_count": len(archived_flags) - sum(archived_flags.values()),
            "config_sha256": sha256(self.codex_home / "config.toml")
            if (self.codex_home / "config.toml").is_file()
            else None,
        }
        atomic_json(backup_root / "manifest.json", manifest)
        if prune:
            self._prune_backups()
        self._log("backup.create", "success", f"已创建安全备份：{backup_root.name}", reason=reason)
        return self._backup_summary(backup_root)

    def _backup_summary(self, backup_root: Path) -> dict[str, Any]:
        manifest_path = backup_root / "manifest.json"
        if not manifest_path.is_file():
            return {"name": backup_root.name, "created_at": None, "reason": "unknown"}
        self._compact_legacy_backup(backup_root)
        manifest = read_json_file(manifest_path)
        bytes_total = 0
        for path in backup_root.rglob("*"):
            if path.is_file():
                bytes_total += path.stat().st_size
        return {
            "name": backup_root.name,
            "created_at": manifest.get("created_at"),
            "reason": manifest.get("reason"),
            "archived_count": manifest.get("archived_count", 0),
            "active_count": manifest.get("active_count", 0),
            "rollout_file_count": manifest.get("rollout_file_count", 0),
            "backup_mode": manifest.get("backup_mode", "full"),
            "size_mb": round(bytes_total / (1024 * 1024), 2),
        }

    def list_backups(self) -> list[dict[str, Any]]:
        if not self.backups_dir.exists():
            return []
        backups = [self._backup_summary(path) for path in self.backups_dir.iterdir() if path.is_dir()]
        return sorted(backups, key=lambda item: item["name"], reverse=True)

    def _prune_backups(self) -> None:
        limit = max(3, min(50, int(self._load_state().get("settings", {}).get("backup_limit", 10))))
        folders = sorted([p for p in self.backups_dir.iterdir() if p.is_dir()], reverse=True)
        for folder in folders[limit:]:
            shutil.rmtree(folder, ignore_errors=True)

    def _restore_files_from_backup(self, backup_root: Path) -> None:
        files_root = backup_root / "files"
        encrypted_auth = files_root / "auth.json.dpapi"
        restored_auth: bytes | None = None
        if encrypted_auth.is_file():
            try:
                restored_auth = dpapi_unprotect(encrypted_auth.read_bytes())
            except Exception as exc:
                raise GuardianError("备份中的 auth.json DPAPI 密文无法解密。") from exc
            if not restored_auth or len(restored_auth) > 4 * 1024 * 1024:
                raise GuardianError("备份中的 auth.json 解密结果无效。")
        if files_root.exists():
            for source in files_root.rglob("*"):
                if source.is_file():
                    relative = source.relative_to(files_root)
                    if relative == Path("auth.json.dpapi"):
                        continue
                    if relative == Path("auth.json") and restored_auth is not None:
                        continue
                    destination = (self.codex_home / relative).resolve()
                    if self.codex_home not in destination.parents and destination != self.codex_home:
                        raise GuardianError("备份路径越界。")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
        if restored_auth is not None:
            atomic_write(self.codex_home / "auth.json", restored_auth)
        backup_db = backup_root / "state_5.sqlite"
        if backup_db.is_file():
            target_db = self.codex_home / "state_5.sqlite"
            for suffix in ("-wal", "-shm"):
                (self.codex_home / f"state_5.sqlite{suffix}").unlink(missing_ok=True)
            temp_db = target_db.with_name(f"state_5.sqlite.{uuid.uuid4().hex}.restore.tmp")
            try:
                shutil.copy2(backup_db, temp_db)
                os.replace(temp_db, target_db)
            finally:
                temp_db.unlink(missing_ok=True)
        self._restore_rollout_first_lines(backup_root)

    def restore_backup(self, backup_name: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_codex_closed()
            backup_root = (self.backups_dir / backup_name).resolve()
            if self.backups_dir not in backup_root.parents or not (backup_root / "manifest.json").is_file():
                raise GuardianError("无效的备份。")
            safety = self.create_backup("before-restore", prune=False)
            try:
                self._restore_files_from_backup(backup_root)
                status = self._database_status()
                if status["integrity"] != "ok":
                    raise GuardianError("恢复后数据库完整性检查失败。")
                self._log("backup.restore", "success", f"已恢复备份：{backup_name}")
            except Exception:
                self._restore_files_from_backup(self.backups_dir / safety["name"])
                raise
            self._prune_backups()
            if self._load_state().get("settings", {}).get("auto_launch_codex", True):
                self.launch_codex()
            return {"restored": backup_name, "safety_backup": safety["name"], "status": status}

    def _update_config(self, profile: dict[str, Any]) -> None:
        config_path = self.codex_home / "config.toml"
        text = config_path.read_text(encoding="utf-8-sig") if config_path.exists() else ""
        managed_pattern = re.compile(
            re.escape(MANAGED_START) + r".*?" + re.escape(MANAGED_END) + r"\s*",
            re.S,
        )
        text = managed_pattern.sub("", text)
        provider_id = profile["provider_id"]
        model = (profile.get("model") or "").strip()
        text = update_top_level_toml(
            text,
            {
                "model_provider": str(provider_id),
                "model": model or None,
                "preferred_auth_method": None,
            },
        )
        if profile["type"] == "api":
            command = self.helper_command[0]
            args = self.helper_command[1:] + ["secret", profile["id"]]
            managed = [
                MANAGED_START,
                f"[model_providers.{provider_id}]",
                f"name = {toml_string(profile['name'])}",
                f"base_url = {toml_string(profile['base_url'])}",
                'wire_api = "responses"',
                "",
                f"[model_providers.{provider_id}.auth]",
                f"command = {toml_string(command)}",
                "args = [" + ", ".join(toml_string(value) for value in args) + "]",
                "timeout_ms = 5000",
                "refresh_interval_ms = 0",
                MANAGED_END,
                "",
            ]
            text = text.rstrip() + "\n\n" + "\n".join(managed)
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise GuardianError(f"Codex config.toml 校验失败：{exc}") from exc
        atomic_write(config_path, text.encode("utf-8"))

    def _rewrite_rollouts(
        self, target_provider: str, rollout_paths: list[Path] | None = None
    ) -> int:
        if rollout_paths is None:
            db = self.codex_home / "state_5.sqlite"
            if not db.is_file():
                raise GuardianError("未找到 state_5.sqlite，无法定位聊天正文。")
            connection = sqlite3.connect(db, timeout=10)
            try:
                rollout_paths = [
                    Path(str(row[0]))
                    for row in connection.execute(
                        "SELECT rollout_path FROM threads WHERE rollout_path IS NOT NULL"
                    )
                ]
            finally:
                connection.close()
        home = self.codex_home.resolve()
        files = []
        for candidate in rollout_paths:
            path = candidate if candidate.is_absolute() else self.codex_home / candidate
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if (
                resolved.is_file()
                and resolved.suffix.lower() == ".jsonl"
                and (resolved == home or home in resolved.parents)
            ):
                files.append(resolved)
        files = sorted(set(files), key=lambda item: str(item).lower())
        changed_files = 0
        for path in files:
            original_stat = path.stat()
            with path.open("rb") as source:
                first_line = source.readline()
            if not first_line:
                continue
            try:
                item = json.loads(first_line.decode("utf-8", errors="strict"))
            except json.JSONDecodeError:
                continue
            if item.get("type") != "session_meta" or not isinstance(item.get("payload"), dict):
                continue
            payload = item["payload"]
            if payload.get("model_provider") == target_provider:
                continue
            payload["model_provider"] = target_provider
            had_newline = first_line.endswith(b"\n")
            capacity = len(first_line) - 1 if had_newline else len(first_line)
            new_json = json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(new_json) <= capacity:
                padded = new_json + (b" " * (capacity - len(new_json))) + (b"\n" if had_newline else b"")
                with path.open("r+b") as target_file:
                    target_file.seek(0)
                    target_file.write(padded)
                    target_file.flush()
                    os.fsync(target_file.fileno())
            else:
                temp = path.with_name(path.name + ".guardian.tmp")
                with path.open("rb") as source, temp.open("wb") as target_file:
                    source.readline()
                    target_file.write(new_json + b"\n")
                    shutil.copyfileobj(source, target_file, length=1024 * 1024)
                    target_file.flush()
                    os.fsync(target_file.fileno())
                os.replace(temp, path)
            os.utime(
                path,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
            changed_files += 1
        return changed_files

    def _migrate_thread_provider(self, target_provider: str) -> dict[str, Any]:
        db = self.codex_home / "state_5.sqlite"
        if not db.is_file():
            raise GuardianError("未找到 state_5.sqlite，无法保护聊天记录。")
        connection = sqlite3.connect(db, timeout=30)
        connection.execute("PRAGMA busy_timeout=30000")
        before_archived = {
            row[0]: int(row[1]) for row in connection.execute("SELECT id, archived FROM threads")
        }
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE threads SET model_provider=? "
                "WHERE model_provider IS NULL OR model_provider<>?",
                (target_provider, target_provider),
            ).rowcount
            rollout_paths = [
                Path(str(row[0]))
                for row in connection.execute(
                    "SELECT rollout_path FROM threads WHERE rollout_path IS NOT NULL"
                )
            ]
            changed_files = self._rewrite_rollouts(target_provider, rollout_paths)
            provider_mismatches = list(
                connection.execute(
                    "SELECT archived, COUNT(*) FROM threads "
                    "WHERE model_provider IS NULL OR model_provider<>? "
                    "GROUP BY archived ORDER BY archived",
                    (target_provider,),
                )
            )
            if provider_mismatches:
                active_mismatches = sum(
                    int(count) for archived, count in provider_mismatches if not int(archived or 0)
                )
                archived_mismatches = sum(
                    int(count) for archived, count in provider_mismatches if int(archived or 0)
                )
                raise GuardianError(
                    "聊天 provider 迁移不完整，已中止切换："
                    f"活动任务 {active_mismatches} 条，归档任务 {archived_mismatches} 条。"
                )
            index_path = self.codex_home / "session_index.jsonl"
            index_preserved = index_path.is_file()
            if index_preserved:
                index_rows = sum(
                    1 for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                )
            else:
                # A missing index is itself user state. New Codex versions can list
                # from state_5.sqlite, so account switching must not synthesize a
                # sidebar index or change visible/archived placement.
                index_rows = 0
            after_archived = {
                row[0]: int(row[1]) for row in connection.execute("SELECT id, archived FROM threads")
            }
            if before_archived != after_archived:
                raise GuardianError("归档标记发生变化，已中止切换。")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise GuardianError(f"数据库完整性检查失败：{integrity}")
            connection.commit()
            return {
                "database_rows_updated": updated,
                "rollout_files_updated": changed_files,
                "index_rows": index_rows,
                "index_preserved": index_preserved,
                "archived_count": sum(before_archived.values()),
                "active_count": len(before_archived) - sum(before_archived.values()),
                "provider_mismatch_count": 0,
                "active_rows_verified": len(before_archived) - sum(before_archived.values()),
                "archive_preserved": True,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def switch_profile(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            profile = self._get_profile(profile_id)
            settings = self._load_state().get("settings", {})
            if (
                profile.get("type") == "api"
                and settings.get("sync_ssh_api", False)
                and not self.is_fixture
            ):
                # A credential that is already rejected by the provider would
                # strand the SSH app-server after the switch and can make Codex
                # open a new continuation task.  Refuse that transition before
                # closing the local app or touching remote history.  Providers
                # that intentionally hide /models are still allowed by the
                # warning result from test_api_profile().
                probe = self.test_api_profile(profile_id)
                if not probe.get("ok") and not probe.get("warning"):
                    detail = str(probe.get("message") or "API 连通性检查失败")
                    raise GuardianError(f"API 预检失败，未切换 SSH：{detail}")
            self._ensure_codex_closed()
            synced_profile_id = self._sync_current_profile_environment()
            profile = self._get_profile(profile_id)
            backup = self.create_backup("before-switch")
            backup_root = self.backups_dir / backup["name"]
            try:
                if profile["type"] == "official":
                    auth_bytes = self.decrypt_secret(profile_id)
                    official_auth_metadata(auth_bytes)
                    atomic_write(self.codex_home / "auth.json", auth_bytes)
                self._update_config(profile)
                migration = self._migrate_thread_provider(profile["provider_id"])
                migration["shared_history_preserved"] = True
                state = self._load_state()
                state["current_profile"] = profile_id
                for item in state["profiles"]:
                    if item["id"] == profile_id:
                        item["last_used_at"] = utc_now()
                self._save_state(state)
                self._log(
                    "profile.switch",
                    "success",
                    f"已切换到：{profile['name']}",
                    profile_id=profile_id,
                    backup=backup["name"],
                    archived_count=migration["archived_count"],
                )
            except Exception as exc:
                self._restore_files_from_backup(backup_root)
                self._log(
                    "profile.switch",
                    "error",
                    f"切换失败并已回滚：{exc}",
                    profile_id=profile_id,
                    backup=backup["name"],
                )
                raise
            remote = None
            settings = self._load_state().get("settings", {})
            if (
                profile["type"] == "official"
                and settings.get("sync_ssh_official", False)
                and not self.is_fixture
            ):
                local_auth = self.decrypt_secret(profile_id)
                remote, authority_auth = sync_official_to_remotes(
                    local_auth,
                    (self.codex_home / "config.toml").read_bytes(),
                    self.codex_home / ".codex-global-state.json",
                )
                if authority_auth != local_auth:
                    authority_meta = official_auth_metadata(authority_auth)
                    state = self._load_state()
                    target = next(item for item in state["profiles"] if item["id"] == profile_id)
                    self._save_official_auth(
                        state,
                        target,
                        authority_auth,
                        authority_meta,
                        source="ssh_newer_authority",
                    )
                    atomic_write(self.codex_home / "auth.json", authority_auth)
                state = self._load_state()
                state["remote_status"] = remote
                self._save_state(state)
                self._log(
                    "remote.sync",
                    "success" if remote["success_count"] == remote["host_count"] else "error",
                    f"SSH 官方账号同步：{remote['success_count']}/{remote['host_count']}",
                    host_count=remote["host_count"],
                    success_count=remote["success_count"],
                )
            elif (
                profile["type"] == "api"
                and settings.get("sync_ssh_api", False)
                and not self.is_fixture
            ):
                remote = sync_api_profile_to_remotes(
                    profile,
                    self.decrypt_secret(profile_id).strip(),
                    (self.codex_home / "config.toml").read_bytes(),
                    self.codex_home / ".codex-global-state.json",
                )
                state = self._load_state()
                state["remote_status"] = remote
                self._save_state(state)
                self._log(
                    "remote.sync_api",
                    "success" if remote["success_count"] == remote["host_count"] else "error",
                    f"SSH API 同步：{remote['success_count']}/{remote['host_count']}",
                    host_count=remote["host_count"],
                    success_count=remote["success_count"],
                )
            launched = False
            if self._load_state().get("settings", {}).get("auto_launch_codex", True):
                launched = self.launch_codex()
            return {
                "profile": profile["name"],
                "backup": backup,
                "migration": migration,
                "launched": launched,
                "synced_profile_id": synced_profile_id,
                "remote": remote,
            }

    def update_official_profile(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            profile = self._get_profile(profile_id)
            if profile.get("type") != "official":
                raise GuardianError("只有官方账号可以更新登录凭据。")
            self._ensure_codex_closed()
            auth_path = self.codex_home / "auth.json"
            if not auth_path.is_file():
                raise GuardianError("未找到当前官方登录。请先在 Codex 重新登录该账号。")
            auth_bytes = auth_path.read_bytes()
            metadata = official_auth_metadata(auth_bytes)
            expected = self._profile_account_fingerprint(profile)
            if expected and expected != metadata["account_fingerprint"]:
                raise GuardianError("当前 Codex 登录的不是这个账号，已拒绝覆盖。")
            backup = self.create_backup("before-credential-update")
            state = self._load_state()
            target = next(item for item in state["profiles"] if item["id"] == profile_id)
            state["current_profile"] = profile_id
            self._save_official_auth(
                state, target, auth_bytes, metadata, source="manual_reauth_sync"
            )
            self._log(
                "profile.credential_update",
                "success",
                f"已更新官方账号登录凭据：{target['name']}",
                profile_id=profile_id,
                backup=backup["name"],
            )
            remote = None
            settings = self._load_state().get("settings", {})
            if settings.get("sync_ssh_official", False) and not self.is_fixture:
                remote, authority_auth = sync_official_to_remotes(
                    auth_bytes,
                    (self.codex_home / "config.toml").read_bytes(),
                    self.codex_home / ".codex-global-state.json",
                )
                if authority_auth != auth_bytes:
                    authority_meta = official_auth_metadata(authority_auth)
                    current_state = self._load_state()
                    current_target = next(
                        item for item in current_state["profiles"] if item["id"] == profile_id
                    )
                    self._save_official_auth(
                        current_state,
                        current_target,
                        authority_auth,
                        authority_meta,
                        source="ssh_newer_authority",
                    )
                    atomic_write(self.codex_home / "auth.json", authority_auth)
                current_state = self._load_state()
                current_state["remote_status"] = remote
                self._save_state(current_state)
            launched = False
            if self._load_state().get("settings", {}).get("auto_launch_codex", True):
                launched = self.launch_codex()
            return {
                "profile": target["name"],
                "backup": backup,
                "launched": launched,
                "remote": remote,
            }

    def sync_current_to_remotes(self) -> dict[str, Any]:
        with self.lock:
            if self.is_fixture:
                raise GuardianError("测试数据目录不能同步 SSH 主机。")
            state = self._load_state()
            current_id = state.get("current_profile")
            if not current_id:
                raise GuardianError("当前没有选中的账号。")
            profile = self._get_profile(str(current_id))
            settings = state.get("settings", {})
            if profile["type"] == "official":
                if not settings.get("sync_ssh_official", False):
                    raise GuardianError("请先开启官方账号 SSH 同步。")
                auth_bytes = self.decrypt_secret(profile["id"])
                remote, authority_auth = sync_official_to_remotes(
                    auth_bytes,
                    (self.codex_home / "config.toml").read_bytes(),
                    self.codex_home / ".codex-global-state.json",
                )
                if authority_auth != auth_bytes:
                    authority_meta = official_auth_metadata(authority_auth)
                    fresh_state = self._load_state()
                    target = next(item for item in fresh_state["profiles"] if item["id"] == profile["id"])
                    self._save_official_auth(
                        fresh_state,
                        target,
                        authority_auth,
                        authority_meta,
                        source="ssh_newer_authority",
                    )
                    atomic_write(self.codex_home / "auth.json", authority_auth)
            elif profile["type"] == "api":
                if not settings.get("sync_ssh_api", False):
                    raise GuardianError("请先开启第三方 API SSH 同步。")
                remote = sync_api_profile_to_remotes(
                    profile,
                    self.decrypt_secret(profile["id"]).strip(),
                    (self.codex_home / "config.toml").read_bytes(),
                    self.codex_home / ".codex-global-state.json",
                )
            else:
                raise GuardianError("未知账号类型，无法同步 SSH。")
            state = self._load_state()
            remote["stale"] = not (
                remote.get("host_count", 0) > 0
                and remote.get("success_count") == remote.get("host_count")
            )
            if remote["stale"]:
                remote["stale_reason"] = "remote_sync_incomplete"
            state["remote_status"] = remote
            self._save_state(state)
            self._log(
                "remote.sync_current",
                "success" if remote["success_count"] == remote["host_count"] else "error",
                f"SSH 当前账号同步：{remote['success_count']}/{remote['host_count']}",
                host_count=remote["host_count"],
                success_count=remote["success_count"],
            )
            return remote

    def repair_visibility(self) -> dict[str, Any]:
        with self.lock:
            self._ensure_codex_closed()
            provider, _ = self._read_config_provider()
            backup = self.create_backup("before-shared-history-repair")
            backup_root = self.backups_dir / backup["name"]
            try:
                result = self._migrate_thread_provider(provider)
                result["shared_history_preserved"] = True
                self._log(
                    "history.repair",
                    "success",
                    "共享聊天历史已统一到当前账号线路",
                    provider=provider,
                    archived_count=result["archived_count"],
                    index_rows=result["index_rows"],
                )
            except Exception:
                self._restore_files_from_backup(backup_root)
                raise
            launched = False
            if self._load_state().get("settings", {}).get("auto_launch_codex", True):
                launched = self.launch_codex()
            return {
                "provider": provider,
                "backup": backup,
                "migration": result,
                "launched": launched,
            }

    def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        state = self._load_state()
        settings = state.setdefault("settings", {})
        if "auto_close_codex" in values:
            settings["auto_close_codex"] = bool(values["auto_close_codex"])
        if "auto_launch_codex" in values:
            settings["auto_launch_codex"] = bool(values["auto_launch_codex"])
        if "backup_limit" in values:
            settings["backup_limit"] = max(3, min(50, int(values["backup_limit"])))
        if "sync_ssh_official" in values:
            settings["sync_ssh_official"] = bool(values["sync_ssh_official"])
        if "sync_ssh_api" in values:
            settings["sync_ssh_api"] = bool(values["sync_ssh_api"])
        if "auto_update_enabled" in values:
            settings["auto_update_enabled"] = bool(values["auto_update_enabled"])
        self._save_state(state)
        self._log("settings.update", "success", "设置已更新")
        return settings

    def logs(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.logs_path.is_file():
            return []
        lines = self.logs_path.read_text(encoding="utf-8-sig").splitlines()[-max(1, min(1000, limit)) :]
        result = []
        for line in reversed(lines):
            try:
                result.append(loads_json_line(line))
            except json.JSONDecodeError:
                continue
        return result

    def clear_logs(self) -> None:
        atomic_write(self.logs_path, b"")

    def open_path(self, kind: str) -> None:
        mapping = {
            "data": self.data_dir,
            "backups": self.backups_dir,
            "codex": self.codex_home,
        }
        target = mapping.get(kind)
        if not target:
            raise GuardianError("未知目录。")
        target.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(target)  # type: ignore[attr-defined]
