from __future__ import annotations

import base64
import csv
import datetime as dt
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import threading
from typing import Any, Callable
from urllib.parse import quote, urlparse
import uuid


GUARDIAN_PROFILE_ID = "00000000-0000-4000-8000-000000187660"
GUARDIAN_PROFILE_NAME = "Codex Profile Guardian"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_PROFILE_COUNT = 50
CLAUDE_SCHEMA_VERSION = 1


class ClaudeDesktopError(RuntimeError):
    pass


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _clean_text(value: Any, *, limit: int = 160) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )


@lru_cache(maxsize=1)
def _windows_current_user_sid() -> str:
    result = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        timeout=5,
        creationflags=0x08000000,
    )
    if result.returncode != 0:
        raise ClaudeDesktopError("claude_private_acl_identity_failed")
    try:
        row = next(csv.reader([result.stdout.strip()]))
        sid = row[1].strip()
    except (IndexError, StopIteration, csv.Error) as exc:
        raise ClaudeDesktopError("claude_private_acl_identity_failed") from exc
    if re.fullmatch(r"S-1-5-(?:\d+-)+\d+", sid) is None:
        raise ClaudeDesktopError("claude_private_acl_identity_failed")
    return sid


def _restrict_private_path(path: Path, *, directory: bool) -> None:
    if not path.exists():
        return
    if os.name != "nt":
        os.chmod(path, stat.S_IRWXU if directory else stat.S_IRUSR | stat.S_IWUSR)
        return
    suffix = ":(OI)(CI)F" if directory else ":F"
    grants = [
        f"*{_windows_current_user_sid()}{suffix}",
        f"*S-1-5-18{suffix}",
        f"*S-1-5-32-544{suffix}",
    ]
    result = subprocess.run(
        ["icacls.exe", str(path), "/inheritance:r", "/grant:r", *grants],
        capture_output=True,
        text=True,
        timeout=8,
        creationflags=0x08000000,
    )
    if result.returncode != 0:
        raise ClaudeDesktopError("claude_private_acl_update_failed")


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    size = path.stat().st_size
    if size < 0 or size > MAX_CONFIG_BYTES:
        raise ClaudeDesktopError("claude_desktop_config_too_large")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClaudeDesktopError("claude_desktop_config_invalid") from exc
    if not isinstance(value, dict):
        raise ClaudeDesktopError("claude_desktop_config_invalid")
    return value


class ClaudeDesktopIntegration:
    """Guardian-owned Claude Desktop profiles with optional one-time CC migration."""

    def __init__(
        self,
        *,
        local_appdata: str | Path | None = None,
        data_dir: str | Path | None = None,
        cc_switch_home: str | Path | None = None,
        protect: Callable[[bytes], bytes] | None = None,
        unprotect: Callable[[bytes], bytes] | None = None,
        socket_timeout: float = 0.2,
    ) -> None:
        default_local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        self.local_appdata = Path(local_appdata or default_local).expanduser().resolve()
        self.data_dir = Path(
            data_dir or self.local_appdata / "Codex Profile Guardian" / "claude"
        ).expanduser().resolve()
        self.cc_switch_home = Path(cc_switch_home or Path.home() / ".cc-switch").expanduser().resolve()
        self.protect = protect or (lambda payload: payload)
        self.unprotect = unprotect or (lambda payload: payload)
        self.socket_timeout = max(0.05, min(float(socket_timeout), 1.0))
        self.lock = threading.RLock()

        self.normal_config_path = self.local_appdata / "Claude" / "claude_desktop_config.json"
        self.threep_root = self.local_appdata / "Claude-3p"
        self.threep_config_path = self.threep_root / "claude_desktop_config.json"
        self.config_library = self.threep_root / "configLibrary"
        self.profile_path = self.config_library / f"{GUARDIAN_PROFILE_ID}.json"
        self.meta_path = self.config_library / "_meta.json"
        self.cc_switch_db_path = self.cc_switch_home / "cc-switch.db"

        self.store_path = self.data_dir / "profiles.json"
        self.secrets_dir = self.data_dir / "secrets"
        self.backups_dir = self.data_dir / "backups"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        _restrict_private_path(self.data_dir, directory=True)
        _restrict_private_path(self.secrets_dir, directory=True)
        _restrict_private_path(self.backups_dir, directory=True)
        if not self.store_path.exists():
            _atomic_json(self.store_path, self._empty_store())
        _restrict_private_path(self.store_path, directory=False)
        for secret in self.secrets_dir.glob("*.dpapi"):
            if secret.is_file() and not secret.is_symlink():
                _restrict_private_path(secret, directory=False)
        for backup in self.backups_dir.glob("*.dpapi"):
            if backup.is_file() and not backup.is_symlink():
                _restrict_private_path(backup, directory=False)

    @staticmethod
    def _empty_store() -> dict[str, Any]:
        return {
            "schema_version": CLAUDE_SCHEMA_VERSION,
            "updated_at": _utc_now(),
            "current_profile": None,
            "profiles": [],
        }

    def _load_store(self) -> dict[str, Any]:
        value = _read_json_object(self.store_path)
        if value.get("schema_version") != CLAUDE_SCHEMA_VERSION:
            raise ClaudeDesktopError("claude_profile_store_version_unsupported")
        profiles = value.get("profiles")
        if not isinstance(profiles, list):
            raise ClaudeDesktopError("claude_profile_store_invalid")
        return value

    def _save_store(self, value: dict[str, Any]) -> None:
        value["updated_at"] = _utc_now()
        _atomic_json(self.store_path, value)
        _restrict_private_path(self.store_path, directory=False)

    @staticmethod
    def _normalize_base_url(value: Any) -> str:
        raw = _clean_text(value, limit=2048).rstrip("/")
        try:
            parsed = urlparse(raw)
            port = parsed.port
        except ValueError as exc:
            raise ClaudeDesktopError("claude_provider_base_url_invalid") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ClaudeDesktopError("claude_provider_base_url_invalid")
        if parsed.scheme == "http" and parsed.hostname.lower() not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ClaudeDesktopError("claude_provider_https_required")
        if port is not None and not 1 <= port <= 65535:
            raise ClaudeDesktopError("claude_provider_base_url_invalid")
        return raw

    @staticmethod
    def _normalize_models(value: Any) -> list[dict[str, Any]]:
        if value in (None, ""):
            return []
        if isinstance(value, str):
            raw_items: list[Any] = re.split(r"[,\n]", value)
        elif isinstance(value, list):
            raw_items = value
        else:
            raise ClaudeDesktopError("claude_provider_models_invalid")
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in raw_items[:20]:
            if isinstance(raw, dict):
                name = _clean_text(raw.get("name"), limit=128)
                label = _clean_text(raw.get("label") or raw.get("labelOverride"), limit=80)
                supports_1m = bool(raw.get("supports_1m") or raw.get("supports1m"))
            else:
                name = _clean_text(raw, limit=128)
                label = ""
                supports_1m = False
            if not name:
                continue
            if re.fullmatch(r"(?:anthropic/)?claude-[A-Za-z0-9._-]+", name) is None:
                raise ClaudeDesktopError("claude_provider_model_id_invalid")
            if name in seen:
                continue
            seen.add(name)
            item: dict[str, Any] = {"name": name, "supports_1m": supports_1m}
            if label:
                item["label"] = label
            result.append(item)
        return result

    def _secret_path(self, profile_id: str) -> Path:
        return self.secrets_dir / f"{profile_id}.dpapi"

    def _store_secret(self, profile_id: str, api_key: str) -> str:
        key = str(api_key or "").strip()
        if not key or len(key) > 8192 or "\x00" in key:
            raise ClaudeDesktopError("claude_provider_api_key_invalid")
        payload = self.protect(key.encode("utf-8"))
        if not payload:
            raise ClaudeDesktopError("claude_provider_secret_protection_failed")
        target = self._secret_path(profile_id)
        _atomic_write(target, payload)
        _restrict_private_path(target, directory=False)
        return target.name

    def _read_secret(self, profile: dict[str, Any]) -> str:
        filename = profile.get("secret_file")
        if not isinstance(filename, str) or not filename:
            raise ClaudeDesktopError("claude_provider_secret_missing")
        path = (self.secrets_dir / filename).resolve()
        if path.parent != self.secrets_dir.resolve() or not path.is_file():
            raise ClaudeDesktopError("claude_provider_secret_missing")
        try:
            raw = self.unprotect(path.read_bytes()).decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ClaudeDesktopError("claude_provider_secret_unavailable") from exc
        if not raw:
            raise ClaudeDesktopError("claude_provider_secret_unavailable")
        return raw

    @staticmethod
    def _public_profile(profile: dict[str, Any], current_id: str | None) -> dict[str, Any]:
        return {
            "id": str(profile.get("id") or ""),
            "name": str(profile.get("name") or "未命名供应商"),
            "base_url": str(profile.get("base_url") or ""),
            "models": list(profile.get("models") or []),
            "secret_hint": str(profile.get("secret_hint") or ""),
            "has_secret": bool(profile.get("secret_file")),
            "current": profile.get("id") == current_id,
            "created_at": profile.get("created_at"),
            "updated_at": profile.get("updated_at"),
            "source": profile.get("source") or "guardian",
        }

    def list_profiles(self) -> list[dict[str, Any]]:
        store = self._load_store()
        current_id = store.get("current_profile")
        return [self._public_profile(item, current_id) for item in store.get("profiles", [])]

    def _get_profile(self, profile_id: str) -> dict[str, Any]:
        store = self._load_store()
        for item in store.get("profiles", []):
            if item.get("id") == profile_id:
                return item
        raise ClaudeDesktopError("claude_provider_not_found")

    def create_profile(
        self,
        name: Any,
        base_url: Any,
        api_key: Any,
        models: Any = None,
        *,
        source: str = "guardian",
    ) -> dict[str, Any]:
        with self.lock:
            store = self._load_store()
            if len(store.get("profiles", [])) >= MAX_PROFILE_COUNT:
                raise ClaudeDesktopError("claude_provider_limit_reached")
            clean_name = _clean_text(name, limit=120)
            if not clean_name:
                raise ClaudeDesktopError("claude_provider_name_required")
            clean_url = self._normalize_base_url(base_url)
            clean_models = self._normalize_models(models)
            profile_id = uuid.uuid4().hex
            key = str(api_key or "").strip()
            secret_file = self._store_secret(profile_id, key)
            now = _utc_now()
            profile = {
                "id": profile_id,
                "name": clean_name,
                "base_url": clean_url,
                "models": clean_models,
                "secret_file": secret_file,
                "secret_hint": key[-4:] if len(key) >= 4 else "••••",
                "source": source,
                "created_at": now,
                "updated_at": now,
            }
            store["profiles"].append(profile)
            try:
                self._save_store(store)
            except Exception:
                self._secret_path(profile_id).unlink(missing_ok=True)
                raise
            return self._public_profile(profile, store.get("current_profile"))

    def edit_profile(self, profile_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            store = self._load_store()
            profile = next(
                (item for item in store.get("profiles", []) if item.get("id") == profile_id),
                None,
            )
            if profile is None:
                raise ClaudeDesktopError("claude_provider_not_found")
            if "name" in payload:
                name = _clean_text(payload.get("name"), limit=120)
                if not name:
                    raise ClaudeDesktopError("claude_provider_name_required")
                profile["name"] = name
            if "base_url" in payload:
                profile["base_url"] = self._normalize_base_url(payload.get("base_url"))
            if "models" in payload:
                profile["models"] = self._normalize_models(payload.get("models"))
            new_key = str(payload.get("api_key") or "").strip()
            if new_key:
                profile["secret_file"] = self._store_secret(profile_id, new_key)
                profile["secret_hint"] = new_key[-4:] if len(new_key) >= 4 else "••••"
            profile["updated_at"] = _utc_now()
            self._save_store(store)
            return self._public_profile(profile, store.get("current_profile"))

    def delete_profile(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            store = self._load_store()
            if store.get("current_profile") == profile_id:
                raise ClaudeDesktopError("claude_provider_current_delete_forbidden")
            profile = next(
                (item for item in store.get("profiles", []) if item.get("id") == profile_id),
                None,
            )
            if profile is None:
                raise ClaudeDesktopError("claude_provider_not_found")
            store["profiles"] = [
                item for item in store.get("profiles", []) if item.get("id") != profile_id
            ]
            self._save_store(store)
            filename = profile.get("secret_file")
            if isinstance(filename, str):
                (self.secrets_dir / filename).unlink(missing_ok=True)
            return {"deleted": profile_id}

    @staticmethod
    def _deployment_mode(*values: Any) -> str:
        modes = {_clean_text(value, limit=8).lower() for value in values if value}
        if "3p" in modes:
            return "third_party"
        if modes and modes <= {"1p"}:
            return "official"
        return "unknown"

    @staticmethod
    def _write_deployment_mode(path: Path, mode: str) -> None:
        value = _read_json_object(path)
        value["deploymentMode"] = mode
        _atomic_json(path, value)

    @staticmethod
    def _profile_document(profile: dict[str, Any], api_key: str) -> dict[str, Any]:
        value: dict[str, Any] = {
            "coworkEgressAllowedHosts": ["*"],
            "disableDeploymentModeChooser": True,
            "inferenceGatewayApiKey": api_key,
            "inferenceGatewayAuthScheme": "bearer",
            "inferenceGatewayBaseUrl": profile["base_url"],
            "inferenceProvider": "gateway",
        }
        models = []
        for item in profile.get("models") or []:
            model = {"name": item["name"]}
            if item.get("label"):
                model["labelOverride"] = item["label"]
            if item.get("supports_1m"):
                model["supports1m"] = True
            models.append(model)
        if models:
            value["inferenceModels"] = models
        return value

    @staticmethod
    def _meta_document(applied: bool) -> dict[str, Any]:
        value: dict[str, Any] = {"appliedId": None, "entries": []}
        return value if not applied else {
            "appliedId": GUARDIAN_PROFILE_ID,
            "entries": [{"id": GUARDIAN_PROFILE_ID, "name": GUARDIAN_PROFILE_NAME}],
        }

    def _updated_meta(self, *, applied: bool) -> dict[str, Any]:
        value = _read_json_object(self.meta_path)
        entries = value.get("entries")
        if not isinstance(entries, list):
            entries = []
        entries = [
            item
            for item in entries
            if not isinstance(item, dict) or item.get("id") != GUARDIAN_PROFILE_ID
        ]
        if applied:
            entries.append({"id": GUARDIAN_PROFILE_ID, "name": GUARDIAN_PROFILE_NAME})
            value["appliedId"] = GUARDIAN_PROFILE_ID
        else:
            value["appliedId"] = None
        value["entries"] = entries
        return value

    def _target_paths(self) -> tuple[Path, ...]:
        return (
            self.normal_config_path,
            self.threep_config_path,
            self.profile_path,
            self.meta_path,
        )

    def _snapshot(self) -> dict[str, bytes | None]:
        return {
            str(path): path.read_bytes() if path.is_file() else None
            for path in self._target_paths()
        }

    def _persist_snapshot(self, snapshot: dict[str, bytes | None], action: str) -> str:
        payload = {
            "schema_version": 1,
            "created_at": _utc_now(),
            "action": action,
            "files": {
                path: None if content is None else base64.b64encode(content).decode("ascii")
                for path, content in snapshot.items()
            },
        }
        protected = self.protect(
            (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        )
        name = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".dpapi"
        target = self.backups_dir / name
        _atomic_write(target, protected)
        _restrict_private_path(target, directory=False)
        return name

    @staticmethod
    def _restore_snapshot(snapshot: dict[str, bytes | None]) -> None:
        for raw_path, content in snapshot.items():
            path = Path(raw_path)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, content)

    def apply_profile(self, profile_id: str, *, confirmed: bool) -> dict[str, Any]:
        if confirmed is not True:
            raise ClaudeDesktopError("claude_provider_apply_confirmation_required")
        with self.lock:
            store = self._load_store()
            profile = next(
                (item for item in store.get("profiles", []) if item.get("id") == profile_id),
                None,
            )
            if profile is None:
                raise ClaudeDesktopError("claude_provider_not_found")
            api_key = self._read_secret(profile)
            snapshot = self._snapshot()
            backup_name = self._persist_snapshot(snapshot, "apply")
            try:
                self._write_deployment_mode(self.normal_config_path, "3p")
                self._write_deployment_mode(self.threep_config_path, "3p")
                _atomic_json(self.profile_path, self._profile_document(profile, api_key))
                _atomic_json(self.meta_path, self._updated_meta(applied=True))
                verification = _read_json_object(self.profile_path)
                if (
                    verification.get("inferenceGatewayBaseUrl") != profile["base_url"]
                    or not verification.get("inferenceGatewayApiKey")
                    or _read_json_object(self.meta_path).get("appliedId") != GUARDIAN_PROFILE_ID
                ):
                    raise ClaudeDesktopError("claude_provider_apply_verification_failed")
                store["current_profile"] = profile_id
                self._save_store(store)
            except Exception:
                self._restore_snapshot(snapshot)
                raise
            return {
                "applied": True,
                "backup": backup_name,
                "restart_required": True,
                "status": self.status(),
            }

    def restore_official(self, *, confirmed: bool) -> dict[str, Any]:
        if confirmed is not True:
            raise ClaudeDesktopError("claude_restore_confirmation_required")
        with self.lock:
            store = self._load_store()
            snapshot = self._snapshot()
            backup_name = self._persist_snapshot(snapshot, "restore_official")
            try:
                self._write_deployment_mode(self.normal_config_path, "1p")
                self._write_deployment_mode(self.threep_config_path, "1p")
                self.profile_path.unlink(missing_ok=True)
                _atomic_json(self.meta_path, self._updated_meta(applied=False))
                store["current_profile"] = None
                self._save_store(store)
            except Exception:
                self._restore_snapshot(snapshot)
                raise
            return {
                "restored": True,
                "backup": backup_name,
                "restart_required": True,
                "status": self.status(),
            }

    def _cc_switch_current(self, *, include_credentials: bool = False) -> dict[str, Any] | None:
        if not self.cc_switch_db_path.is_file():
            return None
        uri_path = quote(self.cc_switch_db_path.as_posix(), safe="/:")
        try:
            connection = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True, timeout=0.25)
            try:
                connection.execute("PRAGMA query_only = ON")
                columns = "id, name, settings_config, meta" if include_credentials else "id, name, meta"
                row = connection.execute(
                    f"SELECT {columns} FROM providers "
                    "WHERE app_type = ? AND is_current = 1 LIMIT 1",
                    ("claude-desktop",),
                ).fetchone()
            finally:
                connection.close()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        if include_credentials:
            provider_id, name, raw_settings, raw_meta = row
        else:
            provider_id, name, raw_meta = row
            raw_settings = "{}"
        try:
            settings = json.loads(raw_settings or "{}")
            meta = json.loads(raw_meta or "{}")
        except json.JSONDecodeError:
            return None
        if not isinstance(settings, dict) or not isinstance(meta, dict):
            return None
        env = settings.get("env")
        if not isinstance(env, dict):
            env = {}
        return {
            "id": str(provider_id or ""),
            "name": _clean_text(name, limit=120) or "CC Switch 当前供应商",
            "base_url": env.get("ANTHROPIC_BASE_URL"),
            "api_key": env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY"),
            "api_format": _clean_text(meta.get("apiFormat"), limit=32).lower(),
            "routes": meta.get("claudeDesktopModelRoutes"),
        }

    def migration_status(self) -> dict[str, Any]:
        current = self._cc_switch_current()
        if current is None:
            return {"available": False}
        return {
            "available": True,
            "provider_name": current["name"],
            "compatible": current.get("api_format") in {"", "anthropic"},
            "credentials_checked": False,
        }

    def import_cc_switch(self, *, confirmed: bool) -> dict[str, Any]:
        if confirmed is not True:
            raise ClaudeDesktopError("claude_cc_import_confirmation_required")
        current = self._cc_switch_current(include_credentials=True)
        if current is None:
            raise ClaudeDesktopError("claude_cc_import_source_missing")
        if current.get("api_format") not in {"", "anthropic"}:
            raise ClaudeDesktopError("claude_cc_import_format_unsupported")
        if not current.get("base_url") or not current.get("api_key"):
            raise ClaudeDesktopError("claude_cc_import_credentials_missing")
        models: list[dict[str, Any]] = []
        routes = current.get("routes")
        if isinstance(routes, dict):
            for item in routes.values():
                if not isinstance(item, dict):
                    continue
                model = _clean_text(item.get("model"), limit=128)
                if model:
                    models.append(
                        {
                            "name": model,
                            "label": _clean_text(item.get("labelOverride"), limit=80),
                            "supports_1m": bool(item.get("supports1m")),
                        }
                    )
        profile = self.create_profile(
            f"{current['name']}（已迁移）",
            current["base_url"],
            current["api_key"],
            models,
            source="cc_switch_migration",
        )
        return {"imported": True, "profile": profile}

    @staticmethod
    def _public_gateway(raw_url: Any) -> tuple[dict[str, Any] | None, tuple[str, int] | None]:
        value = _clean_text(raw_url, limit=2048)
        if not value:
            return None, None
        try:
            parsed = urlparse(value)
            port = parsed.port
        except ValueError:
            return {"configured": True, "address": "地址无效", "loopback": False}, None
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return {"configured": True, "address": "地址无效", "loopback": False}, None
        host = parsed.hostname.lower()
        loopback = host in {"127.0.0.1", "localhost", "::1"}
        default_port = 443 if parsed.scheme == "https" else 80
        effective_port = port or default_port
        display_host = f"[{host}]" if ":" in host else host
        display = f"{parsed.scheme}://{display_host}"
        if effective_port != default_port:
            display += f":{effective_port}"
        display += parsed.path.rstrip("/") or "/"
        endpoint = (host, effective_port) if loopback else None
        return {"configured": True, "address": display, "loopback": loopback}, endpoint

    def _route_online(self, endpoint: tuple[str, int] | None) -> bool | None:
        if endpoint is None:
            return None
        try:
            with socket.create_connection(endpoint, timeout=self.socket_timeout):
                return True
        except OSError:
            return False

    def status(self) -> dict[str, Any]:
        normal = _read_json_object(self.normal_config_path)
        threep = _read_json_object(self.threep_config_path)
        meta = _read_json_object(self.meta_path)
        deployment_mode = self._deployment_mode(
            normal.get("deploymentMode"), threep.get("deploymentMode")
        )
        applied_id = str(meta.get("appliedId") or "")
        store = self._load_store()
        current_id = store.get("current_profile")
        current = next(
            (item for item in store.get("profiles", []) if item.get("id") == current_id),
            None,
        )
        guardian_applied = (
            deployment_mode == "third_party"
            and applied_id == GUARDIAN_PROFILE_ID
            and self.profile_path.is_file()
            and current is not None
        )
        if deployment_mode == "official":
            state = "official"
        elif guardian_applied:
            state = "ready"
        elif deployment_mode == "third_party":
            state = "external"
        else:
            state = "not_configured"

        gateway, endpoint = self._public_gateway(current.get("base_url") if guardian_applied else None)
        if gateway is not None:
            gateway["online"] = self._route_online(endpoint)
        timestamps = [
            path.stat().st_mtime
            for path in (self.normal_config_path, self.threep_config_path, self.profile_path, self.store_path)
            if path.is_file()
        ]
        updated_at = (
            dt.datetime.fromtimestamp(max(timestamps), tz=dt.timezone.utc).isoformat()
            if timestamps else None
        )
        migration = (
            {"available": False}
            if store.get("profiles")
            else self.migration_status()
        )
        return {
            "supported": os.name == "nt",
            "detected": self.normal_config_path.is_file() or self.threep_root.is_dir(),
            "state": state,
            "deployment_mode": deployment_mode,
            "config_owner": "guardian" if guardian_applied else "external" if state == "external" else "official",
            "profiles": [
                self._public_profile(item, current_id) for item in store.get("profiles", [])
            ],
            "current_profile": self._public_profile(current, current_id) if current else None,
            "gateway": gateway,
            "credential_state": "managed_by_guardian" if current else "not_configured",
            "models": list(current.get("models") or []) if current else [],
            "migration": migration,
            "updated_at": updated_at,
            "restart_required_after_change": True,
        }

    def _claude_update_executable(self) -> Path | None:
        update = self.local_appdata / "AnthropicClaude" / "Update.exe"
        if update.is_file():
            return update
        candidates = sorted(
            (self.local_appdata / "AnthropicClaude").glob("app-*/claude.exe"),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )
        return candidates[0] if candidates else None

    def restart_claude(self) -> dict[str, Any]:
        executable = self._claude_update_executable()
        if os.name != "nt" or executable is None:
            raise ClaudeDesktopError("claude_desktop_executable_not_found")
        install_root = (self.local_appdata / "AnthropicClaude").resolve()
        root_literal = str(install_root).replace("'", "''")
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$root='{root_literal}'; "
            "$targets=@(Get-Process -Name claude -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Path -and $_.Path.StartsWith($root, "
            "[System.StringComparison]::OrdinalIgnoreCase) }); "
            "if ($targets.Count -gt 0) { $targets | Stop-Process -Force -ErrorAction Stop }; "
            "exit 0"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=12,
            creationflags=0x08000000,
        )
        if result.returncode != 0:
            raise ClaudeDesktopError("claude_desktop_close_failed")
        command = (
            [str(executable), "--processStart", "claude.exe"]
            if executable.name.lower() == "update.exe"
            else [str(executable)]
        )
        subprocess.Popen(command, cwd=str(executable.parent), close_fds=True)
        return {"restarted": True}
