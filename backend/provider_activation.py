from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any
import uuid


PROVIDER_ID = "guardian_gateway"
MANAGED_START = "# >>> Codex Profile Guardian Failover >>>"
MANAGED_END = "# <<< Codex Profile Guardian Failover <<<"


class ProviderActivationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, stat.S_IRWXU)
    except OSError:
        pass
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
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
        os.replace(temporary, path)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except OSError as exc:
        raise ProviderActivationError("guardian_provider_atomic_write_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


class ProviderActivationCoordinator:
    def __init__(
        self,
        *,
        codex_home: str | Path,
        data_dir: str | Path,
        gateway_status: Callable[[], Mapping[str, object]],
        auth_command: Sequence[str],
        config_writer: Callable[[Path, bytes], None] | None = None,
    ) -> None:
        if not auth_command or any(not isinstance(value, str) or not value for value in auth_command):
            raise ValueError("guardian_provider_auth_command_invalid")
        self.codex_home = Path(codex_home).resolve()
        self.root = Path(data_dir).resolve() / "provider-activation"
        self.config_path = self.codex_home / "config.toml"
        self.state_path = self.root / "state.json"
        self.backup_path = self.root / "config-before.toml"
        self._gateway_status = gateway_status
        self._auth_command = tuple(auth_command)
        self._write_config = config_writer or _atomic_write

    def status(self) -> dict[str, object]:
        state = self._read_state(required=False)
        return {
            "provider_id": PROVIDER_ID,
            "status": state.get("status", "direct") if state else "direct",
            "gateway_revision": state.get("gateway_revision") if state else None,
            "activated_at": state.get("activated_at") if state else None,
            "restored_at": state.get("restored_at") if state else None,
        }

    def activate(self, *, expected_revision: int | None = None) -> dict[str, object]:
        gateway = self._validated_gateway(expected_revision)
        original_config_present = self.config_path.is_file()
        current = self.config_path.read_bytes() if original_config_present else b""
        existing = self._read_state(required=False)
        if existing and existing.get("status") == "active":
            if (
                existing.get("gateway_revision") == gateway["config_revision"]
                and existing.get("active_config_sha256") == sha256_bytes(current)
            ):
                return self.status()
            raise ProviderActivationError("guardian_provider_activation_state_conflict")

        target = self._build_config(
            current,
            data_port=int(gateway["data_port"]),
        )
        original_hash = sha256_bytes(current)
        target_hash = sha256_bytes(target)
        _atomic_write(self.backup_path, current)
        state = {
            "schema_version": 1,
            "status": "active",
            "provider_id": PROVIDER_ID,
            "gateway_instance_id": gateway["instance_id"],
            "gateway_revision": gateway["config_revision"],
            "original_config_present": original_config_present,
            "original_config_sha256": original_hash,
            "active_config_sha256": target_hash,
            "activated_at": utc_now(),
            "restored_at": None,
        }
        try:
            self._write_config(self.config_path, target)
            self._verify_active_config(target_hash, int(gateway["data_port"]))
            verified_gateway = self._validated_gateway(expected_revision)
            if any(
                verified_gateway[field] != gateway[field]
                for field in ("instance_id", "config_revision", "data_port")
            ):
                raise ProviderActivationError("guardian_gateway_identity_changed")
            _atomic_write(
                self.state_path,
                (json.dumps(state, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
                    "utf-8"
                ),
            )
        except Exception as exc:
            try:
                self._write_config(self.config_path, current)
            except Exception as rollback_exc:
                raise ProviderActivationError("guardian_provider_activation_rollback_failed") from rollback_exc
            if isinstance(exc, ProviderActivationError):
                raise
            raise ProviderActivationError("guardian_provider_activation_failed") from exc
        return self.status()

    def restore(self) -> dict[str, object]:
        state = self._read_state(required=True)
        if state.get("status") == "restored":
            return self.status()
        if state.get("status") != "active":
            raise ProviderActivationError("guardian_provider_restore_state_invalid")
        try:
            current = self.config_path.read_bytes()
            original = self.backup_path.read_bytes()
        except OSError as exc:
            raise ProviderActivationError("guardian_provider_restore_snapshot_unavailable") from exc
        if sha256_bytes(current) != state.get("active_config_sha256"):
            raise ProviderActivationError("guardian_provider_config_drift")
        if sha256_bytes(original) != state.get("original_config_sha256"):
            raise ProviderActivationError("guardian_provider_restore_snapshot_invalid")
        try:
            if state.get("original_config_present") is True:
                self._write_config(self.config_path, original)
            else:
                self.config_path.unlink(missing_ok=True)
            restored = self.config_path.read_bytes() if self.config_path.is_file() else None
            expected_restored = original if state.get("original_config_present") is True else None
            if restored != expected_restored:
                raise ProviderActivationError("guardian_provider_restore_verification_failed")
            next_state = dict(state)
            next_state["status"] = "restored"
            next_state["restored_at"] = utc_now()
            _atomic_write(
                self.state_path,
                (json.dumps(next_state, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
                    "utf-8"
                ),
            )
        except Exception as exc:
            try:
                self._write_config(self.config_path, current)
            except Exception as rollback_exc:
                raise ProviderActivationError("guardian_provider_restore_rollback_failed") from rollback_exc
            if isinstance(exc, ProviderActivationError):
                raise
            raise ProviderActivationError("guardian_provider_restore_failed") from exc
        return self.status()

    def _validated_gateway(self, expected_revision: int | None) -> Mapping[str, object]:
        try:
            value = self._gateway_status()
        except Exception as exc:
            raise ProviderActivationError("guardian_gateway_status_unavailable") from exc
        required = {
            "ok",
            "phase",
            "host",
            "data_port",
            "config_revision",
            "instance_id",
            "models_ready",
        }
        if not isinstance(value, Mapping) or not required.issubset(value):
            raise ProviderActivationError("guardian_gateway_status_invalid")
        if value.get("ok") is not True or value.get("phase") != "running":
            raise ProviderActivationError("guardian_gateway_not_ready")
        if value.get("host") != "127.0.0.1" or type(value.get("data_port")) is not int:
            raise ProviderActivationError("guardian_gateway_endpoint_invalid")
        port = int(value["data_port"])
        revision = value.get("config_revision")
        if not 1024 <= port <= 65535 or type(revision) is not int or int(revision) <= 0:
            raise ProviderActivationError("guardian_gateway_status_invalid")
        if expected_revision is not None and revision != expected_revision:
            raise ProviderActivationError("guardian_gateway_revision_mismatch")
        if value.get("models_ready") is not True:
            raise ProviderActivationError("guardian_gateway_models_not_ready")
        instance_id = value.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            raise ProviderActivationError("guardian_gateway_identity_invalid")
        return value

    def _build_config(self, current: bytes, *, data_port: int) -> bytes:
        try:
            text = current.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ProviderActivationError("guardian_provider_config_encoding_invalid") from exc
        managed_pattern = re.compile(
            re.escape(MANAGED_START) + r".*?" + re.escape(MANAGED_END) + r"\s*",
            re.S,
        )
        text = managed_pattern.sub("", text)
        text = _update_top_level(text, {"model_provider": PROVIDER_ID})
        command, *args = self._auth_command
        managed = [
            MANAGED_START,
            f"[model_providers.{PROVIDER_ID}]",
            'name = "Guardian Gateway"',
            f'base_url = "http://127.0.0.1:{data_port}/v1"',
            'wire_api = "responses"',
            "request_max_retries = 0",
            "stream_max_retries = 0",
            "",
            f"[model_providers.{PROVIDER_ID}.auth]",
            f"command = {_toml_string(command)}",
            "args = [" + ", ".join(_toml_string(value) for value in args) + "]",
            "timeout_ms = 5000",
            "refresh_interval_ms = 0",
            MANAGED_END,
            "",
        ]
        result = text.rstrip() + "\n\n" + "\n".join(managed)
        try:
            document = tomllib.loads(result)
        except tomllib.TOMLDecodeError as exc:
            raise ProviderActivationError("guardian_provider_config_invalid") from exc
        provider = document.get("model_providers", {}).get(PROVIDER_ID, {})
        if (
            document.get("model_provider") != PROVIDER_ID
            or provider.get("base_url") != f"http://127.0.0.1:{data_port}/v1"
            or provider.get("wire_api") != "responses"
            or provider.get("request_max_retries") != 0
            or provider.get("stream_max_retries") != 0
        ):
            raise ProviderActivationError("guardian_provider_config_verification_failed")
        return result.encode("utf-8")

    def _verify_active_config(self, expected_hash: str, data_port: int) -> None:
        try:
            payload = self.config_path.read_bytes()
            document = tomllib.loads(payload.decode("utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ProviderActivationError("guardian_provider_config_verification_failed") from exc
        provider = document.get("model_providers", {}).get(PROVIDER_ID, {})
        auth = provider.get("auth", {})
        if (
            sha256_bytes(payload) != expected_hash
            or document.get("model_provider") != PROVIDER_ID
            or provider.get("base_url") != f"http://127.0.0.1:{data_port}/v1"
            or provider.get("request_max_retries") != 0
            or provider.get("stream_max_retries") != 0
            or auth.get("command") != self._auth_command[0]
            or auth.get("args") != list(self._auth_command[1:])
        ):
            raise ProviderActivationError("guardian_provider_config_verification_failed")

    def _read_state(self, *, required: bool) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if required:
                raise ProviderActivationError("guardian_provider_activation_snapshot_missing")
            return {}
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderActivationError("guardian_provider_activation_state_invalid") from exc
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ProviderActivationError("guardian_provider_activation_state_invalid")
        allowed = {
            "schema_version",
            "status",
            "provider_id",
            "gateway_instance_id",
            "gateway_revision",
            "original_config_present",
            "original_config_sha256",
            "active_config_sha256",
            "activated_at",
            "restored_at",
        }
        if (
            set(value) != allowed
            or value.get("provider_id") != PROVIDER_ID
            or type(value.get("original_config_present")) is not bool
        ):
            raise ProviderActivationError("guardian_provider_activation_state_invalid")
        return value


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _update_top_level(text: str, values: Mapping[str, str | None]) -> str:
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
    updated: list[str] = []
    for line in root_lines:
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*=", line)
        key = match.group(1) if match else None
        if key not in values:
            updated.append(line)
            continue
        if key not in emitted and values[key] is not None:
            updated.append(f"{key} = {_toml_string(str(values[key]))}")
        emitted.add(str(key))
    for key, value in values.items():
        if key not in emitted and value is not None:
            updated.append(f"{key} = {_toml_string(value)}")
    if table_lines and updated and updated[-1].strip():
        updated.append("")
    result = "\n".join(updated + table_lines).rstrip() + "\n"
    try:
        tomllib.loads(result)
    except tomllib.TOMLDecodeError as exc:
        raise ProviderActivationError("guardian_provider_config_invalid") from exc
    return result
