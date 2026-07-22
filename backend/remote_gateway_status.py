from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any
import uuid

from .remote_gateway import BoundedProcessResult, ProcessRunner, run_bounded_process


STATUS_PROTOCOL = "guardian-nas-status-v1"
STATUS_REMOTE_COMMAND = "python3 - guardian-nas-status-v1"
MAX_STATUS_STDIN = 64 * 1024
MAX_STATUS_STDOUT = 16 * 1024
MAX_STATUS_STDERR = 8 * 1024
MAX_STATUS_CACHE = 256 * 1024
_HOST_TARGET = re.compile(r"[A-Za-z0-9_.:@][A-Za-z0-9_.:@-]{0,254}")
_VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
_SAFE_TEXT = re.compile(r"[A-Za-z0-9 ._()+@,-]{1,128}")
_BREAKER_STATES = {
    "unknown",
    "closed",
    "open_temporary",
    "half_open",
    "open_action_required",
    "disabled",
}
_PHASES = {"running", "draining"}
_ERROR_CODES = {
    "nas_gateway_status_invalid",
    "nas_gateway_status_unavailable",
}
_RECEIPT_FIELDS = {
    "protocol",
    "ok",
    "error_code",
    "collected_at",
    "version",
    "config_revision",
    "phase",
    "carrier",
    "primary_state",
    "backup_state",
}


class RemoteGatewayStatusError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _public_text(value: object, *, fallback: str, maximum: int = 80) -> str:
    text = " ".join(
        "".join(
            character if ord(character) >= 0x20 and ord(character) != 0x7F else " "
            for character in str(value or "")
        ).split()
    )
    return (text or fallback)[:maximum]


def _host_key(host: Mapping[str, Any]) -> str:
    identity = host.get("host_id")
    if not isinstance(identity, str) or not identity:
        identity = f"{host.get('target', '')}:{host.get('port', 22)}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def ssh_status_command(host: Mapping[str, Any]) -> list[str]:
    target = host.get("target")
    port = host.get("port", 22)
    if not isinstance(target, str) or _HOST_TARGET.fullmatch(target) is None:
        raise RemoteGatewayStatusError("nas_gateway_status_host_invalid")
    if type(port) is not int or not 1 <= port <= 65535:
        raise RemoteGatewayStatusError("nas_gateway_status_host_invalid")
    return [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        str(port),
        target,
        STATUS_REMOTE_COMMAND,
    ]


def render_status_worker() -> bytes:
    payload = _REMOTE_STATUS_WORKER.encode("utf-8")
    if len(payload) > MAX_STATUS_STDIN:
        raise RemoteGatewayStatusError("nas_gateway_status_input_too_large")
    return payload


def parse_status_receipt(payload: bytes) -> dict[str, object]:
    if len(payload) > MAX_STATUS_STDOUT:
        raise RemoteGatewayStatusError("nas_gateway_status_output_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteGatewayStatusError("nas_gateway_status_output_invalid") from exc
    if not isinstance(document, dict) or set(document) != _RECEIPT_FIELDS:
        raise RemoteGatewayStatusError("nas_gateway_status_output_invalid")
    if document.get("protocol") != STATUS_PROTOCOL or type(document.get("ok")) is not bool:
        raise RemoteGatewayStatusError("nas_gateway_status_output_invalid")
    if not document["ok"]:
        if document.get("error_code") not in _ERROR_CODES:
            raise RemoteGatewayStatusError("nas_gateway_status_output_invalid")
        if any(
            document.get(field) is not None
            for field in (
                "collected_at",
                "version",
                "config_revision",
                "phase",
                "carrier",
                "primary_state",
                "backup_state",
            )
        ):
            raise RemoteGatewayStatusError("nas_gateway_status_output_invalid")
        return document
    if document.get("error_code") is not None:
        raise RemoteGatewayStatusError("nas_gateway_status_output_invalid")
    timestamp = document.get("collected_at")
    version = document.get("version")
    revision = document.get("config_revision")
    try:
        parsed = datetime.fromisoformat(str(timestamp)).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise RemoteGatewayStatusError("nas_gateway_status_output_invalid") from exc
    if (
        parsed.tzinfo is None
        or not isinstance(version, str)
        or _VERSION.fullmatch(version) is None
        or type(revision) is not int
        or revision <= 0
        or document.get("phase") not in _PHASES
        or document.get("carrier") not in {None, "primary", "backup"}
        or document.get("primary_state") not in _BREAKER_STATES
        or document.get("backup_state") not in _BREAKER_STATES
    ):
        raise RemoteGatewayStatusError("nas_gateway_status_output_invalid")
    return document


class RemoteGatewayStatusCollector:
    def __init__(
        self,
        *,
        runner: ProcessRunner | None = None,
        timeout: float = 25.0,
    ) -> None:
        if timeout <= 0 or timeout > 120:
            raise ValueError("nas_gateway_status_timeout_invalid")
        self._runner = runner or run_bounded_process
        self._timeout = timeout

    def collect(self, host: Mapping[str, Any]) -> dict[str, object]:
        try:
            command = ssh_status_command(host)
            completed = self._runner(
                command,
                render_status_worker(),
                self._timeout,
                MAX_STATUS_STDOUT,
                MAX_STATUS_STDERR,
            )
            if completed.timed_out:
                raise RemoteGatewayStatusError("nas_gateway_status_timeout")
            if completed.stdout_truncated or completed.stderr_truncated:
                raise RemoteGatewayStatusError("nas_gateway_status_output_too_large")
            if completed.returncode != 0:
                raise RemoteGatewayStatusError("nas_gateway_status_ssh_failed")
            receipt = parse_status_receipt(completed.stdout)
            if not receipt["ok"]:
                raise RemoteGatewayStatusError(str(receipt["error_code"]))
            return receipt
        except RemoteGatewayStatusError as exc:
            return {"ok": False, "error_code": str(exc)}
        except (OSError, subprocess.SubprocessError):
            return {"ok": False, "error_code": "nas_gateway_status_process_failed"}


HostProvider = Callable[[], Sequence[Mapping[str, Any]]]
LocalSnapshotProvider = Callable[[], Mapping[str, object]]


@dataclass(slots=True)
class RemoteGatewayStatusService:
    cache_path: Path
    hosts_provider: HostProvider
    local_snapshot_provider: LocalSnapshotProvider
    collector: RemoteGatewayStatusCollector
    clock: Callable[[], str] = _utc_now

    def __post_init__(self) -> None:
        self.cache_path = Path(self.cache_path).resolve()

    def snapshot(self) -> dict[str, object]:
        checked_at = self.clock()
        cached = self._load_cache()
        cached_items = {
            item["host_key"]: item
            for item in cached.get("items", [])
            if isinstance(item, dict) and isinstance(item.get("host_key"), str)
        }
        items = [self._local_item(checked_at)]
        for host in self._hosts():
            key = _host_key(host)
            previous = cached_items.get(key)
            if previous is None:
                items.append(self._empty_remote(host, key, checked_at))
            else:
                items.append(
                    {
                        **previous,
                        "display_name": _public_text(host.get("display_name"), fallback="NAS"),
                        "online": False,
                        "stale": True,
                        "checked_at": checked_at,
                    }
                )
        return {"schema_version": 1, "checked_at": checked_at, "items": items}

    def refresh(self) -> dict[str, object]:
        checked_at = self.clock()
        hosts = self._hosts()
        cached = self._load_cache()
        cached_items = {
            item["host_key"]: item
            for item in cached.get("items", [])
            if isinstance(item, dict) and isinstance(item.get("host_key"), str)
        }
        workers = min(4, max(1, len(hosts)))
        if hosts:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="guardian-nas-status") as pool:
                collected = list(pool.map(self.collector.collect, hosts))
        else:
            collected = []
        remote_items = [
            self._remote_item(host, result, cached_items.get(_host_key(host)), checked_at)
            for host, result in zip(hosts, collected, strict=True)
        ]
        self._write_cache({"schema_version": 1, "saved_at": checked_at, "items": remote_items})
        return {
            "schema_version": 1,
            "checked_at": checked_at,
            "items": [self._local_item(checked_at), *remote_items],
        }

    def _hosts(self) -> list[Mapping[str, Any]]:
        result: list[Mapping[str, Any]] = []
        seen: set[str] = set()
        for host in self.hosts_provider():
            if not isinstance(host, Mapping):
                continue
            try:
                ssh_status_command(host)
            except RemoteGatewayStatusError:
                continue
            key = _host_key(host)
            if key not in seen:
                result.append(host)
                seen.add(key)
        return result[:32]

    def _local_item(self, checked_at: str) -> dict[str, object]:
        try:
            snapshot = self.local_snapshot_provider()
            return self._project_item(
                host_key="local",
                display_name="Windows 本机",
                kind="windows",
                result=snapshot,
                checked_at=checked_at,
            )
        except Exception:
            return {
                **self._empty_base("local", "Windows 本机", "windows", checked_at),
                "error_code": "local_gateway_status_unavailable",
            }

    def _remote_item(
        self,
        host: Mapping[str, Any],
        result: Mapping[str, object],
        previous: Mapping[str, object] | None,
        checked_at: str,
    ) -> dict[str, object]:
        key = _host_key(host)
        name = _public_text(host.get("display_name"), fallback="NAS")
        if result.get("ok") is True:
            return self._project_item(
                host_key=key,
                display_name=name,
                kind="nas",
                result=result,
                checked_at=checked_at,
            )
        error_code = self._safe_error(result.get("error_code"))
        if previous is not None:
            return {
                **previous,
                "display_name": name,
                "online": False,
                "stale": True,
                "checked_at": checked_at,
                "error_code": error_code,
            }
        return {
            **self._empty_base(key, name, "nas", checked_at),
            "error_code": error_code,
        }

    def _project_item(
        self,
        *,
        host_key: str,
        display_name: str,
        kind: str,
        result: Mapping[str, object],
        checked_at: str,
    ) -> dict[str, object]:
        version = result.get("version")
        revision = result.get("config_revision")
        phase = result.get("phase")
        carrier = result.get("carrier")
        routes = result.get("routes")
        primary = result.get("primary_state")
        backup = result.get("backup_state")
        if isinstance(routes, Mapping):
            primary_route = routes.get("primary")
            backup_route = routes.get("backup")
            primary = primary_route.get("state") if isinstance(primary_route, Mapping) else primary
            backup = backup_route.get("state") if isinstance(backup_route, Mapping) else backup
        if (
            not isinstance(version, str)
            or _VERSION.fullmatch(version) is None
            or type(revision) is not int
            or revision < 0
            or phase not in _PHASES
            or carrier not in {None, "primary", "backup"}
            or primary not in _BREAKER_STATES
            or backup not in _BREAKER_STATES
        ):
            raise RemoteGatewayStatusError("gateway_host_projection_invalid")
        collected_at = result.get("collected_at")
        if not isinstance(collected_at, str):
            collected_at = checked_at
        return {
            "host_key": host_key,
            "display_name": display_name,
            "kind": kind,
            "online": True,
            "stale": False,
            "checked_at": checked_at,
            "collected_at": collected_at,
            "version": version,
            "config_revision": revision,
            "phase": phase,
            "carrier": carrier,
            "routes": {"primary": primary, "backup": backup},
            "error_code": None,
        }

    @staticmethod
    def _empty_base(host_key: str, display_name: str, kind: str, checked_at: str) -> dict[str, object]:
        return {
            "host_key": host_key,
            "display_name": display_name,
            "kind": kind,
            "online": False,
            "stale": True,
            "checked_at": checked_at,
            "collected_at": None,
            "version": None,
            "config_revision": None,
            "phase": "unavailable",
            "carrier": None,
            "routes": {"primary": "unknown", "backup": "unknown"},
            "error_code": "nas_gateway_status_not_collected",
        }

    def _empty_remote(
        self,
        host: Mapping[str, Any],
        host_key: str,
        checked_at: str,
    ) -> dict[str, object]:
        return self._empty_base(
            host_key,
            _public_text(host.get("display_name"), fallback="NAS"),
            "nas",
            checked_at,
        )

    @staticmethod
    def _safe_error(value: object) -> str:
        if isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,96}", value):
            return value
        return "nas_gateway_status_unavailable"

    def _load_cache(self) -> dict[str, object]:
        try:
            if self.cache_path.is_symlink() or self.cache_path.stat().st_size > MAX_STATUS_CACHE:
                raise OSError
            document = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or set(document) != {"schema_version", "saved_at", "items"}:
                raise ValueError
            if document.get("schema_version") != 1 or not isinstance(document.get("items"), list):
                raise ValueError
            return document
        except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return {"schema_version": 1, "saved_at": None, "items": []}

    def _write_cache(self, document: Mapping[str, object]) -> None:
        payload = (
            json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_STATUS_CACHE:
            raise RemoteGatewayStatusError("gateway_host_cache_too_large")
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.cache_path.parent / f".{self.cache_path.name}.{uuid.uuid4().hex}.tmp"
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
            os.replace(temporary, self.cache_path)
            os.chmod(self.cache_path, stat.S_IRUSR | stat.S_IWUSR)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except OSError:
                pass


_REMOTE_STATUS_WORKER = r'''from __future__ import annotations
from datetime import datetime, timezone
import http.client, json, os, stat, sys
from pathlib import Path

PROTOCOL = "guardian-nas-status-v1"
FIELDS = ("protocol", "ok", "error_code", "collected_at", "version", "config_revision", "phase", "carrier", "primary_state", "backup_state")

def emit(ok, error_code=None, **values):
    document = {field: None for field in FIELDS}
    document.update({"protocol": PROTOCOL, "ok": ok, "error_code": error_code})
    document.update(values)
    print(json.dumps(document, ensure_ascii=True, allow_nan=False, separators=(",", ":")))

def reject_links(home, path):
    relative = path.relative_to(home)
    current = home
    if current.is_symlink(): raise RuntimeError
    for part in relative.parts:
        current = current / part
        if current.is_symlink(): raise RuntimeError

def read_private(path, maximum, encoding):
    if path.is_symlink() or not path.is_file(): raise RuntimeError
    mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO): raise RuntimeError
    payload = path.read_bytes()
    if not payload or len(payload) > maximum: raise RuntimeError
    return payload.decode(encoding)

def request_json(port, path, token):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Authorization": "Bearer " + token, "Host": "127.0.0.1:" + str(port), "Accept": "application/json"})
        response = connection.getresponse()
        payload = response.read(64 * 1024 + 1)
        if response.status != 200 or len(payload) > 64 * 1024: raise RuntimeError
        document = json.loads(payload.decode("utf-8"))
        if not isinstance(document, dict): raise RuntimeError
        return document
    finally:
        connection.close()

def main():
    if len(sys.argv) != 2 or sys.argv[1] != PROTOCOL or os.name != "posix":
        emit(False, "nas_gateway_status_invalid"); return 0
    try:
        home = Path.home().resolve()
        state = home / ".local" / "state" / "codex-profile-guardian-gateway"
        config = home / ".config" / "codex-profile-guardian-gateway"
        runtime_path = state / "runtime" / "runtime.json"
        token_path = config / "tokens" / "control.token"
        reject_links(home, runtime_path)
        reject_links(home, token_path)
        runtime = json.loads(read_private(runtime_path, 64 * 1024, "utf-8"))
        if not isinstance(runtime, dict) or runtime.get("schema_version") != 1: raise RuntimeError
        token = read_private(token_path, 512, "ascii")
        if len(token) < 48 or len(token) > 256 or any(ord(char) < 0x21 or ord(char) > 0x7e for char in token): raise RuntimeError
        port = runtime.get("control_port")
        if type(port) is not int or port < 1024 or port > 65535: raise RuntimeError
        status = request_json(port, "/control/v1/status", token)
        snapshot = request_json(port, "/control/v1/failover/snapshot", token)
        identity = ("instance_id", "process_instance_id", "pid", "process_started_at", "version", "config_revision")
        if any(status.get(field) != runtime.get(field) for field in identity): raise RuntimeError
        if status.get("phase") not in {"running", "draining"} or snapshot.get("phase") != status.get("phase"): raise RuntimeError
        if snapshot.get("config_revision") != runtime.get("config_revision") or snapshot.get("active_group_id") != status.get("active_group_id"): raise RuntimeError
        carrier = snapshot.get("carrier")
        routes = snapshot.get("routes")
        if carrier not in {None, "primary", "backup"} or not isinstance(routes, dict): raise RuntimeError
        primary = routes.get("primary")
        backup = routes.get("backup")
        if not isinstance(primary, dict) or not isinstance(backup, dict): raise RuntimeError
        states = {"unknown", "closed", "open_temporary", "half_open", "open_action_required", "disabled"}
        if primary.get("state") not in states or backup.get("state") not in states: raise RuntimeError
        emit(True, collected_at=datetime.now(timezone.utc).isoformat(), version=runtime["version"], config_revision=runtime["config_revision"], phase=status["phase"], carrier=carrier, primary_state=primary["state"], backup_state=backup["state"])
    except Exception:
        emit(False, "nas_gateway_status_unavailable")
    return 0

raise SystemExit(main())
'''


__all__ = [
    "MAX_STATUS_STDERR",
    "MAX_STATUS_STDIN",
    "MAX_STATUS_STDOUT",
    "RemoteGatewayStatusCollector",
    "RemoteGatewayStatusError",
    "RemoteGatewayStatusService",
    "STATUS_PROTOCOL",
    "STATUS_REMOTE_COMMAND",
    "parse_status_receipt",
    "render_status_worker",
    "ssh_status_command",
]
