from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import stat
from typing import Callable, Mapping
import uuid

import aiohttp


class RuntimeFileError(RuntimeError):
    pass


class RuntimeOwnerVerificationError(RuntimeFileError):
    pass


@dataclass(frozen=True, slots=True)
class RuntimeDescriptor:
    schema_version: int
    instance_id: str
    process_instance_id: str
    pid: int
    process_started_at: str
    gateway_started_at: str
    version: str
    executable_path: str
    host: str
    data_port: int
    control_port: int
    control_endpoint: str
    config_revision: int
    config_sha256: str
    ingress_token_sha256: str
    control_token_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("runtime_descriptor_schema_invalid")
        if not self.instance_id or not self.process_instance_id or self.pid <= 0:
            raise ValueError("runtime_descriptor_identity_invalid")
        executable = Path(self.executable_path)
        if not executable.is_absolute():
            raise ValueError("runtime_descriptor_executable_invalid")
        _parse_utc_timestamp(self.process_started_at, "runtime_descriptor_process_time_invalid")
        _parse_utc_timestamp(self.gateway_started_at, "runtime_descriptor_gateway_time_invalid")
        if self.host != "127.0.0.1" or not 1024 <= self.data_port <= 65535:
            raise ValueError("runtime_descriptor_data_endpoint_invalid")
        if not 1024 <= self.control_port <= 65535 or self.control_port == self.data_port:
            raise ValueError("runtime_descriptor_control_endpoint_invalid")
        if self.control_endpoint != f"http://127.0.0.1:{self.control_port}":
            raise ValueError("runtime_descriptor_control_endpoint_invalid")
        if self.config_revision <= 0:
            raise ValueError("runtime_descriptor_revision_invalid")
        for value in (self.config_sha256, self.ingress_token_sha256, self.control_token_sha256):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError("runtime_descriptor_hash_invalid")
        if self.ingress_token_sha256 == self.control_token_sha256:
            raise ValueError("runtime_descriptor_tokens_must_be_distinct")

    def public(self) -> Mapping[str, object]:
        return asdict(self)


class RuntimeDescriptorStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, descriptor: RuntimeDescriptor) -> None:
        payload = (
            json.dumps(
                descriptor.public(),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(parent, stat.S_IRWXU)
        except OSError:
            pass
        temporary = parent / f".{self.path.name}.{uuid.uuid4().hex}.tmp"
        descriptor_fd: int | None = None
        try:
            descriptor_fd = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            with os.fdopen(descriptor_fd, "wb") as stream:
                descriptor_fd = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise RuntimeFileError("runtime_descriptor_write_failed") from exc
        finally:
            if descriptor_fd is not None:
                os.close(descriptor_fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def read(self) -> RuntimeDescriptor:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise TypeError
            return RuntimeDescriptor(**document)
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise RuntimeFileError("runtime_descriptor_invalid") from exc

    def remove_if_owned(self, process_instance_id: str) -> bool:
        try:
            current = self.read()
        except FileNotFoundError:
            return False
        if current.process_instance_id != process_instance_id:
            return False
        try:
            self.path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise RuntimeFileError("runtime_descriptor_remove_failed") from exc


@dataclass(frozen=True, slots=True)
class RuntimeOwnerVerification:
    descriptor: RuntimeDescriptor
    control_status: Mapping[str, object]


ProcessIdentityReader = Callable[[int], tuple[str, str] | None]


async def verify_runtime_owner(
    store: RuntimeDescriptorStore,
    *,
    control_token: str,
    expected_executable: str | Path,
    expected_version: str,
    expected_revision: int,
    session: aiohttp.ClientSession,
    process_identity_reader: ProcessIdentityReader | None = None,
    timeout_seconds: float = 2.0,
) -> RuntimeOwnerVerification:
    try:
        descriptor = store.read()
    except (FileNotFoundError, RuntimeFileError) as exc:
        raise RuntimeOwnerVerificationError("runtime_owner_descriptor_unavailable") from exc
    expected_path = Path(expected_executable).resolve()
    if Path(descriptor.executable_path).resolve() != expected_path:
        raise RuntimeOwnerVerificationError("runtime_owner_executable_mismatch")
    if descriptor.version != expected_version or descriptor.config_revision != expected_revision:
        raise RuntimeOwnerVerificationError("runtime_owner_release_mismatch")
    if _text_sha256(control_token) != descriptor.control_token_sha256:
        raise RuntimeOwnerVerificationError("runtime_owner_control_token_mismatch")
    identity_reader = process_identity_reader or read_process_identity
    identity = identity_reader(descriptor.pid)
    if identity is None:
        raise RuntimeOwnerVerificationError("runtime_owner_process_missing")
    actual_path, actual_started_at = identity
    if Path(actual_path).resolve() != expected_path:
        raise RuntimeOwnerVerificationError("runtime_owner_process_executable_mismatch")
    if not _timestamps_match(actual_started_at, descriptor.process_started_at):
        raise RuntimeOwnerVerificationError("runtime_owner_process_start_mismatch")
    try:
        async with session.get(
            f"{descriptor.control_endpoint}/control/v1/status",
            headers={"Authorization": f"Bearer {control_token}"},
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
        ) as response:
            if response.status != 200:
                raise RuntimeOwnerVerificationError("runtime_owner_control_handshake_failed")
            document = await response.json(content_type="application/json")
    except RuntimeOwnerVerificationError:
        raise
    except Exception as exc:
        raise RuntimeOwnerVerificationError("runtime_owner_control_handshake_failed") from exc
    if not isinstance(document, Mapping):
        raise RuntimeOwnerVerificationError("runtime_owner_control_status_invalid")
    expected_fields = {
        "instance_id": descriptor.instance_id,
        "process_instance_id": descriptor.process_instance_id,
        "pid": descriptor.pid,
        "process_started_at": descriptor.process_started_at,
        "version": descriptor.version,
        "executable_path": descriptor.executable_path,
        "control_port": descriptor.control_port,
        "config_revision": descriptor.config_revision,
    }
    if any(document.get(name) != value for name, value in expected_fields.items()):
        raise RuntimeOwnerVerificationError("runtime_owner_control_identity_mismatch")
    return RuntimeOwnerVerification(descriptor, document)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_utc_timestamp(value: str, error: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(error) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(error)
    return parsed.astimezone(UTC)


def _timestamps_match(first: str, second: str) -> bool:
    try:
        left = _parse_utc_timestamp(first, "runtime_owner_process_time_invalid")
        right = _parse_utc_timestamp(second, "runtime_owner_process_time_invalid")
    except ValueError:
        return False
    return abs((left - right).total_seconds()) <= 1.0


def _text_sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_process_identity(pid: int) -> tuple[str, str] | None:
    if pid <= 0:
        return None
    if os.name != "nt":
        proc = Path("/proc") / str(pid)
        try:
            executable = os.readlink(proc / "exe")
            stat_fields = (proc / "stat").read_text(encoding="ascii").split()
            start_ticks = int(stat_fields[21])
            clock_ticks = os.sysconf("SC_CLK_TCK")
            boot_seconds = next(
                float(line.split()[1])
                for line in Path("/proc/stat").read_text(encoding="ascii").splitlines()
                if line.startswith("btime ")
            )
            started_at = datetime.fromtimestamp(
                boot_seconds + start_ticks / clock_ticks,
                UTC,
            ).isoformat()
            return executable, started_at
        except (OSError, ValueError, IndexError, StopIteration):
            return None
    try:
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return None
        try:
            capacity = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(capacity.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
                return None
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            started_at = datetime.fromtimestamp(
                ticks / 10_000_000 - 11_644_473_600,
                UTC,
            ).isoformat()
            return buffer.value, started_at
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None
