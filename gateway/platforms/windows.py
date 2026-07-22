from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Callable, Mapping
import uuid
import xml.etree.ElementTree as ElementTree


_VERSION_PATTERN = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
_TASK_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}")
_MUTEX_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_FORBIDDEN_ARGUMENT_PARTS = (
    "--api-key",
    "--authorization",
    "--bearer",
    "--cookie",
    "--password",
    "--secret",
    "--token",
)
_FORBIDDEN_ARGUMENT_VALUES = (
    "api-sk-",
    "bearer ",
    "sk-",
)
_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_ERROR_ALREADY_EXISTS = 183


class WindowsPlatformError(RuntimeError):
    pass


class ReleaseError(WindowsPlatformError):
    pass


class TaskDefinitionError(WindowsPlatformError):
    pass


class SingleInstanceError(WindowsPlatformError):
    pass


def _absolute_path(path: str | Path, error: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ValueError(error)
    return Path(os.path.abspath(candidate))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _require_within(path: str | Path, root: Path, error: str) -> Path:
    candidate = _absolute_path(path, error)
    if not _is_within(candidate, root):
        raise ValueError(error)
    return candidate


def _validate_version(version: str) -> str:
    if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("gateway_release_version_invalid")
    return version


@dataclass(frozen=True, slots=True)
class WindowsGatewayLayout:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", _absolute_path(self.root, "gateway_layout_root_must_be_absolute"))

    @property
    def gateway_root(self) -> Path:
        return self.root / "gateway"

    @property
    def versions(self) -> Path:
        return self.gateway_root / "versions"

    @property
    def current_pointer(self) -> Path:
        return self.gateway_root / "current.json"

    @property
    def config(self) -> Path:
        return self.gateway_root / "config"

    @property
    def state(self) -> Path:
        return self.gateway_root / "state"

    @property
    def logs(self) -> Path:
        return self.gateway_root / "logs"

    @property
    def spool(self) -> Path:
        return self.gateway_root / "spool"

    def release_path(self, version: str) -> Path:
        return self.versions / _validate_version(version)


@dataclass(frozen=True, slots=True)
class ReleasePointer:
    version: str
    relative_path: str
    manifest_sha256: str
    previous_version: str | None

    def __post_init__(self) -> None:
        _validate_version(self.version)
        if self.relative_path != f"gateway/versions/{self.version}":
            raise ValueError("gateway_release_pointer_path_invalid")
        if not isinstance(self.manifest_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", self.manifest_sha256) is None:
            raise ValueError("gateway_release_pointer_manifest_hash_invalid")
        if self.previous_version is not None:
            _validate_version(self.previous_version)
            if self.previous_version == self.version:
                raise ValueError("gateway_release_pointer_versions_equal")

    @property
    def active_version(self) -> str:
        return self.version

    def as_document(self) -> Mapping[str, object]:
        return {
            "schema_version": 1,
            "version": self.version,
            "relative_path": self.relative_path,
            "manifest_sha256": self.manifest_sha256,
            "previous_version": self.previous_version,
        }


@dataclass(frozen=True, slots=True)
class InstalledRelease:
    version: str
    path: Path
    content_sha256: str
    manifest_sha256: str


class VersionedReleaseStore:
    _MANIFEST_NAME = "manifest.json"

    def __init__(
        self,
        layout: WindowsGatewayLayout,
        *,
        transaction_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.layout = layout
        self._transaction_id_factory = transaction_id_factory or (lambda: uuid.uuid4().hex)

    def install(self, version: str, source: str | Path) -> InstalledRelease:
        version = _validate_version(version)
        source_path = _absolute_path(source, "gateway_release_source_must_be_absolute")
        if not source_path.is_dir():
            raise ReleaseError("gateway_release_source_missing")
        if _is_within(source_path, self.layout.versions) or _is_within(self.layout.versions, source_path):
            raise ReleaseError("gateway_release_source_overlaps_versions")
        self._reject_links(source_path)
        target = self.layout.release_path(version)
        if target.exists():
            raise ReleaseError("gateway_release_already_installed")
        try:
            self.layout.versions.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReleaseError("gateway_release_directory_failed") from exc
        transaction_id = self._transaction_id_factory()
        if not isinstance(transaction_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", transaction_id) is None:
            raise ReleaseError("gateway_release_transaction_id_invalid")
        temporary = self.layout.versions / f".{version}.{transaction_id}.tmp"
        if temporary.exists():
            raise ReleaseError("gateway_release_transaction_exists")
        content_hash = self._content_hash(source_path)
        manifest = {
            "schema_version": 1,
            "version": version,
            "content_sha256": content_hash,
            "transaction_id": transaction_id,
        }
        temporary_created = False
        try:
            temporary.mkdir()
            temporary_created = True
            shutil.copytree(
                source_path,
                temporary,
                copy_function=shutil.copy2,
                dirs_exist_ok=True,
                symlinks=True,
            )
            self._reject_links(temporary)
            if self._content_hash(temporary) != content_hash:
                raise ReleaseError("gateway_release_source_changed")
            self._atomic_write_json(temporary / self._MANIFEST_NAME, manifest)
            try:
                os.replace(temporary, target)
            except OSError as exc:
                if not self._release_matches(target, manifest):
                    raise ReleaseError("gateway_release_install_failed") from exc
            self._fsync_directory(self.layout.versions)
        except ReleaseError:
            raise
        except OSError as exc:
            raise ReleaseError("gateway_release_install_failed") from exc
        finally:
            if temporary_created:
                try:
                    shutil.rmtree(temporary)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
        return self.inspect(version)

    def activate(self, version: str) -> ReleasePointer:
        version = _validate_version(version)
        release = self.inspect(version)
        current = self.load_pointer()
        if current is not None and current.active_version == version:
            return current
        next_pointer = ReleasePointer(
            version=version,
            relative_path=self._relative_release_path(version),
            manifest_sha256=release.manifest_sha256,
            previous_version=current.active_version if current is not None else None,
        )
        return self.restore_pointer(next_pointer)

    def rollback(self) -> ReleasePointer:
        current = self.load_pointer()
        if current is None or current.previous_version is None:
            raise ReleaseError("gateway_release_rollback_unavailable")
        return self.activate(current.previous_version)

    def restore_pointer(self, pointer: ReleasePointer) -> ReleasePointer:
        if not isinstance(pointer, ReleasePointer):
            raise TypeError("gateway_release_pointer_required")
        active = self.inspect(pointer.version)
        if pointer.relative_path != self._relative_release_path(pointer.version):
            raise ReleaseError("gateway_release_pointer_invalid")
        if pointer.manifest_sha256 != active.manifest_sha256:
            raise ReleaseError("gateway_release_pointer_manifest_mismatch")
        if pointer.previous_version is not None:
            self.inspect(pointer.previous_version)
        self._atomic_write_json(self.layout.current_pointer, pointer.as_document())
        loaded = self.load_pointer()
        if loaded != pointer:
            raise ReleaseError("gateway_release_pointer_commit_uncertain")
        return pointer

    def load_pointer(self) -> ReleasePointer | None:
        path = self.layout.current_pointer
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ReleaseError("gateway_release_pointer_read_failed") from exc
        if len(payload) > 4096:
            raise ReleaseError("gateway_release_pointer_invalid")
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseError("gateway_release_pointer_invalid") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "version",
            "relative_path",
            "manifest_sha256",
            "previous_version",
        }:
            raise ReleaseError("gateway_release_pointer_invalid")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise ReleaseError("gateway_release_pointer_invalid")
        try:
            pointer = ReleasePointer(
                version=document["version"],
                relative_path=document["relative_path"],
                manifest_sha256=document["manifest_sha256"],
                previous_version=document["previous_version"],
            )
        except (TypeError, ValueError) as exc:
            raise ReleaseError("gateway_release_pointer_invalid") from exc
        active = self.inspect(pointer.active_version)
        if active.manifest_sha256 != pointer.manifest_sha256:
            raise ReleaseError("gateway_release_pointer_manifest_mismatch")
        if pointer.previous_version is not None:
            self.inspect(pointer.previous_version)
        return pointer

    def inspect(self, version: str) -> InstalledRelease:
        version = _validate_version(version)
        path = self.layout.release_path(version)
        manifest_path = path / self._MANIFEST_NAME
        try:
            payload = manifest_path.read_bytes()
            if len(payload) > 16 * 1024:
                raise ReleaseError("gateway_release_manifest_invalid")
            document = json.loads(payload.decode("utf-8"))
        except ReleaseError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseError("gateway_release_not_installed") from exc
        if not isinstance(document, dict):
            raise ReleaseError("gateway_release_manifest_invalid")
        expected = {"schema_version", "version", "content_sha256", "transaction_id"}
        if (
            set(document) != expected
            or type(document.get("schema_version")) is not int
            or document.get("schema_version") != 1
            or document.get("version") != version
        ):
            raise ReleaseError("gateway_release_manifest_invalid")
        content_hash = document.get("content_sha256")
        transaction_id = document.get("transaction_id")
        if not isinstance(content_hash, str) or re.fullmatch(r"[0-9a-f]{64}", content_hash) is None:
            raise ReleaseError("gateway_release_manifest_invalid")
        if not isinstance(transaction_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", transaction_id) is None:
            raise ReleaseError("gateway_release_manifest_invalid")
        self._reject_links(path)
        if self._content_hash(path, allow_manifest=True) != content_hash:
            raise ReleaseError("gateway_release_content_hash_mismatch")
        return InstalledRelease(
            version=version,
            path=path,
            content_sha256=content_hash,
            manifest_sha256=hashlib.sha256(payload).hexdigest(),
        )

    @staticmethod
    def _relative_release_path(version: str) -> str:
        return f"gateway/versions/{_validate_version(version)}"

    @staticmethod
    def _reject_links(root: Path) -> None:
        candidates = (root, *root.rglob("*"))
        for candidate in candidates:
            is_junction = getattr(candidate, "is_junction", lambda: False)
            if candidate.is_symlink() or is_junction():
                raise ReleaseError("gateway_release_links_forbidden")

    @classmethod
    def _content_hash(cls, root: Path, *, allow_manifest: bool = False) -> str:
        digest = hashlib.sha256()
        files = sorted(
            (path for path in root.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(root).as_posix(),
        )
        for path in files:
            relative = path.relative_to(root).as_posix()
            if relative == cls._MANIFEST_NAME:
                if allow_manifest:
                    continue
                raise ReleaseError("gateway_release_reserved_file")
            encoded = relative.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            size = path.stat().st_size
            digest.update(size.to_bytes(8, "big"))
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _release_matches(target: Path, manifest: Mapping[str, object]) -> bool:
        try:
            actual = json.loads((target / VersionedReleaseStore._MANIFEST_NAME).read_text(encoding="utf-8"))
            VersionedReleaseStore._reject_links(target)
            content_hash = VersionedReleaseStore._content_hash(target, allow_manifest=True)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReleaseError):
            return False
        return actual == manifest and content_hash == manifest.get("content_sha256")

    @staticmethod
    def _atomic_write_json(path: Path, document: Mapping[str, object]) -> None:
        try:
            payload = (
                json.dumps(
                    document,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ReleaseError("gateway_release_metadata_invalid") from exc
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReleaseError("gateway_release_metadata_directory_failed") from exc
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
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
            try:
                os.replace(temporary, path)
            except OSError as exc:
                try:
                    committed = path.read_bytes() == payload
                except OSError:
                    committed = False
                if not committed:
                    raise ReleaseError("gateway_release_pointer_commit_uncertain") from exc
            VersionedReleaseStore._fsync_directory(path.parent)
        except ReleaseError:
            raise
        except OSError as exc:
            raise ReleaseError("gateway_release_metadata_write_failed") from exc
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


def _safe_task_arguments(layout: WindowsGatewayLayout, config_file: Path) -> tuple[str, ...]:
    arguments = (
        "--layout-root",
        str(layout.root),
        "--config-file",
        str(config_file),
    )
    lowered = tuple(argument.lower() for argument in arguments)
    if any(any(part in argument for part in _FORBIDDEN_ARGUMENT_PARTS) for argument in lowered):
        raise TaskDefinitionError("gateway_task_secret_argument_forbidden")
    if any(any(value in argument for value in _FORBIDDEN_ARGUMENT_VALUES) for argument in lowered):
        raise TaskDefinitionError("gateway_task_secret_value_forbidden")
    if any("\x00" in argument or "\r" in argument or "\n" in argument for argument in arguments):
        raise TaskDefinitionError("gateway_task_argument_invalid")
    return arguments


@dataclass(frozen=True, slots=True)
class CurrentUserScheduledTask:
    task_name: str
    user_id: str
    supervisor_executable: Path
    layout: WindowsGatewayLayout
    config_file: Path

    def __post_init__(self) -> None:
        if not isinstance(self.task_name, str) or _TASK_NAME_PATTERN.fullmatch(self.task_name) is None:
            raise ValueError("gateway_task_name_invalid")
        if not isinstance(self.user_id, str) or not self.user_id.strip():
            raise ValueError("gateway_task_user_invalid")
        if any(character in self.user_id for character in ("\x00", "\r", "\n")):
            raise ValueError("gateway_task_user_invalid")
        supervisor = _require_within(
            self.supervisor_executable,
            self.layout.root,
            "gateway_task_supervisor_outside_layout",
        )
        config = _require_within(
            self.config_file,
            self.layout.config,
            "gateway_task_config_outside_layout",
        )
        object.__setattr__(self, "supervisor_executable", supervisor)
        object.__setattr__(self, "config_file", config)
        _safe_task_arguments(self.layout, config)

    @property
    def launch_argv(self) -> tuple[str, ...]:
        return (str(self.supervisor_executable), *_safe_task_arguments(self.layout, self.config_file))

    def render_xml(self) -> bytes:
        ElementTree.register_namespace("", _TASK_NAMESPACE)

        def element(parent: ElementTree.Element, name: str, text: str | None = None, **attributes: str) -> ElementTree.Element:
            child = ElementTree.SubElement(parent, f"{{{_TASK_NAMESPACE}}}{name}", attributes)
            child.text = text
            return child

        root = ElementTree.Element(f"{{{_TASK_NAMESPACE}}}Task", {"version": "1.4"})
        registration = element(root, "RegistrationInfo")
        element(registration, "Description", "Codex Profile Guardian user-level gateway supervisor")
        triggers = element(root, "Triggers")
        logon = element(triggers, "LogonTrigger")
        element(logon, "Enabled", "true")
        element(logon, "UserId", self.user_id)
        principals = element(root, "Principals")
        principal = element(principals, "Principal", id="CurrentUser")
        element(principal, "UserId", self.user_id)
        element(principal, "LogonType", "InteractiveToken")
        element(principal, "RunLevel", "LeastPrivilege")
        settings = element(root, "Settings")
        element(settings, "MultipleInstancesPolicy", "IgnoreNew")
        element(settings, "DisallowStartIfOnBatteries", "false")
        element(settings, "StopIfGoingOnBatteries", "false")
        element(settings, "AllowHardTerminate", "true")
        element(settings, "StartWhenAvailable", "true")
        element(settings, "RunOnlyIfNetworkAvailable", "false")
        element(settings, "AllowStartOnDemand", "true")
        element(settings, "Enabled", "true")
        element(settings, "Hidden", "true")
        element(settings, "ExecutionTimeLimit", "PT0S")
        actions = element(root, "Actions", Context="CurrentUser")
        execute = element(actions, "Exec")
        element(execute, "Command", str(self.supervisor_executable))
        element(execute, "Arguments", subprocess.list2cmdline(list(self.launch_argv[1:])))
        element(execute, "WorkingDirectory", str(self.layout.gateway_root))
        return ElementTree.tostring(root, encoding="utf-16", xml_declaration=True)

    def registration_command(self, definition_path: str | Path) -> tuple[str, ...]:
        definition = _absolute_path(definition_path, "gateway_task_definition_must_be_absolute")
        return (
            "schtasks.exe",
            "/Create",
            "/TN",
            self.task_name,
            "/XML",
            str(definition),
            "/F",
        )

    def query_command(self) -> tuple[str, ...]:
        return (
            "schtasks.exe",
            "/Query",
            "/TN",
            self.task_name,
            "/XML",
        )

    def removal_command(self) -> tuple[str, ...]:
        return ("schtasks.exe", "/Delete", "/TN", self.task_name, "/F")

    def write_fixture_definition(self, definitions_root: str | Path) -> Path:
        root = _require_within(
            definitions_root,
            self.layout.root,
            "gateway_task_definitions_outside_layout",
        )
        path = root / f"{self.task_name}.xml"
        payload = self.render_xml()
        try:
            root.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        except OSError as exc:
            raise TaskDefinitionError("gateway_task_definition_write_failed") from exc
        return path

    def remove_fixture_definition(self, definitions_root: str | Path) -> bool:
        root = _require_within(
            definitions_root,
            self.layout.root,
            "gateway_task_definitions_outside_layout",
        )
        path = root / f"{self.task_name}.xml"
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise TaskDefinitionError("gateway_task_definition_remove_failed") from exc


class WindowsSingleInstanceMutex:
    def __init__(self, instance_name: str) -> None:
        if not isinstance(instance_name, str) or _MUTEX_NAME_PATTERN.fullmatch(instance_name) is None:
            raise ValueError("gateway_mutex_name_invalid")
        self.name = f"Local\\CodexProfileGuardianGateway-{instance_name}"
        self._handle: int | None = None

    @property
    def acquired(self) -> bool:
        return self._handle is not None

    def acquire(self) -> None:
        if self._handle is not None:
            raise SingleInstanceError("gateway_mutex_already_acquired")
        if os.name != "nt":
            raise SingleInstanceError("gateway_mutex_windows_required")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_mutex = kernel32.CreateMutexW
        create_mutex.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
        create_mutex.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        handle = create_mutex(None, False, self.name)
        if not handle:
            raise SingleInstanceError("gateway_mutex_create_failed") from ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
            close_handle(handle)
            raise SingleInstanceError("gateway_instance_already_running")
        self._handle = int(handle)

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        if os.name != "nt":
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        if not close_handle(wintypes.HANDLE(handle)):
            raise SingleInstanceError("gateway_mutex_close_failed")

    def __enter__(self) -> WindowsSingleInstanceMutex:
        self.acquire()
        return self

    def __exit__(self, _exception_type, _exception, _traceback) -> None:
        self.release()
