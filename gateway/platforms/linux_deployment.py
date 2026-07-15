from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
import hashlib
import datetime as dt
import inspect
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
from typing import TypeAlias
import uuid

from .linux import (
    LinuxGatewayLayout,
    LinuxPlatformError,
    StdinBundleApplier,
    SystemdUserUnit,
    reject_link_chain,
)
from ..lifecycle_config import ActiveConfigError, parse_active_config


_VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
_ARCHITECTURES = {"x86_64", "aarch64"}
_PACKAGE_MODES = {"locked_venv"}
_HASH = re.compile(r"[0-9a-f]{64}")
_TRANSACTION = re.compile(r"[A-Za-z0-9_-]{8,128}")


class LinuxReleaseError(LinuxPlatformError):
    pass


class LinuxDeploymentError(RuntimeError):
    def __init__(self, code: str, *, recovered: bool, cause: BaseException | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.recovered = recovered
        if cause is not None:
            self.__cause__ = cause


@dataclass(frozen=True, slots=True)
class LinuxInstalledRelease:
    version: str
    architecture: str
    package_mode: str
    path: Path
    content_sha256: str
    manifest_sha256: str
    entrypoint: str


@dataclass(frozen=True, slots=True)
class LinuxReleasePointer:
    version: str
    relative_path: str
    manifest_sha256: str
    previous_version: str | None

    def __post_init__(self) -> None:
        _validate_version(self.version)
        if self.relative_path != f"versions/{self.version}":
            raise ValueError("linux_release_pointer_path_invalid")
        if not isinstance(self.manifest_sha256, str) or _HASH.fullmatch(self.manifest_sha256) is None:
            raise ValueError("linux_release_pointer_hash_invalid")
        if self.previous_version is not None:
            _validate_version(self.previous_version)
            if self.previous_version == self.version:
                raise ValueError("linux_release_pointer_versions_equal")

    def as_document(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "version": self.version,
            "relative_path": self.relative_path,
            "manifest_sha256": self.manifest_sha256,
            "previous_version": self.previous_version,
        }


@dataclass(frozen=True, slots=True)
class LinuxDeploymentBundle:
    config: Mapping[str, object]
    secrets: Mapping[str, str]

    def payload(self) -> bytes:
        document = {
            "schema_version": 1,
            "config": dict(self.config),
            "secrets": dict(self.secrets),
        }
        try:
            payload = json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise LinuxDeploymentError("linux_deployment_bundle_invalid", recovered=True, cause=exc) from exc
        if len(payload) > 2 * 1024 * 1024:
            raise LinuxDeploymentError("linux_deployment_bundle_too_large", recovered=True)
        return payload

    def validate_for_release(self, release: LinuxInstalledRelease) -> None:
        if not isinstance(release, LinuxInstalledRelease):
            raise TypeError("linux_deployment_release_required")
        try:
            parsed = parse_active_config(
                self.config,
                object(),
                runner_factory=lambda _route, _role, _limits: object(),
            )
        except (ActiveConfigError, TypeError, ValueError) as exc:
            raise LinuxDeploymentError(
                "linux_deployment_config_invalid",
                recovered=True,
                cause=exc,
            ) from exc
        if parsed.version != release.version:
            raise LinuxDeploymentError(
                "linux_deployment_config_version_mismatch",
                recovered=True,
            )
        expected = set(self.secrets)
        referenced: set[str] = set()
        for route in (parsed.active_group.primary, parsed.active_group.backup):
            match = re.fullmatch(
                r"profile:([A-Za-z0-9][A-Za-z0-9_-]{0,127})(?::(r[1-9][0-9]{0,18}))?",
                route.secret_ref,
            )
            if match is None:
                raise LinuxDeploymentError(
                    "linux_deployment_secret_ref_invalid",
                    recovered=True,
                )
            referenced.add(match.group(1) + (f".{match.group(2)}" if match.group(2) else ""))
        if referenced != expected:
            raise LinuxDeploymentError(
                "linux_deployment_secret_set_mismatch",
                recovered=True,
            )


@dataclass(frozen=True, slots=True)
class LinuxDeploymentPlan:
    architecture: str
    package_mode: str
    supervisor: str

    def __post_init__(self) -> None:
        _validate_architecture(self.architecture)
        _validate_package_mode(self.package_mode)
        if self.supervisor not in {"systemd_user", "cron_user"}:
            raise ValueError("linux_deployment_supervisor_invalid")


class LinuxVersionedReleaseStore:
    def __init__(
        self,
        layout: LinuxGatewayLayout,
        *,
        max_files: int = 512,
        max_total_bytes: int = 64 * 1024 * 1024,
        transaction_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(layout, LinuxGatewayLayout):
            raise TypeError("linux_release_layout_required")
        if max_files < 1 or max_total_bytes < 1:
            raise ValueError("linux_release_limits_invalid")
        self.layout = layout
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self._transaction_id_factory = transaction_id_factory or (lambda: uuid.uuid4().hex)

    def install(
        self,
        version: str,
        source: str | Path,
        *,
        architecture: str,
        package_mode: str = "locked_venv",
        entrypoint: str = "bin/guardian-gateway",
    ) -> LinuxInstalledRelease:
        version = _validate_version(version)
        architecture = _validate_architecture(architecture)
        package_mode = _validate_package_mode(package_mode)
        entrypoint = _validate_relative_path(entrypoint, "linux_release_entrypoint_invalid")
        source_path = Path(source).expanduser()
        if not source_path.is_absolute() or not source_path.is_dir():
            raise LinuxReleaseError("linux_release_source_missing")
        source_path = Path(os.path.abspath(source_path))
        if _overlaps(source_path, self.layout.versions):
            raise LinuxReleaseError("linux_release_source_overlaps_versions")
        source_entries = self._inventory(source_path, entrypoint=entrypoint)
        if entrypoint not in {item["path"] for item in source_entries}:
            raise LinuxReleaseError("linux_release_entrypoint_missing")
        target = self.layout.release_path(version)
        if target.exists() or target.is_symlink():
            raise LinuxReleaseError("linux_release_already_installed")
        transaction_id = self._transaction_id_factory()
        if not isinstance(transaction_id, str) or _TRANSACTION.fullmatch(transaction_id) is None:
            raise LinuxReleaseError("linux_release_transaction_invalid")
        self.layout.ensure_private_directories()
        temporary = self.layout.versions / f".{version}.{transaction_id}.tmp"
        if temporary.exists() or temporary.is_symlink():
            raise LinuxReleaseError("linux_release_transaction_exists")
        manifest = {
            "schema_version": 1,
            "version": version,
            "architecture": architecture,
            "package_mode": package_mode,
            "entrypoint": entrypoint,
            "transaction_id": transaction_id,
            "content_sha256": _inventory_hash(source_entries),
            "files": source_entries,
        }
        try:
            temporary.mkdir(mode=0o700)
            for item in source_entries:
                relative = PurePosixPath(str(item["path"]))
                source_file = source_path.joinpath(*relative.parts)
                target_file = temporary.joinpath(*relative.parts)
                target_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _reject_link(target_file.parent)
                with source_file.open("rb") as input_stream:
                    descriptor = os.open(target_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, int(item["mode"]))
                    with os.fdopen(descriptor, "wb") as output_stream:
                        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
                        output_stream.flush()
                        os.fsync(output_stream.fileno())
                os.chmod(target_file, int(item["mode"]))
            _atomic_write_json(temporary / "manifest.json", manifest, mode=0o600)
            if self._inventory(temporary, entrypoint=entrypoint, allow_manifest=True) != source_entries:
                raise LinuxReleaseError("linux_release_copy_mismatch")
            os.replace(temporary, target)
            _fsync_directory(self.layout.versions)
        except LinuxReleaseError:
            raise
        except OSError as exc:
            raise LinuxReleaseError("linux_release_install_failed") from exc
        finally:
            try:
                shutil.rmtree(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        return self.inspect(version)

    def inspect(self, version: str) -> LinuxInstalledRelease:
        version = _validate_version(version)
        path = self.layout.release_path(version)
        manifest_path = path / "manifest.json"
        try:
            payload = manifest_path.read_bytes()
            if len(payload) > 128 * 1024:
                raise LinuxReleaseError("linux_release_manifest_invalid")
            document = json.loads(payload.decode("utf-8"))
        except LinuxReleaseError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LinuxReleaseError("linux_release_not_installed") from exc
        expected = {
            "schema_version",
            "version",
            "architecture",
            "package_mode",
            "entrypoint",
            "transaction_id",
            "content_sha256",
            "files",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise LinuxReleaseError("linux_release_manifest_invalid")
        if document.get("schema_version") != 1 or document.get("version") != version:
            raise LinuxReleaseError("linux_release_manifest_invalid")
        architecture = _validate_architecture(document.get("architecture"))
        package_mode = _validate_package_mode(document.get("package_mode"))
        entrypoint = _validate_relative_path(document.get("entrypoint"), "linux_release_manifest_invalid")
        transaction_id = document.get("transaction_id")
        content_hash = document.get("content_sha256")
        files = document.get("files")
        if not isinstance(transaction_id, str) or _TRANSACTION.fullmatch(transaction_id) is None:
            raise LinuxReleaseError("linux_release_manifest_invalid")
        if not isinstance(content_hash, str) or _HASH.fullmatch(content_hash) is None:
            raise LinuxReleaseError("linux_release_manifest_invalid")
        normalized = self._validate_manifest_files(files, entrypoint=entrypoint)
        actual = self._inventory(path, entrypoint=entrypoint, allow_manifest=True)
        if normalized != actual or _inventory_hash(actual) != content_hash:
            raise LinuxReleaseError("linux_release_content_mismatch")
        return LinuxInstalledRelease(
            version=version,
            architecture=architecture,
            package_mode=package_mode,
            path=path,
            content_sha256=content_hash,
            manifest_sha256=hashlib.sha256(payload).hexdigest(),
            entrypoint=entrypoint,
        )

    def activate(self, version: str) -> LinuxReleasePointer:
        release = self.inspect(version)
        current = self.load_pointer()
        if current is not None and current.version == version:
            return current
        pointer = LinuxReleasePointer(
            version=version,
            relative_path=f"versions/{version}",
            manifest_sha256=release.manifest_sha256,
            previous_version=current.version if current is not None else None,
        )
        return self.restore_pointer(pointer)

    def restore_pointer(self, pointer: LinuxReleasePointer | None) -> LinuxReleasePointer | None:
        if pointer is None:
            path = self.layout.current_pointer
            if path.is_symlink():
                raise LinuxReleaseError("linux_release_pointer_link_forbidden")
            path.unlink(missing_ok=True)
            return None
        if not isinstance(pointer, LinuxReleasePointer):
            raise TypeError("linux_release_pointer_required")
        release = self.inspect(pointer.version)
        if release.manifest_sha256 != pointer.manifest_sha256:
            raise LinuxReleaseError("linux_release_pointer_manifest_mismatch")
        if pointer.previous_version is not None:
            self.inspect(pointer.previous_version)
        _atomic_write_json(self.layout.current_pointer, pointer.as_document(), mode=0o600)
        loaded = self.load_pointer()
        if loaded != pointer:
            raise LinuxReleaseError("linux_release_pointer_commit_uncertain")
        return loaded

    def load_pointer(self) -> LinuxReleasePointer | None:
        path = self.layout.current_pointer
        if path.is_symlink():
            raise LinuxReleaseError("linux_release_pointer_link_forbidden")
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise LinuxReleaseError("linux_release_pointer_read_failed") from exc
        if len(payload) > 4096:
            raise LinuxReleaseError("linux_release_pointer_invalid")
        try:
            document = json.loads(payload.decode("utf-8"))
            if not isinstance(document, dict) or set(document) != {
                "schema_version",
                "version",
                "relative_path",
                "manifest_sha256",
                "previous_version",
            } or document.get("schema_version") != 1:
                raise ValueError
            pointer = LinuxReleasePointer(
                version=document["version"],
                relative_path=document["relative_path"],
                manifest_sha256=document["manifest_sha256"],
                previous_version=document["previous_version"],
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise LinuxReleaseError("linux_release_pointer_invalid") from exc
        release = self.inspect(pointer.version)
        if release.manifest_sha256 != pointer.manifest_sha256:
            raise LinuxReleaseError("linux_release_pointer_manifest_mismatch")
        if pointer.previous_version is not None:
            self.inspect(pointer.previous_version)
        return pointer

    def _inventory(
        self,
        root: Path,
        *,
        entrypoint: str,
        allow_manifest: bool = False,
    ) -> list[dict[str, object]]:
        if root.is_symlink():
            raise LinuxReleaseError("linux_release_link_forbidden")
        entries: list[dict[str, object]] = []
        total = 0
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise LinuxReleaseError("linux_release_link_forbidden")
            if path.is_dir():
                continue
            if not path.is_file():
                raise LinuxReleaseError("linux_release_special_file_forbidden")
            relative = path.relative_to(root).as_posix()
            if allow_manifest and relative == "manifest.json":
                continue
            relative = _validate_relative_path(relative, "linux_release_path_invalid")
            size = path.stat().st_size
            total += size
            if len(entries) >= self.max_files or total > self.max_total_bytes:
                raise LinuxReleaseError("linux_release_limits_exceeded")
            mode = _release_file_mode(relative, entrypoint=entrypoint)
            if allow_manifest and os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != mode:
                raise LinuxReleaseError("linux_release_permissions_invalid")
            entries.append(
                {
                    "path": relative,
                    "size": size,
                    "sha256": _file_hash(path),
                    "mode": mode,
                }
            )
        return entries

    def _validate_manifest_files(self, value: object, *, entrypoint: str) -> list[dict[str, object]]:
        if not isinstance(value, list) or len(value) > self.max_files:
            raise LinuxReleaseError("linux_release_manifest_invalid")
        normalized: list[dict[str, object]] = []
        seen: set[str] = set()
        total = 0
        for item in value:
            if not isinstance(item, dict) or set(item) != {"path", "size", "sha256", "mode"}:
                raise LinuxReleaseError("linux_release_manifest_invalid")
            relative = _validate_relative_path(item.get("path"), "linux_release_manifest_invalid")
            size = item.get("size")
            digest = item.get("sha256")
            mode = item.get("mode")
            expected_mode = _release_file_mode(relative, entrypoint=entrypoint)
            if relative in seen or type(size) is not int or size < 0:
                raise LinuxReleaseError("linux_release_manifest_invalid")
            if not isinstance(digest, str) or _HASH.fullmatch(digest) is None or mode != expected_mode:
                raise LinuxReleaseError("linux_release_manifest_invalid")
            seen.add(relative)
            total += size
            if total > self.max_total_bytes:
                raise LinuxReleaseError("linux_release_limits_exceeded")
            normalized.append({"path": relative, "size": size, "sha256": digest, "mode": mode})
        normalized.sort(key=lambda item: str(item["path"]))
        if entrypoint not in seen:
            raise LinuxReleaseError("linux_release_manifest_invalid")
        return normalized


CallbackResult: TypeAlias = bool | Mapping[str, object] | None
ReleaseCallback: TypeAlias = Callable[[LinuxInstalledRelease], CallbackResult | Awaitable[CallbackResult]]


@dataclass(slots=True)
class _FileSnapshot:
    path: Path
    existed: bool
    content: bytearray
    mode: int

    def wipe(self) -> None:
        for index in range(len(self.content)):
            self.content[index] = 0


@dataclass(frozen=True, slots=True)
class LinuxDeploymentResult:
    previous_version: str | None
    active_version: str
    content_sha256: str
    manifest_sha256: str
    config_sha256: str


class LinuxGatewayDeploymentManager:
    def __init__(
        self,
        store: LinuxVersionedReleaseStore,
        *,
        unit_path: Path,
        drain: ReleaseCallback,
        stop: ReleaseCallback,
        start: ReleaseCallback,
        verify_health: ReleaseCallback,
        wall_clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        if not isinstance(store, LinuxVersionedReleaseStore):
            raise TypeError("linux_deployment_store_required")
        if not Path(unit_path).is_absolute():
            raise ValueError("linux_deployment_unit_path_invalid")
        expected_unit = store.layout.home / ".config" / "systemd" / "user" / "codex-profile-guardian-gateway.service"
        if Path(os.path.abspath(unit_path)) != Path(os.path.abspath(expected_unit)):
            raise ValueError("linux_deployment_unit_path_invalid")
        if not all(callable(callback) for callback in (drain, stop, start, verify_health)):
            raise TypeError("linux_deployment_callback_required")
        self.store = store
        self.layout = store.layout
        self.unit_path = Path(os.path.abspath(unit_path))
        self.drain = drain
        self.stop = stop
        self.start = start
        self.verify_health = verify_health
        self.wall_clock = wall_clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._lock = asyncio.Lock()

    @property
    def state_uncertain_path(self) -> Path:
        return self.layout.state / "deployment.state-uncertain.json"

    async def deploy(
        self,
        version: str,
        source: str | Path,
        *,
        architecture: str,
        bundle: LinuxDeploymentBundle,
        plan: LinuxDeploymentPlan,
    ) -> LinuxDeploymentResult:
        async with self._lock:
            return await self._deploy_locked(
                version,
                source,
                architecture=architecture,
                bundle=bundle,
                plan=plan,
            )

    async def _deploy_locked(
        self,
        version: str,
        source: str | Path,
        *,
        architecture: str,
        bundle: LinuxDeploymentBundle,
        plan: LinuxDeploymentPlan,
    ) -> LinuxDeploymentResult:
        if self.state_uncertain_path.exists() or self.state_uncertain_path.is_symlink():
            raise LinuxDeploymentError("linux_deployment_state_uncertain_locked", recovered=False)
        if not isinstance(plan, LinuxDeploymentPlan):
            raise LinuxDeploymentError("linux_deployment_plan_invalid", recovered=True)
        if plan.architecture != architecture:
            raise LinuxDeploymentError("linux_deployment_architecture_mismatch", recovered=True)
        payload = bundle.payload()
        try:
            previous_pointer = self.store.load_pointer()
            previous_release = self.store.inspect(previous_pointer.version) if previous_pointer else None
            installed = self.store.install(
                version,
                source,
                architecture=architecture,
                package_mode=plan.package_mode,
            )
            bundle.validate_for_release(installed)
            secret_names = self._secret_names(payload)
            snapshot_paths = [self.layout.config / "active.json", self.unit_path]
            snapshot_paths.extend(self.layout.secrets / f"{name}.key" for name in secret_names)
            snapshots = [self._snapshot(path) for path in snapshot_paths]
        except LinuxDeploymentError:
            raise
        except Exception as exc:
            raise LinuxDeploymentError("linux_deployment_prepare_failed", recovered=True, cause=exc) from exc
        activated = False
        stopped = False
        try:
            if previous_release is not None:
                await self._invoke(self.drain, previous_release, "linux_deployment_drain_failed")
                await self._invoke(self.stop, previous_release, "linux_deployment_stop_failed")
                stopped = True
            applied = StdinBundleApplier(self.layout).apply(io.BytesIO(payload))
            unit = SystemdUserUnit(
                executable=installed.path / installed.entrypoint,
                install_root=self.layout.gateway_root,
                config_path=self.layout.config / "active.json",
            ).render()
            _atomic_write(self.unit_path, unit.encode("utf-8"), mode=0o600)
            self.store.activate(installed.version)
            activated = True
            await self._invoke(self.start, installed, "linux_deployment_start_failed")
            await self._invoke(self.verify_health, installed, "linux_deployment_health_failed")
            return LinuxDeploymentResult(
                previous_version=previous_release.version if previous_release else None,
                active_version=installed.version,
                content_sha256=installed.content_sha256,
                manifest_sha256=installed.manifest_sha256,
                config_sha256=str(applied["config_sha256"]),
            )
        except BaseException as exc:
            recovered = await self._recover(
                previous_pointer,
                previous_release,
                installed,
                snapshots,
                activated=activated,
                stopped=stopped,
            )
            if not recovered:
                self._mark_state_uncertain()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, LinuxDeploymentError):
                raise LinuxDeploymentError(exc.code, recovered=recovered, cause=exc.__cause__ or exc) from exc
            raise LinuxDeploymentError("linux_deployment_failed", recovered=recovered, cause=exc) from exc
        finally:
            for snapshot in snapshots:
                snapshot.wipe()

    async def _recover(
        self,
        previous_pointer: LinuxReleasePointer | None,
        previous_release: LinuxInstalledRelease | None,
        installed: LinuxInstalledRelease,
        snapshots: list[_FileSnapshot],
        *,
        activated: bool,
        stopped: bool,
    ) -> bool:
        try:
            if activated:
                try:
                    await self._invoke(self.stop, installed, "linux_deployment_recovery_stop_failed")
                except BaseException:
                    return False
            for snapshot in reversed(snapshots):
                self._restore(snapshot)
            self.store.restore_pointer(previous_pointer)
            if previous_release is not None and (stopped or activated):
                await self._invoke(self.start, previous_release, "linux_deployment_recovery_start_failed")
                await self._invoke(
                    self.verify_health,
                    previous_release,
                    "linux_deployment_recovery_health_failed",
                )
            return self.store.load_pointer() == previous_pointer
        except BaseException:
            return False

    async def _invoke(self, callback: ReleaseCallback, release: LinuxInstalledRelease, code: str) -> None:
        try:
            result = callback(release)
            if inspect.isawaitable(result):
                result = await result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise LinuxDeploymentError(code, recovered=False, cause=exc) from exc
        if result is False or isinstance(result, Mapping) and result.get("ok") is not True:
            raise LinuxDeploymentError(code, recovered=False)

    @staticmethod
    def _secret_names(payload: bytes) -> tuple[str, ...]:
        try:
            document = json.loads(payload.decode("utf-8"))
            names = tuple(sorted(document["secrets"]))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LinuxDeploymentError("linux_deployment_bundle_invalid", recovered=True, cause=exc) from exc
        return names

    @staticmethod
    def _snapshot(path: Path) -> _FileSnapshot:
        if path.is_symlink():
            raise LinuxDeploymentError("linux_deployment_target_link_forbidden", recovered=True)
        try:
            content = bytearray(path.read_bytes())
            mode = stat.S_IMODE(path.stat().st_mode)
            return _FileSnapshot(path=path, existed=True, content=content, mode=mode)
        except FileNotFoundError:
            return _FileSnapshot(path=path, existed=False, content=bytearray(), mode=0o600)
        except OSError as exc:
            raise LinuxDeploymentError("linux_deployment_snapshot_failed", recovered=True, cause=exc) from exc

    @staticmethod
    def _restore(snapshot: _FileSnapshot) -> None:
        if snapshot.path.is_symlink():
            raise LinuxDeploymentError("linux_deployment_recovery_link_forbidden", recovered=False)
        if snapshot.existed:
            _atomic_write(snapshot.path, bytes(snapshot.content), mode=snapshot.mode)
        else:
            snapshot.path.unlink(missing_ok=True)

    def _mark_state_uncertain(self) -> None:
        document = {
            "schema_version": 1,
            "error_code": "linux_deployment_state_uncertain",
            "recorded_at": self.wall_clock().astimezone(dt.timezone.utc).isoformat(),
        }
        try:
            reject_link_chain(self.layout.home, self.state_uncertain_path.parent)
            _atomic_write_json(self.state_uncertain_path, document, mode=0o600)
        except Exception:
            pass


def _validate_version(value: object) -> str:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise LinuxReleaseError("linux_release_version_invalid")
    return value


def _validate_architecture(value: object) -> str:
    if value not in _ARCHITECTURES:
        raise LinuxReleaseError("linux_release_architecture_invalid")
    return str(value)


def _validate_package_mode(value: object) -> str:
    if value not in _PACKAGE_MODES:
        raise LinuxReleaseError("linux_release_package_mode_invalid")
    return str(value)


def _validate_relative_path(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(character) < 0x20 for character in value):
        raise LinuxReleaseError(code)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise LinuxReleaseError(code)
    normalized = path.as_posix()
    if normalized == "manifest.json" or len(normalized) > 240:
        raise LinuxReleaseError(code)
    return normalized


def _overlaps(left: Path, right: Path) -> bool:
    left = Path(os.path.abspath(left))
    right = Path(os.path.abspath(right))
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _reject_link(path: Path) -> None:
    if path.is_symlink():
        raise LinuxReleaseError("linux_release_link_forbidden")


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _release_file_mode(relative: str, *, entrypoint: str) -> int:
    executable_paths = {entrypoint, "bin/guardian-gateway-supervisor"}
    return 0o700 if relative in executable_paths else 0o600


def _inventory_hash(entries: list[dict[str, object]]) -> str:
    canonical = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _atomic_write_json(path: Path, document: Mapping[str, object], *, mode: int) -> None:
    payload = (json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _atomic_write(path, payload, mode=mode)


def _atomic_write(path: Path, content: bytes, *, mode: int) -> None:
    if path.is_symlink():
        raise LinuxReleaseError("linux_release_target_link_forbidden")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_link(path.parent)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "LinuxDeploymentBundle",
    "LinuxDeploymentError",
    "LinuxDeploymentResult",
    "LinuxDeploymentPlan",
    "LinuxGatewayDeploymentManager",
    "LinuxInstalledRelease",
    "LinuxReleaseError",
    "LinuxReleasePointer",
    "LinuxVersionedReleaseStore",
]
