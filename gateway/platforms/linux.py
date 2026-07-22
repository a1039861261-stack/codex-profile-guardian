from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Mapping
import uuid


_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}(?:\.r[1-9][0-9]{0,18})?")
_VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")


class LinuxPlatformError(RuntimeError):
    pass


def reject_link_chain(root: Path, target: Path) -> None:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(target))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise LinuxPlatformError("linux_gateway_path_outside_home") from exc
    current = root
    if current.is_symlink():
        raise LinuxPlatformError("linux_gateway_directory_link_forbidden")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise LinuxPlatformError("linux_gateway_directory_link_forbidden")


@dataclass(frozen=True, slots=True)
class LinuxGatewayLayout:
    home: Path

    def __post_init__(self) -> None:
        home = Path(self.home).expanduser()
        if not home.is_absolute():
            raise ValueError("linux_gateway_home_must_be_absolute")
        object.__setattr__(self, "home", Path(os.path.abspath(home)))

    @property
    def gateway_root(self) -> Path:
        return self.home / ".local" / "share" / "codex-profile-guardian-gateway"

    @property
    def versions(self) -> Path:
        return self.gateway_root / "versions"

    @property
    def current_pointer(self) -> Path:
        return self.gateway_root / "current.json"

    @property
    def config(self) -> Path:
        return self.home / ".config" / "codex-profile-guardian-gateway"

    @property
    def state(self) -> Path:
        return self.home / ".local" / "state" / "codex-profile-guardian-gateway"

    @property
    def logs(self) -> Path:
        return self.state / "logs"

    @property
    def spool(self) -> Path:
        return self.state / "spool"

    @property
    def secrets(self) -> Path:
        return self.config / "secrets"

    def release_path(self, version: str) -> Path:
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise ValueError("linux_gateway_version_invalid")
        return self.versions / version

    def ensure_private_directories(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        for path in (
            self.gateway_root,
            self.versions,
            self.config,
            self.secrets,
            self.state,
            self.logs,
            self.spool,
        ):
            reject_link_chain(self.home, path)
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            reject_link_chain(self.home, path)
            os.chmod(path, 0o700)


class StdinBundleApplier:
    def __init__(self, layout: LinuxGatewayLayout, *, max_bytes: int = 2 * 1024 * 1024) -> None:
        self.layout = layout
        self.max_bytes = max_bytes

    def apply(self, stream: BinaryIO) -> Mapping[str, object]:
        payload = stream.read(self.max_bytes + 1)
        if len(payload) > self.max_bytes:
            raise LinuxPlatformError("linux_gateway_bundle_too_large")
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LinuxPlatformError("linux_gateway_bundle_invalid") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "config",
            "secrets",
        } or document.get("schema_version") != 1:
            raise LinuxPlatformError("linux_gateway_bundle_invalid")
        config = document.get("config")
        secrets = document.get("secrets")
        if not isinstance(config, dict) or not isinstance(secrets, dict):
            raise LinuxPlatformError("linux_gateway_bundle_invalid")
        self.layout.ensure_private_directories()
        config_payload = (json.dumps(config, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        staged: list[tuple[Path, bytes]] = [(self.layout.config / "active.json", config_payload)]
        for name, value in secrets.items():
            if not isinstance(name, str) or _PROFILE.fullmatch(name) is None or not isinstance(value, str):
                raise LinuxPlatformError("linux_gateway_bundle_secret_invalid")
            if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
                raise LinuxPlatformError("linux_gateway_bundle_secret_invalid")
            staged.append((self.layout.secrets / f"{name}.key", value.encode("utf-8")))
        temporaries: list[tuple[Path, Path]] = []
        backups: dict[Path, bytes | None] = {}
        committed: list[Path] = []
        try:
            for target, content in staged:
                if target.is_symlink():
                    raise LinuxPlatformError("linux_gateway_target_link_forbidden")
                temporary = target.parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
                descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, 0o600)
                temporaries.append((temporary, target))
            for temporary, target in temporaries:
                if target.exists():
                    backups[target] = target.read_bytes()
                else:
                    backups[target] = None
                os.replace(temporary, target)
                committed.append(target)
                os.chmod(target, 0o600)
            return {
                "ok": True,
                "config_sha256": hashlib.sha256(config_payload).hexdigest(),
                "secret_count": len(secrets),
            }
        except Exception as exc:
            recovery_ok = True
            for target in reversed(committed):
                backup = backups.get(target)
                try:
                    if backup is None:
                        target.unlink(missing_ok=True)
                    else:
                        self._restore(target, backup)
                except OSError:
                    recovery_ok = False
            if not recovery_ok:
                raise LinuxPlatformError("linux_gateway_bundle_recovery_failed") from exc
            if isinstance(exc, LinuxPlatformError):
                raise
            raise LinuxPlatformError("linux_gateway_bundle_write_failed") from exc
        finally:
            for temporary, _target in temporaries:
                try:
                    temporary.unlink()
                except OSError:
                    pass

    @staticmethod
    def _restore(target: Path, content: bytes) -> None:
        temporary = target.parent / f".{target.name}.{uuid.uuid4().hex}.restore"
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class SystemdUserUnit:
    executable: Path
    install_root: Path
    config_path: Path

    def render(self) -> str:
        executable = self._quote(self.executable)
        config = self._quote(self.config_path)
        install_root = self._quote(self.install_root)
        home = self._quote(self.install_root.parent.parent.parent)
        for value in (executable, install_root, config, home):
            lowered = value.lower()
            if any(token in lowered for token in ("bearer ", "--token", "--secret", "--api-key")) or "\n" in value:
                raise LinuxPlatformError("linux_gateway_unit_argument_invalid")
        return (
            "[Unit]\nDescription=Codex Profile Guardian Gateway\nAfter=network-online.target\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={executable} --install-root {install_root} --config {config} "
            f"--platform linux --home {home}\n"
            "Restart=on-failure\nRestartSec=5s\nStartLimitIntervalSec=300\nStartLimitBurst=5\n"
            "NoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n\n"
            "[Install]\nWantedBy=default.target\n"
        )

    @staticmethod
    def _quote(value: Path) -> str:
        text = str(value)
        if any(character in text for character in ("\x00", "\r", "\n", "%")):
            raise LinuxPlatformError("linux_gateway_unit_argument_invalid")
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


__all__ = [
    "LinuxGatewayLayout",
    "LinuxPlatformError",
    "StdinBundleApplier",
    "SystemdUserUnit",
    "reject_link_chain",
]
