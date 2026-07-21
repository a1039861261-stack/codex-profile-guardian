from __future__ import annotations

from collections.abc import Mapping
from collections.abc import Callable
from pathlib import Path
import os
import re
import stat


class InMemorySecretResolver:
    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    def resolve(self, secret_ref: str) -> str:
        value = self._values.get(secret_ref)
        if not value:
            raise RuntimeError("guardian_upstream_credential_unavailable")
        return value


class ProtectedFileSecretResolver:
    _REFERENCE = re.compile(
        r"\Aprofile:([a-zA-Z0-9][a-zA-Z0-9_-]{0,127})(?::(r[1-9][0-9]{0,18}))?\Z"
    )

    def __init__(self, directory: str | Path, *, unprotect: Callable[[bytes], bytes]) -> None:
        self.directory = Path(directory).resolve()
        self._unprotect = unprotect

    def resolve(self, secret_ref: str) -> str:
        match = self._REFERENCE.fullmatch(secret_ref)
        if match is None:
            raise RuntimeError("guardian_upstream_credential_unavailable")
        revision = match.group(2)
        filename = (
            f"{match.group(1)}.dpapi"
            if revision is None
            else f"{match.group(1)}.{revision}.dpapi"
        )
        target = (self.directory / filename).resolve()
        if target.parent != self.directory:
            raise RuntimeError("guardian_upstream_credential_unavailable")
        try:
            value = self._unprotect(target.read_bytes()).decode("utf-8")
        except Exception as exc:
            raise RuntimeError("guardian_upstream_credential_unavailable") from exc
        if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise RuntimeError("guardian_upstream_credential_unavailable")
        return value


class PosixFileSecretResolver:
    _REFERENCE = ProtectedFileSecretResolver._REFERENCE

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).resolve()

    def resolve(self, secret_ref: str) -> str:
        match = self._REFERENCE.fullmatch(secret_ref)
        if match is None:
            raise RuntimeError("guardian_upstream_credential_unavailable")
        revision = match.group(2)
        filename = (
            f"{match.group(1)}.key"
            if revision is None
            else f"{match.group(1)}.{revision}.key"
        )
        target = self.directory / filename
        try:
            if target.is_symlink() or target.resolve().parent != self.directory:
                raise OSError
            mode = stat.S_IMODE(os.stat(target, follow_symlinks=False).st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise OSError
            value = target.read_text(encoding="utf-8")
        except Exception as exc:
            raise RuntimeError("guardian_upstream_credential_unavailable") from exc
        if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise RuntimeError("guardian_upstream_credential_unavailable")
        return value
