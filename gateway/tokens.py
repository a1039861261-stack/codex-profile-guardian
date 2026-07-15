from __future__ import annotations

from collections.abc import Callable, Mapping
import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat


class TokenStoreError(RuntimeError):
    pass


class ProtectedTokenStore:
    def __init__(
        self,
        directory: str | Path,
        *,
        protect: Callable[[bytes], bytes],
        unprotect: Callable[[bytes], bytes],
    ) -> None:
        self.directory = Path(directory)
        self._protect = protect
        self._unprotect = unprotect

    def ensure(self) -> Mapping[str, str]:
        values = {
            purpose: self._read_or_create(purpose)
            for purpose in ("ingress", "control")
        }
        if hmac.compare_digest(values["ingress"], values["control"]):
            raise TokenStoreError("gateway_tokens_must_be_distinct")
        return values

    def rotate(self, purpose: str) -> str:
        self._validate_purpose(purpose)
        value = self._new_token()
        self._write(purpose, value)
        return value

    def read_existing(self, purpose: str) -> str:
        """Read an existing token without creating or rotating it."""
        return self._read(purpose)

    def fingerprint(self, purpose: str) -> str:
        value = self._read(purpose)
        return hashlib.sha256(value.encode("ascii")).hexdigest()

    def _read_or_create(self, purpose: str) -> str:
        try:
            return self._read(purpose)
        except FileNotFoundError:
            value = self._new_token()
            self._write(purpose, value)
            return value

    def _read(self, purpose: str) -> str:
        self._validate_purpose(purpose)
        try:
            protected = self._path(purpose).read_bytes()
            raw = self._unprotect(protected)
            value = raw.decode("ascii")
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise TokenStoreError("gateway_token_unprotect_failed") from exc
        self._validate_token(value)
        return value

    def _write(self, purpose: str, value: str) -> None:
        self._validate_token(value)
        try:
            protected = self._protect(value.encode("ascii"))
        except Exception as exc:
            raise TokenStoreError("gateway_token_protect_failed") from exc
        if value.encode("ascii") in protected:
            raise TokenStoreError("gateway_token_protection_is_plaintext")
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, stat.S_IRWXU)
        except OSError:
            pass
        target = self._path(purpose)
        temporary = target.with_suffix(f".{secrets.token_hex(8)}.tmp")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(protected)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise TokenStoreError("gateway_token_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _path(self, purpose: str) -> Path:
        return self.directory / f"{purpose}.token.dpapi"

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def _validate_purpose(purpose: str) -> None:
        if purpose not in {"ingress", "control"}:
            raise ValueError("gateway_token_purpose_invalid")

    @staticmethod
    def _validate_token(value: str) -> None:
        if not 48 <= len(value) <= 256:
            raise TokenStoreError("gateway_token_length_invalid")
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, TypeError) as exc:
            raise TokenStoreError("gateway_token_format_invalid") from exc
        if len(decoded) < 32:
            raise TokenStoreError("gateway_token_entropy_invalid")


class PosixTokenStore(ProtectedTokenStore):
    def __init__(self, directory: str | Path) -> None:
        super().__init__(directory, protect=lambda payload: payload, unprotect=lambda payload: payload)

    def _read(self, purpose: str) -> str:
        self._validate_purpose(purpose)
        target = self._path(purpose)
        try:
            if target.is_symlink() or stat.S_IMODE(os.stat(target, follow_symlinks=False).st_mode) & (
                stat.S_IRWXG | stat.S_IRWXO
            ):
                raise OSError
            value = target.read_text(encoding="ascii")
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise TokenStoreError("gateway_token_read_failed") from exc
        self._validate_token(value)
        return value

    def _write(self, purpose: str, value: str) -> None:
        self._validate_token(value)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        target = self._path(purpose)
        temporary = target.with_suffix(f".{secrets.token_hex(8)}.tmp")
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(value.encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        except OSError as exc:
            raise TokenStoreError("gateway_token_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except OSError:
                pass

    def _path(self, purpose: str) -> Path:
        return self.directory / f"{purpose}.token"


def read_gateway_token(
    install_root: str | Path,
    purpose: str,
    *,
    unprotect: Callable[[bytes], bytes],
) -> str:
    """Resolve one existing Gateway token without creating or rotating it."""
    store = ProtectedTokenStore(
        Path(install_root).resolve() / "gateway" / "secrets" / "tokens",
        protect=lambda _payload: b"",
        unprotect=unprotect,
    )
    return store.read_existing(purpose)


def read_gateway_ingress_token(
    install_root: str | Path,
    *,
    unprotect: Callable[[bytes], bytes],
) -> str:
    """Resolve only the data-plane token used by Codex's fixed provider."""
    return read_gateway_token(install_root, "ingress", unprotect=unprotect)
