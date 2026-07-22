from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
from typing import Mapping
import uuid

from .breaker import BreakerStateStoreError


_FORBIDDEN_FIELD_PARTS = {
    "auth",
    "authorization",
    "bearer",
    "body",
    "buffer",
    "cookie",
    "key",
    "lease",
    "lease_id",
    "prompt",
    "request_body",
    "response_body",
    "secret",
    "token",
    "attempt_id",
}


class AtomicBreakerStateStore:
    def __init__(self, path: str | Path, *, max_bytes: int = 1024 * 1024) -> None:
        if max_bytes <= 0:
            raise ValueError("breaker_state_max_bytes_invalid")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = Lock()

    def load(self) -> Mapping[str, object] | None:
        with self._lock:
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise BreakerStateStoreError("breaker_state_read_failed") from exc
            if size > self.max_bytes:
                raise BreakerStateStoreError("breaker_state_too_large")
            try:
                payload = self.path.read_bytes()
            except OSError as exc:
                raise BreakerStateStoreError("breaker_state_read_failed") from exc
            if len(payload) > self.max_bytes:
                raise BreakerStateStoreError("breaker_state_too_large")
            try:
                document = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BreakerStateStoreError("breaker_state_json_invalid") from exc
            if not isinstance(document, Mapping):
                raise BreakerStateStoreError("breaker_state_json_invalid")
            self._reject_forbidden_fields(document)
            return document

    def save(self, document: Mapping[str, object]) -> None:
        self._reject_forbidden_fields(document)
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
            raise BreakerStateStoreError("breaker_state_serialize_failed") from exc
        if len(payload) > self.max_bytes:
            raise BreakerStateStoreError("breaker_state_too_large")
        with self._lock:
            parent = self.path.parent
            created_parent = not parent.exists()
            try:
                parent.mkdir(parents=True, exist_ok=True)
                if created_parent:
                    os.chmod(parent, stat.S_IRWXU)
            except OSError as exc:
                raise BreakerStateStoreError("breaker_state_directory_failed") from exc
            temporary = parent / f".{self.path.name}.{uuid.uuid4().hex}.tmp"
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
                    os.replace(temporary, self.path)
                except OSError as exc:
                    if not self._target_matches(payload):
                        raise BreakerStateStoreError("breaker_state_commit_uncertain") from exc
                self._fsync_directory(parent)
            except OSError as exc:
                raise BreakerStateStoreError("breaker_state_write_failed") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    @classmethod
    def _reject_forbidden_fields(cls, value: object) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise BreakerStateStoreError("breaker_state_forbidden_field")
                parts = {
                    part
                    for part in re.split(r"[^a-z0-9]+", key.lower())
                    if part
                }
                if parts & _FORBIDDEN_FIELD_PARTS:
                    raise BreakerStateStoreError("breaker_state_forbidden_field")
                cls._reject_forbidden_fields(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                cls._reject_forbidden_fields(nested)

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

    def _target_matches(self, payload: bytes) -> bool:
        try:
            return self.path.read_bytes() == payload
        except OSError:
            return False
