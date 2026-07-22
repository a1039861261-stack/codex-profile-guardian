from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
from threading import Lock
from typing import Mapping


class RotatingAllowlistJournal:
    _ALLOWED = {
        "event",
        "status",
        "timestamp",
        "version",
        "instance_id",
        "process_instance_id",
        "config_revision",
        "reason",
        "restart_count",
        "active_requests",
        "http_status_category",
        "route_role",
        "signal",
    }

    def __init__(
        self,
        path: str | Path,
        *,
        max_bytes: int = 1024 * 1024,
        backups: int = 3,
        memory_capacity: int = 256,
    ) -> None:
        if max_bytes <= 0 or not 0 <= backups <= 10 or memory_capacity <= 0:
            raise ValueError("file_journal_limits_invalid")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._events: deque[dict[str, object]] = deque(maxlen=memory_capacity)
        self._lock = Lock()

    def append(self, event: Mapping[str, object]) -> None:
        if set(event) - self._ALLOWED:
            raise ValueError("file_journal_schema_violation")
        payload = dict(event)
        serialized = (
            json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + len(serialized) > self.max_bytes:
                self._rotate()
            with self.path.open("ab") as stream:
                stream.write(serialized)
                stream.flush()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._events.append(payload)

    def snapshot(self, *, offset: int = 0, limit: int = 100) -> tuple[dict[str, object], ...]:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("file_journal_page_invalid")
        with self._lock:
            return tuple(dict(item) for item in tuple(self._events)[offset : offset + limit])

    def _rotate(self) -> None:
        if self.backups == 0:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            return
        oldest = self.path.with_suffix(self.path.suffix + f".{self.backups}")
        try:
            oldest.unlink()
        except FileNotFoundError:
            pass
        for index in range(self.backups - 1, 0, -1):
            source = self.path.with_suffix(self.path.suffix + f".{index}")
            target = self.path.with_suffix(self.path.suffix + f".{index + 1}")
            try:
                os.replace(source, target)
            except FileNotFoundError:
                pass
        try:
            os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))
        except FileNotFoundError:
            pass
