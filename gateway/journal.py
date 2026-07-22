from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any
import uuid


@dataclass(frozen=True, slots=True)
class GatewayEvent:
    request_id: str
    event: str
    model: str
    status: str
    event_id: str = ""
    timestamp: str = ""
    instance_id: str = ""
    group_id: str = ""
    buffer_bytes: int = 0
    config_revision: int = 0
    route_role: str = ""
    attempt_id: str = ""
    failover_used: bool = False
    possible_double_charge: bool = False
    signal: str = "business"
    breaker_before: str = ""
    breaker_after: str = ""
    http_status_category: str = ""
    latency_ms: int = 0


class MemoryEventJournal:
    _ALLOWED = {
        "request_id",
        "event",
        "model",
        "status",
        "event_id",
        "timestamp",
        "instance_id",
        "group_id",
        "buffer_bytes",
        "config_revision",
        "route_role",
        "attempt_id",
        "failover_used",
        "possible_double_charge",
        "signal",
        "breaker_before",
        "breaker_after",
        "http_status_category",
        "latency_ms",
    }

    def __init__(self, capacity: int = 256) -> None:
        if capacity <= 0:
            raise ValueError("journal_capacity_must_be_positive")
        self._events: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = Lock()

    def append(self, event: GatewayEvent) -> None:
        value = asdict(event)
        if set(value) != self._ALLOWED:
            raise RuntimeError("journal_schema_violation")
        value["event_id"] = value["event_id"] or uuid.uuid4().hex
        value["timestamp"] = value["timestamp"] or datetime.now(UTC).isoformat()
        if value["latency_ms"] < 0:
            raise ValueError("journal_latency_must_not_be_negative")
        with self._lock:
            self._events.append(value)

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(event) for event in self._events)
