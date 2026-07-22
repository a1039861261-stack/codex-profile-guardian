from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping

from .public_values import validate_failure_category, validate_public_failure_code


class GatewayError(Exception):
    def __init__(self, code: str, public_message: str, *, http_status: int = 502) -> None:
        super().__init__(code)
        self.code = code
        self.public_message = public_message
        self.http_status = http_status


class CancelReason(StrEnum):
    CLIENT_DISCONNECTED = "client_disconnected"
    REQUEST_TIMEOUT = "request_timeout"
    GATEWAY_SHUTDOWN = "gateway_shutdown"


class CommitState(StrEnum):
    UNCOMMITTED = "uncommitted"
    COMMITTING = "committing"
    DELIVERED = "delivered"
    ERROR_COMMITTED = "error_committed"
    DELIVERY_UNCERTAIN = "delivery_uncertain"


class FailureDisposition(StrEnum):
    RETRYABLE_TEMPORARY = "retryable_temporary"
    RETRYABLE_ACTION_REQUIRED = "retryable_action_required"
    NON_RETRYABLE = "non_retryable"
    LOCAL_FAILURE = "local_failure"


class AttemptPhase(StrEnum):
    BEFORE_REQUEST = "before_request"
    AWAITING_HEADERS = "awaiting_headers"
    READING_BODY = "reading_body"
    VALIDATING = "validating"


@dataclass(frozen=True, slots=True)
class GatewayLimits:
    max_request_bytes: int = 8 * 1024 * 1024
    max_response_bytes: int = 16 * 1024 * 1024
    read_chunk_bytes: int = 64 * 1024
    max_concurrent_requests: int = 8
    connect_timeout_seconds: float = 10.0
    first_byte_timeout_seconds: float = 30.0
    idle_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 600.0

    def __post_init__(self) -> None:
        integer_fields = (
            self.max_request_bytes,
            self.max_response_bytes,
            self.read_chunk_bytes,
            self.max_concurrent_requests,
        )
        timeout_fields = (
            self.connect_timeout_seconds,
            self.first_byte_timeout_seconds,
            self.idle_timeout_seconds,
            self.total_timeout_seconds,
        )
        if any(value <= 0 for value in integer_fields + timeout_fields):
            raise ValueError("gateway_limits_must_be_positive")
        if self.total_timeout_seconds < self.first_byte_timeout_seconds:
            raise ValueError("total_timeout_must_cover_first_byte_timeout")


@dataclass(frozen=True, slots=True)
class RequestSnapshot:
    body: bytes
    body_sha256: str
    model: str
    stream: bool
    forward_headers: Mapping[str, str]
    state_dependencies: tuple[str, ...]
    has_server_side_tool_risk: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", bytes(self.body))
        object.__setattr__(self, "forward_headers", self.immutable_headers(self.forward_headers))
        object.__setattr__(self, "state_dependencies", tuple(self.state_dependencies))

    @staticmethod
    def immutable_headers(headers: Mapping[str, str]) -> Mapping[str, str]:
        return MappingProxyType(dict(headers))


@dataclass(frozen=True, slots=True)
class BufferedResponse:
    status: int
    content_type: str
    body: bytes
    body_sha256: str
    terminal_status: str
    response_id: str
    buffer_bytes: int


@dataclass(frozen=True, slots=True)
class AttemptFailure:
    category: str
    public_code: str
    http_status: int | None = None
    possible_double_charge: bool = False
    phase: AttemptPhase = AttemptPhase.BEFORE_REQUEST
    request_started: bool = False
    response_bytes_received: int = 0
    retry_after: str | None = None
    adapter_action_required: bool = False
    possible_server_side_effects: bool = False

    def __post_init__(self) -> None:
        validate_failure_category(self.category)
        validate_public_failure_code(self.public_code)
        if self.http_status is not None and (
            type(self.http_status) is not int or not 100 <= self.http_status <= 599
        ):
            raise ValueError("attempt_http_status_invalid")
        if self.response_bytes_received < 0:
            raise ValueError("attempt_response_bytes_must_not_be_negative")
        if self.response_bytes_received and not self.request_started:
            raise ValueError("attempt_response_bytes_require_started_request")
        if self.possible_server_side_effects and not self.request_started:
            raise ValueError("server_side_effect_risk_requires_started_request")


@dataclass(frozen=True, slots=True)
class AttemptResult:
    complete: BufferedResponse | None = None
    failure: AttemptFailure | None = None
    cancelled: CancelReason | None = None
    request_started: bool = False
    response_bytes_received: int = 0

    def __post_init__(self) -> None:
        populated = sum(value is not None for value in (self.complete, self.failure, self.cancelled))
        if populated != 1:
            raise ValueError("attempt_result_requires_exactly_one_outcome")
        if self.response_bytes_received < 0:
            raise ValueError("attempt_response_bytes_must_not_be_negative")
        if self.response_bytes_received and not self.request_started:
            raise ValueError("attempt_response_bytes_require_started_request")
        if self.failure is not None:
            if self.request_started and not self.failure.request_started:
                raise ValueError("attempt_result_conflicts_with_failure_start_evidence")
            if (
                self.response_bytes_received
                and self.response_bytes_received != self.failure.response_bytes_received
            ):
                raise ValueError("attempt_result_conflicts_with_failure_response_bytes")


@dataclass(frozen=True, slots=True)
class CommitResult:
    state: CommitState
    bytes_written: int
    error_type: str | None = None
