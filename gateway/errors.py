from __future__ import annotations

import hashlib
import json

from .models import AttemptFailure, BufferedResponse
from .public_values import (
    normalize_public_gateway_code,
    validate_public_breaker_unavailable_reason,
)


_INTERNAL_ERROR_MESSAGE = "本地网关内部错误。"


def gateway_error_response(
    *,
    status: int,
    code: str,
    message: str,
    request_id: str | None = None,
) -> BufferedResponse:
    public_code = normalize_public_gateway_code(code)
    if public_code != code or type(status) is not int or not 400 <= status <= 599:
        status = 500
        public_code = "guardian_internal_error"
        message = _INTERNAL_ERROR_MESSAGE
    error = {
        "type": "guardian_gateway_error",
        "code": public_code,
        "message": message,
    }
    if request_id:
        error["request_id"] = request_id
    body = json.dumps(
        {"error": error},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return BufferedResponse(
        status=status,
        content_type="application/json",
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        terminal_status="gateway_error",
        response_id="",
        buffer_bytes=len(body),
    )


def all_routes_failed_response(
    *,
    request_id: str,
    primary: AttemptFailure | None,
    backup: AttemptFailure | None,
    possible_double_charge: bool,
    action_required: bool,
    primary_unavailable: str | None = None,
    backup_unavailable: str | None = None,
) -> BufferedResponse:
    for unavailable in (primary_unavailable, backup_unavailable):
        if unavailable is not None:
            try:
                validate_public_breaker_unavailable_reason(unavailable)
            except ValueError:
                return gateway_error_response(
                    status=500,
                    code="guardian_internal_error",
                    message=_INTERNAL_ERROR_MESSAGE,
                    request_id=request_id,
                )
    attempts = []
    for role, failure, unavailable in (
        ("primary", primary, primary_unavailable),
        ("backup", backup, backup_unavailable),
    ):
        if failure is not None:
            attempt = {"role": role, "category": failure.category}
            if failure.http_status is not None:
                attempt["http_status"] = failure.http_status
            attempts.append(attempt)
        elif unavailable is not None:
            attempts.append({"role": role, "category": f"breaker_{unavailable}"})
    value = {
        "error": {
            "type": "guardian_gateway_error",
            "code": "guardian_all_routes_failed",
            "message": "主线路和备用线路当前均不可用。",
            "request_id": request_id,
            "attempts": attempts,
            "possible_double_charge": possible_double_charge,
            "action_required": action_required,
            "next_action": "请检查线路状态后重试；凭据或权限故障请到中转站检查 Key、分组和模型权限。",
        }
    }
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    status = _public_status(primary, backup, primary_unavailable, backup_unavailable)
    return BufferedResponse(
        status=status,
        content_type="application/json",
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        terminal_status="gateway_error",
        response_id="",
        buffer_bytes=len(body),
    )


def _public_status(
    primary: AttemptFailure | None,
    backup: AttemptFailure | None,
    primary_unavailable: str | None,
    backup_unavailable: str | None,
) -> int:
    failures = tuple(failure for failure in (primary, backup) if failure is not None)
    if not failures and (primary_unavailable is not None or backup_unavailable is not None):
        return 503
    if failures and all(
        failure.category in {"upstream_timeout", "upstream_transport_error", "upstream_http_error"}
        and (failure.http_status is None or failure.http_status in {401, 403, 429, 500, 502, 503, 504})
        for failure in failures
    ):
        return 503
    return 502
