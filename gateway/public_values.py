from __future__ import annotations

import re


FAILURE_CATEGORIES = frozenset(
    {
        "auth_rejected",
        "network_error",
        "protocol_error",
        "protocol_or_local_error",
        "rate_limited",
        "upstream_5xx",
        "upstream_http_error",
        "upstream_timeout",
        "upstream_transport_error",
    }
)

PUBLIC_FAILURE_CODES = frozenset(
    {
        "guardian_response_too_large",
        "guardian_upstream_credential_unavailable",
        "guardian_upstream_protocol_error",
        "guardian_upstream_timeout",
        "guardian_upstream_transport_error",
    }
)

PUBLIC_GATEWAY_CODES = frozenset(
    {
        "guardian_all_routes_failed",
        "guardian_automatic_replay_blocked",
        "guardian_browser_origin_rejected",
        "guardian_client_cancelled",
        "guardian_expectation_not_supported",
        "guardian_gateway_busy",
        "guardian_gateway_draining",
        "guardian_disk_low_watermark",
        "guardian_disk_status_unavailable",
        "guardian_internal_error",
        "guardian_invalid_model",
        "guardian_invalid_request",
        "guardian_invalid_stream",
        "guardian_model_not_allowed",
        "guardian_request_too_large",
        "guardian_state_compatibility_stale",
        "guardian_state_compatibility_unknown",
        "guardian_state_incompatible",
        "guardian_unauthorized",
        "guardian_unsupported_media_type",
    }
)

PUBLIC_BREAKER_UNAVAILABLE_REASONS = frozenset(
    {
        "disabled",
        "half_open_busy",
        "open_action_required",
        "open_temporary",
    }
)

_HTTP_CODE = re.compile(r"^guardian_upstream_http_([1-5][0-9]{2})$")


def validate_failure_category(value: str) -> str:
    if not isinstance(value, str) or value not in FAILURE_CATEGORIES:
        raise ValueError("attempt_failure_category_invalid")
    return value


def validate_public_failure_code(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("attempt_public_code_invalid")
    if value in PUBLIC_FAILURE_CODES:
        return value
    match = _HTTP_CODE.fullmatch(value)
    if match is None:
        raise ValueError("attempt_public_code_invalid")
    return value


def normalize_public_gateway_code(value: str) -> str:
    if isinstance(value, str) and value in PUBLIC_GATEWAY_CODES:
        return value
    try:
        return validate_public_failure_code(value)
    except ValueError:
        return "guardian_internal_error"


def validate_public_breaker_unavailable_reason(value: str) -> str:
    if not isinstance(value, str) or value not in PUBLIC_BREAKER_UNAVAILABLE_REASONS:
        raise ValueError("breaker_unavailable_reason_invalid")
    return value


def public_protocol_code(_detail_code: str) -> str:
    return "guardian_upstream_protocol_error"
