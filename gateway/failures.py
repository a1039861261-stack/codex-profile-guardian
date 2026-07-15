from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math

from .models import AttemptFailure, FailureDisposition


@dataclass(frozen=True, slots=True)
class FailureDecision:
    category: str
    disposition: FailureDisposition
    retry_on_backup: bool
    breaker_failure: bool
    action_required: bool
    possible_double_charge: bool
    retry_after_seconds: float | None = None
    protocol_failure: bool = False


class FailureClassifier:
    _TEMPORARY_HTTP = {429, 500, 502, 503, 504}
    _ACTION_HTTP = {401, 403}
    _NON_RETRYABLE_HTTP = {400, 404, 409, 413, 415, 422}
    _LOCAL_NON_RETRYABLE = {
        "guardian_response_too_large",
        "guardian_upstream_credential_unavailable",
    }

    def classify(
        self,
        failure: AttemptFailure,
        *,
        now_wall: float,
        max_retry_after_seconds: float,
    ) -> FailureDecision:
        status = failure.http_status
        if failure.category == "protocol_or_local_error":
            if failure.public_code in self._LOCAL_NON_RETRYABLE or (status is not None and status >= 500 and status != 502):
                return self._decision(
                    failure,
                    FailureDisposition.LOCAL_FAILURE,
                    retry_on_backup=False,
                    breaker_failure=False,
                )
            return self._decision(
                failure,
                FailureDisposition.RETRYABLE_TEMPORARY,
                protocol_failure=True,
            )
        if status in self._ACTION_HTTP or (status == 404 and failure.adapter_action_required):
            return self._decision(failure, FailureDisposition.RETRYABLE_ACTION_REQUIRED, action_required=True)
        if status in self._TEMPORARY_HTTP:
            retry_after = None
            if status == 429:
                retry_after = parse_retry_after(
                    failure.retry_after,
                    now_wall=now_wall,
                    maximum=max_retry_after_seconds,
                )
            return self._decision(
                failure,
                FailureDisposition.RETRYABLE_TEMPORARY,
                retry_after_seconds=retry_after,
            )
        if status in self._NON_RETRYABLE_HTTP or 400 <= (status or 0) <= 499:
            return self._decision(failure, FailureDisposition.NON_RETRYABLE, retry_on_backup=False, breaker_failure=False)
        if failure.category in {"upstream_timeout", "upstream_transport_error"}:
            return self._decision(failure, FailureDisposition.RETRYABLE_TEMPORARY)
        return self._decision(
            failure,
            FailureDisposition.LOCAL_FAILURE,
            retry_on_backup=False,
            breaker_failure=False,
        )

    @staticmethod
    def _decision(
        failure: AttemptFailure,
        disposition: FailureDisposition,
        *,
        retry_on_backup: bool = True,
        breaker_failure: bool = True,
        action_required: bool = False,
        retry_after_seconds: float | None = None,
        protocol_failure: bool = False,
    ) -> FailureDecision:
        return FailureDecision(
            category=failure.category,
            disposition=disposition,
            retry_on_backup=retry_on_backup,
            breaker_failure=breaker_failure,
            action_required=action_required,
            possible_double_charge=failure.possible_double_charge,
            retry_after_seconds=retry_after_seconds,
            protocol_failure=protocol_failure,
        )


def parse_retry_after(value: str | None, *, now_wall: float, maximum: float) -> float | None:
    if not value or not math.isfinite(maximum) or maximum <= 0:
        return None
    stripped = value.strip()
    if stripped.isascii() and stripped.isdecimal() and len(stripped) <= 18:
        try:
            seconds = float(int(stripped))
        except (ValueError, OverflowError):
            return None
    else:
        try:
            parsed = parsedate_to_datetime(stripped)
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        seconds = parsed.timestamp() - now_wall
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return min(seconds, maximum)
