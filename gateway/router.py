from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import time
from threading import Lock
from typing import Callable
import uuid

from .breaker import (
    AdmissionDenied,
    BreakerSignal,
    BreakerAdmission,
    BreakerTicket,
    CircuitBreakerRegistry,
    RouteKey,
    RouteRegistration,
)
from .cancellation import CancellationToken
from .config import FailoverGroupConfig, RouteConfig, RouteRole, SecretResolver
from .failures import FailureClassifier, FailureDecision
from .models import AttemptFailure, AttemptResult, BufferedResponse, CancelReason, RequestSnapshot


class TrafficSignal(StrEnum):
    BUSINESS = "business"
    PROBE = "probe"


@dataclass(frozen=True, slots=True)
class RouteAttempt:
    route: RouteConfig
    attempt_id: str
    result: AttemptResult
    decision: FailureDecision | None = None
    admission: BreakerAdmission | None = None
    breaker_before: str = ""
    breaker_after: str = ""
    latency_ms: int = 0


@dataclass(frozen=True, slots=True)
class RoutedResult:
    complete: BufferedResponse | None
    attempts: tuple[RouteAttempt, ...]
    primary_failure: AttemptFailure | None
    backup_failure: AttemptFailure | None
    cancelled: CancelReason | None
    failover_used: bool
    possible_double_charge: bool
    action_required: bool
    signal: TrafficSignal
    primary_admission: BreakerAdmission | None = None
    backup_admission: BreakerAdmission | None = None
    replay_blocked: bool = False


class FailoverRouter:
    def __init__(
        self,
        group: FailoverGroupConfig,
        breaker: CircuitBreakerRegistry,
        classifier: FailureClassifier,
        secrets: SecretResolver,
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._group = group
        self._breaker = breaker
        self._classifier = classifier
        self._secrets = secrets
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._carrying_lock = Lock()
        self._last_business_carrier: RouteRole | None = None
        self._breaker.configure_routes(
            tuple(
                RouteRegistration(
                    self._route_key(route),
                    group.revision,
                    route.fingerprint,
                    group.breaker_policy,
                    route.enabled,
                )
                for route in (group.primary, group.backup)
            ),
            retire_instance_routes=True,
        )

    @property
    def group(self) -> FailoverGroupConfig:
        return self._group

    @property
    def version_keys(self) -> tuple[tuple[RouteKey, int, str], ...]:
        return tuple(
            (self._route_key(route), self._group.revision, route.fingerprint)
            for route in (self._group.primary, self._group.backup)
        )

    async def execute(
        self,
        snapshot: RequestSnapshot,
        cancellation: CancellationToken,
        *,
        signal: TrafficSignal = TrafficSignal.BUSINESS,
        probe_role: RouteRole | None = None,
        can_failover: Callable[[], bool] | None = None,
    ) -> RoutedResult:
        if signal is TrafficSignal.PROBE:
            from .probes import is_safe_probe

            if not is_safe_probe(snapshot):
                raise RuntimeError("guardian_unsafe_probe_request")
            if probe_role is None:
                raise RuntimeError("guardian_probe_route_required")
            routes = (self._group.primary,) if probe_role is RouteRole.PRIMARY else (self._group.backup,)
        else:
            if probe_role is not None:
                raise RuntimeError("guardian_probe_route_requires_probe_signal")
            routes = (self._group.primary, self._group.backup)
        if snapshot.model not in self._group.allowed_models:
            raise RuntimeError("guardian_model_not_allowed")
        self._group.validate_state_dependencies(snapshot.model, snapshot.state_dependencies)
        attempts: list[RouteAttempt] = []
        primary_failure: AttemptFailure | None = None
        backup_failure: AttemptFailure | None = None
        primary_charge_uncertain = False
        backup_upstream_started = False
        action_required = False
        replay_blocked = False
        admissions: dict[str, BreakerAdmission] = {}
        issued_tickets: list[BreakerTicket] = []
        versions = self.version_keys
        self._breaker.pin_versions(versions)
        try:
            planned_routes = []
            for route in routes:
                preview = self._breaker.preview_admission(
                    self._route_key(route),
                    config_revision=self._group.revision,
                    route_fingerprint=route.fingerprint,
                    manual_probe=signal is TrafficSignal.PROBE,
                )
                if preview.allowed:
                    planned_routes.append(route)
                    continue
                admissions[route.role.value] = preview
                if preview.denied not in {
                    AdmissionDenied.DISABLED,
                    AdmissionDenied.OPEN_TEMPORARY,
                    AdmissionDenied.OPEN_ACTION_REQUIRED,
                    AdmissionDenied.HALF_OPEN_BUSY,
                }:
                    raise RuntimeError(f"breaker_admission_failed:{preview.denied}")
            credentials = {
                route.role.value: self._resolve_credential(route)
                for route in planned_routes
            }
            unavailable_credential = next(
                (value for value in credentials.values() if isinstance(value, AttemptFailure)),
                None,
            )
            if unavailable_credential is not None:
                raise RuntimeError(unavailable_credential.public_code)
            for route in planned_routes:
                if route is self._group.backup and can_failover is not None and not can_failover():
                    raise RuntimeError("backup_attempt_requires_uncommitted_response")
                attempt_id = self._next_attempt_id()
                admission = self._breaker.acquire(
                    self._route_key(route),
                    config_revision=self._group.revision,
                    route_fingerprint=route.fingerprint,
                    attempt_id=attempt_id,
                    manual_probe=signal is TrafficSignal.PROBE,
                    signal=(
                        BreakerSignal.PROBE
                        if signal is TrafficSignal.PROBE
                        else BreakerSignal.BUSINESS
                    ),
                )
                admissions[route.role.value] = admission
                if not admission.allowed:
                    if admission.denied in {
                        AdmissionDenied.DISABLED,
                        AdmissionDenied.OPEN_TEMPORARY,
                        AdmissionDenied.OPEN_ACTION_REQUIRED,
                        AdmissionDenied.HALF_OPEN_BUSY,
                    }:
                        continue
                    raise RuntimeError(f"breaker_admission_failed:{admission.denied}")
                ticket = admission.ticket
                if ticket is None:
                    raise RuntimeError("breaker_ticket_missing")
                issued_tickets.append(ticket)
                bearer = credentials[route.role.value]
                attempt_started = self._monotonic_clock()
                try:
                    result = await route.runner.run(snapshot, bearer, cancellation)
                except BaseException:
                    self._breaker.record_cancelled(ticket)
                    raise
                if result.cancelled is not None:
                    if route is self._group.backup:
                        backup_upstream_started = result.request_started
                    self._breaker.record_cancelled(ticket)
                    attempts.append(
                        RouteAttempt(
                            route,
                            attempt_id,
                            result,
                            admission=admission,
                            breaker_before=admission.state.value,
                            breaker_after=self._breaker_state(route),
                            latency_ms=self._elapsed_ms(attempt_started),
                        )
                    )
                    return self._result(
                        complete=None,
                        attempts=attempts,
                        primary_failure=primary_failure,
                        backup_failure=backup_failure,
                        cancelled=result.cancelled,
                            possible_double_charge=primary_charge_uncertain and backup_upstream_started,
                        action_required=action_required,
                        signal=signal,
                            admissions=admissions,
                            replay_blocked=replay_blocked,
                    )
                if result.complete is not None:
                    if route is self._group.backup:
                        backup_upstream_started = True
                    self._breaker.record_success(ticket)
                    if signal is TrafficSignal.BUSINESS:
                        with self._carrying_lock:
                            self._last_business_carrier = route.role
                    attempts.append(
                        RouteAttempt(
                            route,
                            attempt_id,
                            result,
                            admission=admission,
                            breaker_before=admission.state.value,
                            breaker_after=self._breaker_state(route),
                            latency_ms=self._elapsed_ms(attempt_started),
                        )
                    )
                    return self._result(
                        complete=result.complete,
                        attempts=attempts,
                        primary_failure=primary_failure,
                        backup_failure=backup_failure,
                        cancelled=None,
                            possible_double_charge=primary_charge_uncertain and backup_upstream_started,
                        action_required=action_required,
                        signal=signal,
                            admissions=admissions,
                            replay_blocked=replay_blocked,
                    )
                failure = result.failure
                if failure is None:
                    self._breaker.record_cancelled(ticket)
                    raise RuntimeError("attempt_outcome_missing")
                decision = self._classifier.classify(
                    failure,
                    now_wall=self._wall_clock(),
                    max_retry_after_seconds=self._group.breaker_policy.max_cooldown_seconds,
                )
                if route is self._group.primary:
                    primary_charge_uncertain = decision.possible_double_charge
                else:
                    backup_upstream_started = failure.request_started
                action_required = action_required or decision.action_required
                if route is self._group.primary:
                    primary_failure = failure
                else:
                    backup_failure = failure
                    if signal is TrafficSignal.BUSINESS:
                        with self._carrying_lock:
                            self._last_business_carrier = None
                self._record_failure(ticket, failure, decision)
                attempts.append(
                    RouteAttempt(
                        route,
                        attempt_id,
                        result,
                        decision,
                        admission,
                        admission.state.value,
                        self._breaker_state(route),
                        self._elapsed_ms(attempt_started),
                    )
                )
                if (
                    route is self._group.primary
                    and decision.retry_on_backup
                    and snapshot.has_server_side_tool_risk
                    and failure.possible_server_side_effects
                ):
                    replay_blocked = True
                    break
                if not decision.retry_on_backup or route is self._group.backup:
                    break
        finally:
            for ticket in issued_tickets:
                self._breaker.abandon(ticket)
            self._breaker.release_versions(versions)
        return self._result(
            complete=None,
            attempts=attempts,
            primary_failure=primary_failure,
            backup_failure=backup_failure,
            cancelled=None,
            possible_double_charge=primary_charge_uncertain and backup_upstream_started,
            action_required=action_required,
            signal=signal,
            admissions=admissions,
            replay_blocked=replay_blocked,
        )

    def _result(
        self,
        *,
        complete: BufferedResponse | None,
        attempts: list[RouteAttempt],
        primary_failure: AttemptFailure | None,
        backup_failure: AttemptFailure | None,
        cancelled: CancelReason | None,
        possible_double_charge: bool,
        action_required: bool,
        signal: TrafficSignal,
        admissions: dict[str, BreakerAdmission],
        replay_blocked: bool,
    ) -> RoutedResult:
        return RoutedResult(
            complete=complete,
            attempts=tuple(attempts),
            primary_failure=primary_failure,
            backup_failure=backup_failure,
            cancelled=cancelled,
            failover_used=(
                signal is TrafficSignal.BUSINESS
                and any(attempt.route is self._group.backup for attempt in attempts)
            ),
            possible_double_charge=possible_double_charge,
            action_required=action_required,
            signal=signal,
            primary_admission=admissions.get(RouteRole.PRIMARY.value),
            backup_admission=admissions.get(RouteRole.BACKUP.value),
            replay_blocked=replay_blocked,
        )

    def _record_failure(
        self,
        ticket: BreakerTicket,
        failure: AttemptFailure,
        decision: FailureDecision,
    ) -> None:
        if not decision.breaker_failure:
            self._breaker.record_cancelled(ticket)
        elif decision.protocol_failure:
            self._breaker.record_protocol_failure(
                ticket,
                failure_category=failure.category,
                http_status=failure.http_status,
            )
        elif decision.action_required:
            self._breaker.record_action_required(
                ticket,
                failure_category=failure.category,
                http_status=failure.http_status,
            )
        elif failure.http_status == 429:
            self._breaker.record_rate_limited(
                ticket,
                retry_after_seconds=decision.retry_after_seconds,
                failure_category=failure.category,
                http_status=failure.http_status,
            )
        else:
            self._breaker.record_temporary_failure(
                ticket,
                failure_category=failure.category,
                http_status=failure.http_status,
            )

    def _route_key(self, route: RouteConfig) -> RouteKey:
        return RouteKey(
            instance_id=self._group.instance_id,
            group_id=self._group.group_id,
            route_role=route.role.value,
            profile_id=route.profile_id,
        )

    def _breaker_state(self, route: RouteConfig) -> str:
        snapshot = self._breaker.snapshot_version(
            self._route_key(route),
            config_revision=self._group.revision,
            route_fingerprint=route.fingerprint,
        )
        return "" if snapshot is None else snapshot.state.value

    def _resolve_credential(self, route: RouteConfig) -> str | AttemptFailure:
        try:
            bearer = self._secrets.resolve(route.secret_ref)
        except Exception:
            return AttemptFailure(
                category="protocol_or_local_error",
                public_code="guardian_upstream_credential_unavailable",
                http_status=500,
            )
        if not bearer:
            return AttemptFailure(
                category="protocol_or_local_error",
                public_code="guardian_upstream_credential_unavailable",
                http_status=500,
            )
        return bearer

    def action_required_alerts(self) -> tuple[object, ...]:
        from .alerts import action_required_alert

        primary_snapshot = self._breaker.snapshot(self._route_key(self._group.primary))
        backup_snapshot = self._breaker.snapshot(self._route_key(self._group.backup))
        with self._carrying_lock:
            backup_carrying = self._last_business_carrier is RouteRole.BACKUP
        alerts = []
        if primary_snapshot is not None:
            alert = action_required_alert(
                self._group.primary,
                primary_snapshot,
                backup_carrying=backup_carrying,
            )
            if alert is not None:
                alerts.append(alert)
        if backup_snapshot is not None:
            alert = action_required_alert(
                self._group.backup,
                backup_snapshot,
                backup_carrying=False,
            )
            if alert is not None:
                alerts.append(alert)
        return tuple(alerts)

    def _next_attempt_id(self) -> str:
        return f"attempt-{uuid.uuid4().hex}"

    def _elapsed_ms(self, started: float) -> int:
        elapsed = self._monotonic_clock() - started
        return max(0, int(elapsed * 1000))
