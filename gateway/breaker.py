from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import math
import random
import re
from threading import RLock
from typing import Callable, Mapping, Protocol
import uuid

from .public_values import validate_failure_category


class BreakerState(StrEnum):
    UNKNOWN = "unknown"
    CLOSED = "closed"
    OPEN_TEMPORARY = "open_temporary"
    HALF_OPEN = "half_open"
    OPEN_ACTION_REQUIRED = "open_action_required"
    DISABLED = "disabled"


class AdmissionDenied(StrEnum):
    UNKNOWN_ROUTE = "unknown_route"
    STALE_CONFIGURATION = "stale_configuration"
    DISABLED = "disabled"
    OPEN_TEMPORARY = "open_temporary"
    OPEN_ACTION_REQUIRED = "open_action_required"
    HALF_OPEN_BUSY = "half_open_busy"
    ATTEMPT_ALREADY_ACTIVE = "attempt_already_active"


class ObservationResult(StrEnum):
    APPLIED = "applied"
    IGNORED = "ignored"


class BreakerSignal(StrEnum):
    BUSINESS = "business"
    PROBE = "probe"


class BreakerStateStoreError(RuntimeError):
    pass


class BreakerStateStore(Protocol):
    def load(self) -> Mapping[str, object] | None: ...

    def save(self, document: Mapping[str, object]) -> None: ...


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINGERPRINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_CATEGORY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MAX_COOLDOWN_SECONDS = 365 * 24 * 60 * 60
_MAX_COUNTER = 2**63 - 1
_TRANSITION_REASONS = frozenset(
    {
        "business_failed",
        "business_succeeded",
        "configuration_disabled",
        "configuration_enabled",
        "configuration_replaced",
        "cooldown_elapsed",
        "manual_probe_started",
        "probe_cancelled",
        "probe_failed",
        "probe_succeeded",
        "state_restored",
    }
)


@dataclass(frozen=True, slots=True)
class RouteKey:
    instance_id: str
    group_id: str
    route_role: str
    profile_id: str

    def __post_init__(self) -> None:
        for value in (self.instance_id, self.group_id, self.route_role, self.profile_id):
            if not _IDENTIFIER.fullmatch(value):
                raise ValueError("breaker_route_identifier_invalid")


@dataclass(frozen=True, slots=True)
class CircuitBreakerPolicy:
    failure_threshold: int = 3
    protocol_failure_threshold: int = 3
    error_rate_threshold: float | None = 0.5
    minimum_samples: int = 10
    window_size: int = 20
    recovery_success_threshold: int = 2
    base_cooldown_seconds: float = 30.0
    max_cooldown_seconds: float = 300.0
    jitter_ratio: float = 0.1

    def __post_init__(self) -> None:
        if self.failure_threshold <= 0:
            raise ValueError("breaker_failure_threshold_invalid")
        if self.protocol_failure_threshold <= 0:
            raise ValueError("breaker_protocol_failure_threshold_invalid")
        if self.window_size <= 0 or self.window_size > 10_000:
            raise ValueError("breaker_window_size_invalid")
        if self.minimum_samples <= 0 or self.minimum_samples > self.window_size:
            raise ValueError("breaker_minimum_samples_invalid")
        if self.error_rate_threshold is not None and not 0 < self.error_rate_threshold <= 1:
            raise ValueError("breaker_error_rate_threshold_invalid")
        if self.recovery_success_threshold <= 0:
            raise ValueError("breaker_recovery_threshold_invalid")
        if (
            not math.isfinite(self.base_cooldown_seconds)
            or not math.isfinite(self.max_cooldown_seconds)
            or self.base_cooldown_seconds <= 0
            or self.max_cooldown_seconds < self.base_cooldown_seconds
            or self.max_cooldown_seconds > _MAX_COOLDOWN_SECONDS
        ):
            raise ValueError("breaker_cooldown_range_invalid")
        if not math.isfinite(self.jitter_ratio) or not 0 <= self.jitter_ratio <= 1:
            raise ValueError("breaker_jitter_ratio_invalid")


@dataclass(frozen=True, slots=True)
class RouteRegistration:
    key: RouteKey
    config_revision: int
    route_fingerprint: str
    policy: CircuitBreakerPolicy
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class BreakerTicket:
    route_key: RouteKey
    config_revision: int
    route_fingerprint: str
    transition_epoch: int
    lease_id: str
    attempt_id: str
    half_open_probe: bool
    signal: BreakerSignal


@dataclass(frozen=True, slots=True)
class BreakerAdmission:
    allowed: bool
    state: BreakerState
    ticket: BreakerTicket | None = None
    denied: AdmissionDenied | None = None
    retry_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class BreakerSnapshot:
    route_key: RouteKey
    config_revision: int
    route_fingerprint: str
    transition_epoch: int
    state: BreakerState
    consecutive_failures: int
    consecutive_protocol_failures: int
    consecutive_successes: int
    sample_count: int
    failure_count: int
    error_rate: float
    open_count: int
    open_until: datetime | None
    first_failed_at: datetime | None
    last_failed_at: datetime | None
    last_succeeded_at: datetime | None
    last_failure_category: str | None
    last_http_status: int | None
    action_required: bool
    half_open_lease_active: bool


@dataclass(frozen=True, slots=True)
class BreakerTransition:
    event_id: str
    timestamp: str
    route_key: RouteKey
    config_revision: int
    transition_epoch: int
    old_state: BreakerState
    new_state: BreakerState
    reason: str
    failure_category: str | None = None
    http_status: int | None = None
    signal: BreakerSignal | None = None


@dataclass(slots=True)
class _RouteRuntime:
    key: RouteKey
    config_revision: int
    route_fingerprint: str
    policy: CircuitBreakerPolicy
    enabled: bool
    state: BreakerState
    transition_epoch: int = 1
    consecutive_failures: int = 0
    consecutive_protocol_failures: int = 0
    consecutive_successes: int = 0
    outcomes: deque[bool] = field(default_factory=deque)
    open_count: int = 0
    open_until: datetime | None = None
    first_failed_at: datetime | None = None
    last_failed_at: datetime | None = None
    last_succeeded_at: datetime | None = None
    last_failure_category: str | None = None
    last_http_status: int | None = None
    action_required: bool = False
    half_open_lease_id: str | None = None

    def clone(self) -> _RouteRuntime:
        return _RouteRuntime(
            key=self.key,
            config_revision=self.config_revision,
            route_fingerprint=self.route_fingerprint,
            policy=self.policy,
            enabled=self.enabled,
            state=self.state,
            transition_epoch=self.transition_epoch,
            consecutive_failures=self.consecutive_failures,
            consecutive_protocol_failures=self.consecutive_protocol_failures,
            consecutive_successes=self.consecutive_successes,
            outcomes=deque(self.outcomes, maxlen=self.policy.window_size),
            open_count=self.open_count,
            open_until=self.open_until,
            first_failed_at=self.first_failed_at,
            last_failed_at=self.last_failed_at,
            last_succeeded_at=self.last_succeeded_at,
            last_failure_category=self.last_failure_category,
            last_http_status=self.last_http_status,
            action_required=self.action_required,
            half_open_lease_id=self.half_open_lease_id,
        )


class CircuitBreakerRegistry:
    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        rng: Callable[[], float] | None = None,
        lease_factory: Callable[[], str] | None = None,
        transition_capacity: int = 1024,
    ) -> None:
        if type(transition_capacity) is not int or not 0 < transition_capacity <= 10_000:
            raise ValueError("breaker_transition_capacity_invalid")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._rng = rng or random.SystemRandom().random
        self._lease_factory = lease_factory or (lambda: uuid.uuid4().hex)
        self._lock = RLock()
        self._routes: dict[tuple[RouteKey, int, str], _RouteRuntime] = {}
        self._current_routes: dict[RouteKey, tuple[int, str]] = {}
        self._active: dict[tuple[RouteKey, int, str, str], BreakerTicket] = {}
        self._pins: dict[tuple[RouteKey, int, str], int] = {}
        self._store: BreakerStateStore | None = None
        self._lease_sequence = 0
        self._persistence_uncertain = False
        self._transition_events: deque[BreakerTransition] = deque(maxlen=transition_capacity)
        self._transition_batches: list[list[BreakerTransition]] = []

    def configure_routes(
        self,
        registrations: tuple[RouteRegistration, ...],
        *,
        retire_group_routes: bool = False,
        retire_instance_routes: bool = False,
    ) -> tuple[BreakerSnapshot, ...]:
        if not registrations or len({item.key for item in registrations}) != len(registrations):
            raise ValueError("breaker_route_registration_invalid")
        if retire_group_routes and retire_instance_routes:
            raise ValueError("breaker_route_retirement_scope_invalid")
        with self._lock:
            routes_before = {key: runtime.clone() for key, runtime in self._routes.items()}
            current_before = dict(self._current_routes)
            active_before = dict(self._active)
            pins_before = dict(self._pins)
            store = self._store
            self._store = None
            self._begin_transition_batch_locked()
            try:
                snapshots = tuple(
                    self.configure_route(
                        item.key,
                        config_revision=item.config_revision,
                        route_fingerprint=item.route_fingerprint,
                        policy=item.policy,
                        enabled=item.enabled,
                    )
                    for item in registrations
                )
                if retire_group_routes:
                    self._retire_unregistered_group_routes_locked(registrations)
                elif retire_instance_routes:
                    self._retire_unregistered_instance_routes_locked(registrations)
                self._store = store
                self._persist_locked()
                self._commit_transition_batch_locked()
                return snapshots
            except Exception:
                self._rollback_transition_batch_locked()
                self._routes = routes_before
                self._current_routes = current_before
                self._active = active_before
                self._pins = pins_before
                self._store = store
                raise

    def configure_route(
        self,
        key: RouteKey,
        *,
        config_revision: int,
        route_fingerprint: str,
        policy: CircuitBreakerPolicy,
        enabled: bool = True,
    ) -> BreakerSnapshot:
        _validate_revision_and_fingerprint(config_revision, route_fingerprint)
        with self._lock:
            current_version = self._current_routes.get(key)
            current = None if current_version is None else self._routes.get((key, *current_version))
            previous_state = None if current is None else current.state
            versions_before = {
                version_key: runtime.clone()
                for version_key, runtime in self._routes.items()
                if version_key[0] == key
            }
            active_before = self._active_for_route_locked(key)
            if current is not None and config_revision < current.config_revision:
                raise ValueError("breaker_config_revision_regressed")
            if (
                current is not None
                and config_revision == current.config_revision
                and route_fingerprint != current.route_fingerprint
            ):
                raise ValueError("breaker_fingerprint_changed_without_revision")
            try:
                if current is None:
                    runtime = _RouteRuntime(
                        key=key,
                        config_revision=config_revision,
                        route_fingerprint=route_fingerprint,
                        policy=policy,
                        enabled=enabled,
                        state=BreakerState.UNKNOWN if enabled else BreakerState.DISABLED,
                        outcomes=deque(maxlen=policy.window_size),
                    )
                    self._routes[(key, config_revision, route_fingerprint)] = runtime
                    self._current_routes[key] = (config_revision, route_fingerprint)
                elif config_revision == current.config_revision:
                    runtime = current
                    if policy != runtime.policy or enabled != runtime.enabled:
                        raise ValueError("breaker_configuration_changed_without_revision")
                else:
                    same_route = route_fingerprint == current.route_fingerprint
                    was_enabled = current.enabled
                    runtime = current.clone()
                    runtime.config_revision = config_revision
                    runtime.route_fingerprint = route_fingerprint
                    runtime.policy = policy
                    runtime.enabled = enabled
                    runtime.transition_epoch = _increment_counter(runtime.transition_epoch)
                    runtime.half_open_lease_id = None
                    if same_route:
                        if not enabled:
                            runtime.state = BreakerState.DISABLED
                            runtime.open_until = None
                            runtime.action_required = False
                        elif not was_enabled:
                            runtime.state = BreakerState.UNKNOWN
                            runtime.open_until = None
                            runtime.action_required = False
                        runtime.outcomes = deque(runtime.outcomes, maxlen=policy.window_size)
                    else:
                        runtime.state = BreakerState.UNKNOWN if enabled else BreakerState.DISABLED
                        runtime.open_until = None
                        runtime.action_required = False
                        runtime.consecutive_successes = 0
                        runtime.consecutive_failures = 0
                        runtime.outcomes = deque(maxlen=policy.window_size)
                        runtime.open_count = 0
                        runtime.first_failed_at = None
                        runtime.last_failed_at = None
                        runtime.last_succeeded_at = None
                        runtime.last_failure_category = None
                        runtime.last_http_status = None
                        runtime.consecutive_protocol_failures = 0
                    self._routes[(key, config_revision, route_fingerprint)] = runtime
                    self._current_routes[key] = (config_revision, route_fingerprint)
                self._persist_locked()
                if previous_state is not None:
                    self._record_transition_locked(
                        previous_state,
                        runtime,
                        reason=self._configuration_transition_reason(previous_state, runtime),
                    )
            except Exception:
                self._restore_configure_locked(key, current_version, versions_before, active_before)
                raise
            self._prune_noncurrent_versions_locked(key)
            return self._snapshot_locked(runtime)

    def acquire(
        self,
        key: RouteKey,
        *,
        config_revision: int,
        route_fingerprint: str,
        attempt_id: str,
        manual_probe: bool = False,
        signal: BreakerSignal = BreakerSignal.BUSINESS,
    ) -> BreakerAdmission:
        _validate_revision_and_fingerprint(config_revision, route_fingerprint)
        _validate_attempt_id(attempt_id)
        signal = BreakerSignal.PROBE if manual_probe else BreakerSignal(signal)
        with self._lock:
            if self._persistence_uncertain:
                raise BreakerStateStoreError("breaker_state_commit_uncertain")
            runtime = self._routes.get((key, config_revision, route_fingerprint))
            if runtime is None:
                current_version = self._current_routes.get(key)
                if current_version is None:
                    return BreakerAdmission(False, BreakerState.UNKNOWN, denied=AdmissionDenied.UNKNOWN_ROUTE)
                return BreakerAdmission(
                    False,
                    self._routes[(key, *current_version)].state,
                    denied=AdmissionDenied.STALE_CONFIGURATION,
                )
            active_key = (key, config_revision, route_fingerprint, attempt_id)
            if active_key in self._active:
                return BreakerAdmission(
                    False,
                    runtime.state,
                    denied=AdmissionDenied.ATTEMPT_ALREADY_ACTIVE,
                )
            now = self._now()
            if runtime.state is BreakerState.DISABLED or not runtime.enabled:
                return BreakerAdmission(False, BreakerState.DISABLED, denied=AdmissionDenied.DISABLED)
            if runtime.state is BreakerState.OPEN_ACTION_REQUIRED:
                if not manual_probe:
                    return BreakerAdmission(
                        False,
                        runtime.state,
                        denied=AdmissionDenied.OPEN_ACTION_REQUIRED,
                    )
                self._transition_and_persist_locked(
                    runtime,
                    BreakerState.HALF_OPEN,
                    reason="manual_probe_started",
                    at=now,
                    signal=BreakerSignal.PROBE,
                )
            elif runtime.state is BreakerState.OPEN_TEMPORARY:
                if runtime.open_until is None or now < runtime.open_until:
                    return BreakerAdmission(
                        False,
                        runtime.state,
                        denied=AdmissionDenied.OPEN_TEMPORARY,
                        retry_at=runtime.open_until,
                    )
                self._transition_and_persist_locked(
                    runtime,
                    BreakerState.HALF_OPEN,
                    reason="manual_probe_started" if manual_probe else "cooldown_elapsed",
                    at=now,
                    signal=signal,
                )
            if (
                runtime.state is BreakerState.HALF_OPEN
                and runtime.action_required
                and not manual_probe
            ):
                return BreakerAdmission(
                    False,
                    runtime.state,
                    denied=AdmissionDenied.OPEN_ACTION_REQUIRED,
                )
            guarded_probe = runtime.state in {BreakerState.UNKNOWN, BreakerState.HALF_OPEN}
            if guarded_probe and self._guarded_lease_active_locked(
                key,
                route_fingerprint,
            ):
                return BreakerAdmission(
                    False,
                    runtime.state,
                    denied=AdmissionDenied.HALF_OPEN_BUSY,
                    retry_at=runtime.open_until,
                )
            lease_id = self._new_lease_id()
            half_open_probe = guarded_probe
            ticket = BreakerTicket(
                route_key=key,
                config_revision=config_revision,
                route_fingerprint=route_fingerprint,
                transition_epoch=runtime.transition_epoch,
                lease_id=lease_id,
                attempt_id=attempt_id,
                half_open_probe=half_open_probe,
                signal=signal,
            )
            self._active[active_key] = ticket
            if guarded_probe:
                runtime.half_open_lease_id = lease_id
            return BreakerAdmission(True, runtime.state, ticket=ticket)

    def preview_admission(
        self,
        key: RouteKey,
        *,
        config_revision: int,
        route_fingerprint: str,
        manual_probe: bool = False,
    ) -> BreakerAdmission:
        _validate_revision_and_fingerprint(config_revision, route_fingerprint)
        with self._lock:
            if self._persistence_uncertain:
                raise BreakerStateStoreError("breaker_state_commit_uncertain")
            runtime = self._routes.get((key, config_revision, route_fingerprint))
            if runtime is None:
                current_version = self._current_routes.get(key)
                if current_version is None:
                    return BreakerAdmission(False, BreakerState.UNKNOWN, denied=AdmissionDenied.UNKNOWN_ROUTE)
                return BreakerAdmission(
                    False,
                    self._routes[(key, *current_version)].state,
                    denied=AdmissionDenied.STALE_CONFIGURATION,
                )
            if runtime.state is BreakerState.DISABLED or not runtime.enabled:
                return BreakerAdmission(False, BreakerState.DISABLED, denied=AdmissionDenied.DISABLED)
            prospective_state = runtime.state
            if prospective_state is BreakerState.OPEN_ACTION_REQUIRED:
                if not manual_probe:
                    return BreakerAdmission(
                        False,
                        prospective_state,
                        denied=AdmissionDenied.OPEN_ACTION_REQUIRED,
                    )
                prospective_state = BreakerState.HALF_OPEN
            elif prospective_state is BreakerState.OPEN_TEMPORARY:
                now = self._now()
                if runtime.open_until is None or now < runtime.open_until:
                    return BreakerAdmission(
                        False,
                        prospective_state,
                        denied=AdmissionDenied.OPEN_TEMPORARY,
                        retry_at=runtime.open_until,
                    )
                prospective_state = BreakerState.HALF_OPEN
            if (
                prospective_state is BreakerState.HALF_OPEN
                and runtime.action_required
                and not manual_probe
            ):
                return BreakerAdmission(
                    False,
                    prospective_state,
                    denied=AdmissionDenied.OPEN_ACTION_REQUIRED,
                )
            if (
                prospective_state in {BreakerState.UNKNOWN, BreakerState.HALF_OPEN}
                and self._guarded_lease_active_locked(key, route_fingerprint)
            ):
                return BreakerAdmission(
                    False,
                    prospective_state,
                    denied=AdmissionDenied.HALF_OPEN_BUSY,
                    retry_at=runtime.open_until,
                )
            return BreakerAdmission(True, prospective_state)

    def record_success(self, ticket: BreakerTicket) -> ObservationResult:
        with self._lock:
            observation = self._begin_observation_locked(ticket)
            if observation is None:
                return ObservationResult.IGNORED
            runtime, before, active_before = observation
            try:
                now = self._now()
                if ticket.signal is BreakerSignal.PROBE:
                    if runtime.state is BreakerState.UNKNOWN:
                        runtime.last_succeeded_at = now
                        self._transition_locked(runtime, BreakerState.CLOSED)
                        runtime.open_count = 0
                        runtime.open_until = None
                        runtime.action_required = False
                    elif runtime.state is BreakerState.HALF_OPEN:
                        runtime.consecutive_successes = min(
                            runtime.consecutive_successes + 1,
                            runtime.policy.recovery_success_threshold,
                        )
                        runtime.last_succeeded_at = now
                        if runtime.consecutive_successes >= runtime.policy.recovery_success_threshold:
                            self._transition_locked(runtime, BreakerState.CLOSED)
                            runtime.open_count = 0
                            runtime.open_until = None
                            runtime.action_required = False
                    self._persist_locked()
                    self._record_transition_locked(
                        before.state,
                        runtime,
                        reason="probe_succeeded",
                        at=now,
                        signal=ticket.signal,
                    )
                    return ObservationResult.APPLIED
                runtime.outcomes.append(False)
                runtime.consecutive_failures = 0
                runtime.consecutive_protocol_failures = 0
                runtime.consecutive_successes = min(
                    runtime.consecutive_successes + 1,
                    runtime.policy.recovery_success_threshold,
                )
                runtime.last_succeeded_at = now
                if runtime.state is BreakerState.UNKNOWN:
                    self._transition_locked(runtime, BreakerState.CLOSED)
                    runtime.open_count = 0
                    runtime.action_required = False
                elif runtime.state is BreakerState.HALF_OPEN:
                    if runtime.consecutive_successes >= runtime.policy.recovery_success_threshold:
                        recovery_successes = runtime.consecutive_successes
                        self._transition_locked(runtime, BreakerState.CLOSED)
                        runtime.outcomes.clear()
                        runtime.outcomes.extend(False for _ in range(recovery_successes))
                        runtime.open_count = 0
                        runtime.open_until = None
                        runtime.action_required = False
                self._persist_locked()
                self._record_transition_locked(
                    before.state,
                    runtime,
                    reason="business_succeeded",
                    at=now,
                    signal=ticket.signal,
                )
            except Exception:
                self._restore_runtime_locked(before, active_before)
                raise
            return ObservationResult.APPLIED

    def record_temporary_failure(
        self,
        ticket: BreakerTicket,
        *,
        failure_category: str,
        http_status: int | None = None,
    ) -> ObservationResult:
        return self._record_failure(
            ticket,
            failure_category=failure_category,
            immediate_open=False,
            retry_after_seconds=None,
            action_required=False,
            http_status=http_status,
        )

    def record_rate_limited(
        self,
        ticket: BreakerTicket,
        *,
        retry_after_seconds: float | None,
        failure_category: str = "rate_limited",
        http_status: int | None = 429,
    ) -> ObservationResult:
        return self._record_failure(
            ticket,
            failure_category=failure_category,
            immediate_open=True,
            retry_after_seconds=retry_after_seconds,
            action_required=False,
            http_status=http_status,
        )

    def record_action_required(
        self,
        ticket: BreakerTicket,
        *,
        failure_category: str,
        http_status: int | None = None,
    ) -> ObservationResult:
        return self._record_failure(
            ticket,
            failure_category=failure_category,
            immediate_open=True,
            retry_after_seconds=None,
            action_required=True,
            http_status=http_status,
        )

    def record_protocol_failure(
        self,
        ticket: BreakerTicket,
        *,
        failure_category: str,
        http_status: int | None = None,
    ) -> ObservationResult:
        _validate_category(failure_category)
        with self._lock:
            runtime = self._matching_runtime_locked(ticket)
            if runtime is None:
                return ObservationResult.IGNORED
            next_count = runtime.consecutive_protocol_failures + 1
            return self._record_failure(
                ticket,
                failure_category=failure_category,
                immediate_open=False,
                retry_after_seconds=None,
                action_required=next_count >= runtime.policy.protocol_failure_threshold,
                protocol_failure=True,
                http_status=http_status,
            )

    def record_cancelled(self, ticket: BreakerTicket) -> ObservationResult:
        with self._lock:
            observation = self._begin_observation_locked(ticket)
            if observation is None:
                return ObservationResult.IGNORED
            runtime, before, active_before = observation
            if runtime.state is BreakerState.HALF_OPEN and runtime.action_required:
                try:
                    self._transition_locked(runtime, BreakerState.OPEN_ACTION_REQUIRED)
                    self._persist_locked()
                    self._record_transition_locked(
                        before.state,
                        runtime,
                        reason="probe_cancelled",
                        signal=ticket.signal,
                    )
                except Exception:
                    self._restore_runtime_locked(before, active_before)
                    raise
            return ObservationResult.APPLIED

    def abandon(self, ticket: BreakerTicket) -> ObservationResult:
        """Release attempt-only state without changing persisted breaker evidence."""
        with self._lock:
            runtime = self._matching_runtime_locked(ticket)
            if runtime is None:
                return ObservationResult.IGNORED
            version_key = (
                ticket.route_key,
                ticket.config_revision,
                ticket.route_fingerprint,
            )
            self._active.pop((*version_key, ticket.attempt_id), None)
            if runtime.half_open_lease_id == ticket.lease_id:
                runtime.half_open_lease_id = None
            self._prune_version_locked(version_key)
            return ObservationResult.APPLIED

    def snapshot(self, key: RouteKey) -> BreakerSnapshot | None:
        with self._lock:
            version = self._current_routes.get(key)
            runtime = None if version is None else self._routes.get((key, *version))
            return None if runtime is None else self._snapshot_locked(runtime)

    def snapshot_version(
        self,
        key: RouteKey,
        *,
        config_revision: int,
        route_fingerprint: str,
    ) -> BreakerSnapshot | None:
        with self._lock:
            runtime = self._routes.get((key, config_revision, route_fingerprint))
            return None if runtime is None else self._snapshot_locked(runtime)

    def pin_versions(
        self,
        versions: tuple[tuple[RouteKey, int, str], ...],
    ) -> None:
        with self._lock:
            if not versions or len(set(versions)) != len(versions):
                raise ValueError("breaker_version_pin_invalid")
            if any(version not in self._routes for version in versions):
                raise RuntimeError("breaker_version_stale")
            for version in versions:
                self._pins[version] = self._pins.get(version, 0) + 1

    def release_versions(
        self,
        versions: tuple[tuple[RouteKey, int, str], ...],
    ) -> None:
        with self._lock:
            for version in versions:
                count = self._pins.get(version)
                if count is None or count <= 0:
                    raise RuntimeError("breaker_version_pin_underflow")
                if count == 1:
                    self._pins.pop(version)
                else:
                    self._pins[version] = count - 1
                self._prune_version_locked(version)

    def snapshots(self) -> tuple[BreakerSnapshot, ...]:
        with self._lock:
            return tuple(
                self._snapshot_locked(self._routes[(key, *self._current_routes[key])])
                for key in sorted(
                    self._current_routes,
                    key=lambda item: (item.instance_id, item.group_id, item.route_role, item.profile_id),
                )
            )

    def transition_events(self) -> tuple[BreakerTransition, ...]:
        with self._lock:
            return tuple(self._transition_events)

    def active_pin_count(self) -> int:
        with self._lock:
            return sum(self._pins.values())

    def export_state(self) -> dict[str, object]:
        with self._lock:
            return self._export_state_locked()

    def restore(self, document: Mapping[str, object]) -> int:
        with self._lock:
            if self._active:
                raise RuntimeError("breaker_restore_requires_no_active_attempts")
            routes_before = {key: runtime.clone() for key, runtime in self._routes.items()}
            current_before = dict(self._current_routes)
            active_before = dict(self._active)
            try:
                restored = self._restore_locked(document)
                self._persist_locked()
                self._record_restored_transitions_locked(routes_before)
            except Exception:
                self._routes = routes_before
                self._current_routes = current_before
                self._active = active_before
                raise
            return restored

    def _restore_locked(self, document: Mapping[str, object]) -> int:
            routes = _validate_document(document)
            seen: set[RouteKey] = set()
            restored = 0
            now = self._now()
            for payload in routes:
                try:
                    key = RouteKey(
                        instance_id=_required_string(payload, "instance_id"),
                        group_id=_required_string(payload, "group_id"),
                        route_role=_required_string(payload, "route_role"),
                        profile_id=_required_string(payload, "profile_id"),
                    )
                except ValueError as exc:
                    raise BreakerStateStoreError("breaker_state_route_identity_invalid") from exc
                if key in seen:
                    raise BreakerStateStoreError("breaker_state_duplicate_route")
                seen.add(key)
                version = self._current_routes.get(key)
                runtime = None if version is None else self._routes.get((key, *version))
                if runtime is None:
                    continue
                revision = _required_nonnegative_int(payload, "config_revision", minimum=1)
                fingerprint = _required_string(payload, "route_fingerprint")
                try:
                    _validate_revision_and_fingerprint(revision, fingerprint)
                except ValueError as exc:
                    raise BreakerStateStoreError("breaker_state_route_version_invalid") from exc
                enabled = _required_bool(payload, "enabled")
                if (
                    revision != runtime.config_revision
                    or fingerprint != runtime.route_fingerprint
                    or enabled != runtime.enabled
                ):
                    continue
                state = _required_state(payload, "state")
                transition_epoch = _required_nonnegative_int(payload, "transition_epoch", minimum=1)
                consecutive_failures = _required_nonnegative_int(payload, "consecutive_failures")
                consecutive_protocol_failures = _required_nonnegative_int(
                    payload,
                    "consecutive_protocol_failures",
                )
                consecutive_successes = _required_nonnegative_int(payload, "consecutive_successes")
                outcomes_value = payload.get("outcomes")
                if (
                    not isinstance(outcomes_value, list)
                    or len(outcomes_value) > 10_000
                    or any(type(value) is not bool for value in outcomes_value)
                ):
                    raise BreakerStateStoreError("breaker_state_outcomes_invalid")
                outcomes = outcomes_value[-runtime.policy.window_size :]
                open_count = _required_nonnegative_int(payload, "open_count")
                first_failed_at = _optional_datetime(payload, "first_failed_at")
                last_failed_at = _optional_datetime(payload, "last_failed_at")
                last_succeeded_at = _optional_datetime(payload, "last_succeeded_at")
                open_until = _optional_datetime(payload, "open_until")
                category = _optional_category(payload, "last_failure_category")
                last_http_status = _optional_http_status(payload, "last_http_status")
                action_required = _required_bool(payload, "action_required")
                if not enabled:
                    state = BreakerState.DISABLED
                elif state is BreakerState.DISABLED:
                    raise BreakerStateStoreError("breaker_state_enabled_disabled_conflict")
                elif state is BreakerState.HALF_OPEN:
                    transition_epoch = _increment_counter(
                        transition_epoch,
                        error_type=BreakerStateStoreError,
                    )
                    if action_required:
                        state = BreakerState.OPEN_ACTION_REQUIRED
                        open_until = None
                    else:
                        state = BreakerState.OPEN_TEMPORARY
                        minimum_open = now + timedelta(seconds=runtime.policy.base_cooldown_seconds)
                        open_until = max(open_until or minimum_open, minimum_open)
                elif state is BreakerState.OPEN_TEMPORARY and open_until is None:
                    open_until = now + timedelta(seconds=runtime.policy.base_cooldown_seconds)
                if state is BreakerState.OPEN_ACTION_REQUIRED:
                    action_required = True
                    open_until = None
                elif action_required:
                    raise BreakerStateStoreError("breaker_state_action_flag_invalid")
                runtime.state = state
                runtime.transition_epoch = transition_epoch
                runtime.consecutive_failures = consecutive_failures
                runtime.consecutive_protocol_failures = consecutive_protocol_failures
                runtime.consecutive_successes = consecutive_successes
                runtime.outcomes = deque(outcomes, maxlen=runtime.policy.window_size)
                runtime.open_count = open_count
                runtime.open_until = open_until
                runtime.first_failed_at = first_failed_at
                runtime.last_failed_at = last_failed_at
                runtime.last_succeeded_at = last_succeeded_at
                runtime.last_failure_category = category
                runtime.last_http_status = last_http_status
                runtime.action_required = action_required
                runtime.half_open_lease_id = None
                self._invalidate_active_locked(key)
                restored += 1
            return restored

    def restore_from_store(self, store: BreakerStateStore) -> int:
        with self._lock:
            if self._persistence_uncertain:
                raise BreakerStateStoreError("breaker_state_commit_uncertain")
            if self._store is not None and self._store is not store:
                raise RuntimeError("breaker_state_store_already_attached")
            if self._active:
                raise RuntimeError("breaker_restore_requires_no_active_attempts")
            document = store.load()
            routes_before = {key: runtime.clone() for key, runtime in self._routes.items()}
            current_before = dict(self._current_routes)
            active_before = dict(self._active)
            try:
                restored = 0 if document is None else self._restore_locked(document)
                store.save(self._export_state_locked())
                self._store = store
                self._record_restored_transitions_locked(routes_before)
                return restored
            except Exception:
                self._routes = routes_before
                self._current_routes = current_before
                self._active = active_before
                raise

    def attach_store(self, store: BreakerStateStore) -> None:
        with self._lock:
            if self._persistence_uncertain:
                raise BreakerStateStoreError("breaker_state_commit_uncertain")
            if self._store is not None and self._store is not store:
                raise RuntimeError("breaker_state_store_already_attached")
            store.save(self._export_state_locked())
            self._store = store

    def _record_failure(
        self,
        ticket: BreakerTicket,
        *,
        failure_category: str,
        immediate_open: bool,
        retry_after_seconds: float | None,
        action_required: bool,
        protocol_failure: bool = False,
        http_status: int | None = None,
    ) -> ObservationResult:
        _validate_category(failure_category)
        _validate_http_status(http_status)
        with self._lock:
            observation = self._begin_observation_locked(ticket)
            if observation is None:
                return ObservationResult.IGNORED
            runtime, before, active_before = observation
            try:
                now = self._now()
                if ticket.signal is BreakerSignal.PROBE:
                    runtime.consecutive_successes = 0
                    runtime.first_failed_at = runtime.first_failed_at or now
                    runtime.last_failed_at = now
                    runtime.last_failure_category = failure_category
                    runtime.last_http_status = http_status
                    if action_required:
                        runtime.action_required = True
                        runtime.open_until = None
                        self._transition_locked(runtime, BreakerState.OPEN_ACTION_REQUIRED)
                    elif runtime.state is BreakerState.HALF_OPEN:
                        if runtime.action_required:
                            runtime.open_until = None
                            self._transition_locked(runtime, BreakerState.OPEN_ACTION_REQUIRED)
                        else:
                            self._open_temporary_locked(runtime, now, retry_after_seconds)
                    elif runtime.state is BreakerState.UNKNOWN:
                        self._open_temporary_locked(runtime, now, retry_after_seconds)
                    self._persist_locked()
                    self._record_transition_locked(
                        before.state,
                        runtime,
                        reason="probe_failed",
                        at=now,
                        failure_category=failure_category,
                        http_status=http_status,
                        signal=ticket.signal,
                    )
                    return ObservationResult.APPLIED
                runtime.outcomes.append(True)
                runtime.consecutive_failures += 1
                if protocol_failure:
                    runtime.consecutive_protocol_failures += 1
                else:
                    runtime.consecutive_protocol_failures = 0
                runtime.consecutive_successes = 0
                runtime.first_failed_at = runtime.first_failed_at or now
                runtime.last_failed_at = now
                runtime.last_failure_category = failure_category
                runtime.last_http_status = http_status
                if action_required:
                    runtime.action_required = True
                    runtime.open_until = None
                    self._transition_locked(runtime, BreakerState.OPEN_ACTION_REQUIRED)
                else:
                    if runtime.state is BreakerState.HALF_OPEN and runtime.action_required:
                        runtime.open_until = None
                        self._transition_locked(runtime, BreakerState.OPEN_ACTION_REQUIRED)
                        self._persist_locked()
                        self._record_transition_locked(
                            before.state,
                            runtime,
                            reason="business_failed",
                            at=now,
                            failure_category=failure_category,
                            http_status=http_status,
                            signal=ticket.signal,
                        )
                        return ObservationResult.APPLIED
                    should_open = (
                        immediate_open
                        or runtime.state is BreakerState.HALF_OPEN
                        or runtime.consecutive_failures >= runtime.policy.failure_threshold
                        or self._error_rate_opens(runtime)
                    )
                    if should_open:
                        self._open_temporary_locked(runtime, now, retry_after_seconds)
                self._persist_locked()
                self._record_transition_locked(
                    before.state,
                    runtime,
                    reason="business_failed",
                    at=now,
                    failure_category=failure_category,
                    http_status=http_status,
                    signal=ticket.signal,
                )
            except Exception:
                self._restore_runtime_locked(before, active_before)
                raise
            return ObservationResult.APPLIED

    def _error_rate_opens(self, runtime: _RouteRuntime) -> bool:
        threshold = runtime.policy.error_rate_threshold
        sample_count = len(runtime.outcomes)
        return (
            threshold is not None
            and sample_count >= runtime.policy.minimum_samples
            and sum(runtime.outcomes) / sample_count >= threshold
        )

    def _open_temporary_locked(
        self,
        runtime: _RouteRuntime,
        now: datetime,
        retry_after_seconds: float | None,
    ) -> None:
        runtime.open_count = min(runtime.open_count + 1, 63)
        exponent = min(runtime.open_count - 1, 62)
        raw_backoff = runtime.policy.base_cooldown_seconds * (2**exponent)
        backoff = min(raw_backoff, runtime.policy.max_cooldown_seconds)
        jitter = backoff * runtime.policy.jitter_ratio * self._random_fraction()
        cooldown = min(backoff + jitter, runtime.policy.max_cooldown_seconds)
        normalized_retry_after = _validate_retry_after_seconds(retry_after_seconds)
        if normalized_retry_after is not None:
            cooldown = min(
                max(cooldown, normalized_retry_after),
                runtime.policy.max_cooldown_seconds,
            )
        runtime.open_until = now + timedelta(seconds=cooldown)
        self._transition_locked(runtime, BreakerState.OPEN_TEMPORARY)

    def _transition_and_persist_locked(
        self,
        runtime: _RouteRuntime,
        state: BreakerState,
        *,
        reason: str,
        at: datetime,
        signal: BreakerSignal | None,
    ) -> None:
        before = runtime.clone()
        active_before = self._active_for_route_locked(runtime.key)
        try:
            self._transition_locked(runtime, state)
            self._persist_locked()
            self._record_transition_locked(
                before.state,
                runtime,
                reason=reason,
                at=at,
                signal=signal,
            )
        except Exception:
            self._restore_runtime_locked(before, active_before)
            raise

    def _transition_locked(self, runtime: _RouteRuntime, state: BreakerState) -> None:
        if runtime.state is state:
            return
        runtime.state = state
        runtime.transition_epoch = _increment_counter(runtime.transition_epoch)
        runtime.half_open_lease_id = None
        self._invalidate_active_locked(
            runtime.key,
            runtime.config_revision,
            runtime.route_fingerprint,
        )

    def _record_transition_locked(
        self,
        old_state: BreakerState,
        runtime: _RouteRuntime,
        *,
        reason: str,
        at: datetime | None = None,
        failure_category: str | None = None,
        http_status: int | None = None,
        signal: BreakerSignal | None = None,
    ) -> None:
        if old_state is runtime.state:
            return
        if reason not in _TRANSITION_REASONS:
            raise RuntimeError("breaker_transition_reason_invalid")
        if failure_category is not None:
            _validate_category(failure_category)
        _validate_http_status(http_status)
        timestamp = self._now() if at is None else _as_utc(at)
        event = BreakerTransition(
            event_id=uuid.uuid4().hex,
            timestamp=_format_datetime(timestamp) or "",
            route_key=runtime.key,
            config_revision=runtime.config_revision,
            transition_epoch=runtime.transition_epoch,
            old_state=old_state,
            new_state=runtime.state,
            reason=reason,
            failure_category=failure_category,
            http_status=http_status,
            signal=signal,
        )
        if self._transition_batches:
            self._transition_batches[-1].append(event)
        else:
            self._transition_events.append(event)

    def _begin_transition_batch_locked(self) -> None:
        self._transition_batches.append([])

    def _commit_transition_batch_locked(self) -> None:
        if not self._transition_batches:
            raise RuntimeError("breaker_transition_batch_missing")
        events = self._transition_batches.pop()
        if self._transition_batches:
            self._transition_batches[-1].extend(events)
        else:
            self._transition_events.extend(events)

    def _rollback_transition_batch_locked(self) -> None:
        if not self._transition_batches:
            raise RuntimeError("breaker_transition_batch_missing")
        self._transition_batches.pop()

    @staticmethod
    def _configuration_transition_reason(
        old_state: BreakerState,
        runtime: _RouteRuntime,
    ) -> str:
        if runtime.state is BreakerState.DISABLED:
            return "configuration_disabled"
        if old_state is BreakerState.DISABLED:
            return "configuration_enabled"
        return "configuration_replaced"

    def _record_restored_transitions_locked(
        self,
        before: Mapping[tuple[RouteKey, int, str], _RouteRuntime],
    ) -> None:
        at = self._now()
        for version_key, previous in before.items():
            runtime = self._routes.get(version_key)
            if runtime is not None:
                self._record_transition_locked(
                    previous.state,
                    runtime,
                    reason="state_restored",
                    at=at,
                )

    def _begin_observation_locked(
        self,
        ticket: BreakerTicket,
    ) -> tuple[_RouteRuntime, _RouteRuntime, dict[tuple[RouteKey, int, str, str], BreakerTicket]] | None:
        runtime = self._matching_runtime_locked(ticket)
        if runtime is None:
            return None
        before = runtime.clone()
        active_before = self._active_for_route_locked(ticket.route_key)
        self._active.pop(
            (ticket.route_key, ticket.config_revision, ticket.route_fingerprint, ticket.attempt_id),
            None,
        )
        if runtime.half_open_lease_id == ticket.lease_id:
            runtime.half_open_lease_id = None
        self._prune_version_locked(
            (ticket.route_key, ticket.config_revision, ticket.route_fingerprint)
        )
        return runtime, before, active_before

    def _matching_runtime_locked(self, ticket: BreakerTicket) -> _RouteRuntime | None:
        version_key = (ticket.route_key, ticket.config_revision, ticket.route_fingerprint)
        runtime = self._routes.get(version_key)
        active = self._active.get((*version_key, ticket.attempt_id))
        if runtime is None or active != ticket:
            return None
        if (
            runtime.config_revision != ticket.config_revision
            or runtime.route_fingerprint != ticket.route_fingerprint
            or runtime.transition_epoch != ticket.transition_epoch
        ):
            return None
        if ticket.half_open_probe and runtime.half_open_lease_id != ticket.lease_id:
            return None
        return runtime

    def _snapshot_locked(self, runtime: _RouteRuntime) -> BreakerSnapshot:
        failures = sum(runtime.outcomes)
        samples = len(runtime.outcomes)
        return BreakerSnapshot(
            route_key=runtime.key,
            config_revision=runtime.config_revision,
            route_fingerprint=runtime.route_fingerprint,
            transition_epoch=runtime.transition_epoch,
            state=runtime.state,
            consecutive_failures=runtime.consecutive_failures,
            consecutive_protocol_failures=runtime.consecutive_protocol_failures,
            consecutive_successes=runtime.consecutive_successes,
            sample_count=samples,
            failure_count=failures,
            error_rate=failures / samples if samples else 0.0,
            open_count=runtime.open_count,
            open_until=runtime.open_until,
            first_failed_at=runtime.first_failed_at,
            last_failed_at=runtime.last_failed_at,
            last_succeeded_at=runtime.last_succeeded_at,
            last_failure_category=runtime.last_failure_category,
            last_http_status=runtime.last_http_status,
            action_required=runtime.action_required,
            half_open_lease_active=runtime.half_open_lease_id is not None,
        )

    def _persist_locked(self) -> None:
        if self._persistence_uncertain:
            raise BreakerStateStoreError("breaker_state_commit_uncertain")
        if self._store is not None:
            try:
                self._store.save(self._export_state_locked())
            except BreakerStateStoreError as exc:
                if str(exc) == "breaker_state_commit_uncertain":
                    self._persistence_uncertain = True
                raise

    def _export_state_locked(self) -> dict[str, object]:
        routes: list[dict[str, object]] = []
        for snapshot in (
            self._snapshot_locked(self._routes[(key, *self._current_routes[key])])
            for key in sorted(
                self._current_routes,
                key=lambda item: (item.instance_id, item.group_id, item.route_role, item.profile_id),
            )
        ):
            runtime = self._routes[
                (snapshot.route_key, snapshot.config_revision, snapshot.route_fingerprint)
            ]
            routes.append(
                {
                    "instance_id": snapshot.route_key.instance_id,
                    "group_id": snapshot.route_key.group_id,
                    "route_role": snapshot.route_key.route_role,
                    "profile_id": snapshot.route_key.profile_id,
                    "config_revision": snapshot.config_revision,
                    "route_fingerprint": snapshot.route_fingerprint,
                    "enabled": runtime.enabled,
                    "state": snapshot.state.value,
                    "transition_epoch": snapshot.transition_epoch,
                    "consecutive_failures": snapshot.consecutive_failures,
                    "consecutive_protocol_failures": snapshot.consecutive_protocol_failures,
                    "consecutive_successes": snapshot.consecutive_successes,
                    "outcomes": list(runtime.outcomes),
                    "open_count": snapshot.open_count,
                    "open_until": _format_datetime(snapshot.open_until),
                    "first_failed_at": _format_datetime(snapshot.first_failed_at),
                    "last_failed_at": _format_datetime(snapshot.last_failed_at),
                    "last_succeeded_at": _format_datetime(snapshot.last_succeeded_at),
                    "last_failure_category": snapshot.last_failure_category,
                    "last_http_status": snapshot.last_http_status,
                    "action_required": snapshot.action_required,
                }
            )
        return {"schema_version": 2, "routes": routes}

    def _active_for_route_locked(
        self,
        key: RouteKey,
    ) -> dict[tuple[RouteKey, int, str, str], BreakerTicket]:
        return {
            active_key: ticket
            for active_key, ticket in self._active.items()
            if active_key[0] == key
        }

    def _guarded_lease_active_locked(
        self,
        key: RouteKey,
        route_fingerprint: str,
    ) -> bool:
        return any(
            ticket.half_open_probe
            and ticket.route_key == key
            and ticket.route_fingerprint == route_fingerprint
            for ticket in self._active.values()
        )

    def _invalidate_active_locked(
        self,
        key: RouteKey,
        config_revision: int | None = None,
        route_fingerprint: str | None = None,
    ) -> None:
        for active_key in tuple(self._active):
            if (
                active_key[0] == key
                and (config_revision is None or active_key[1] == config_revision)
                and (route_fingerprint is None or active_key[2] == route_fingerprint)
            ):
                self._active.pop(active_key, None)

    def _restore_runtime_locked(
        self,
        runtime: _RouteRuntime,
        active: Mapping[tuple[RouteKey, int, str, str], BreakerTicket],
    ) -> None:
        version_key = (runtime.key, runtime.config_revision, runtime.route_fingerprint)
        self._invalidate_active_locked(*version_key)
        self._active.update(active)
        self._routes[version_key] = runtime

    def _restore_configure_locked(
        self,
        key: RouteKey,
        current_version: tuple[int, str] | None,
        versions: Mapping[tuple[RouteKey, int, str], _RouteRuntime],
        active: Mapping[tuple[RouteKey, int, str, str], BreakerTicket],
    ) -> None:
        self._invalidate_active_locked(key)
        self._active.update(active)
        for version_key in tuple(self._routes):
            if version_key[0] == key:
                self._routes.pop(version_key, None)
        self._routes.update(versions)
        if current_version is None:
            self._current_routes.pop(key, None)
        else:
            self._current_routes[key] = current_version

    def _prune_version_locked(self, version_key: tuple[RouteKey, int, str]) -> None:
        if self._current_routes.get(version_key[0]) == version_key[1:]:
            return
        if self._pins.get(version_key, 0) > 0:
            return
        if any(active_key[:3] == version_key for active_key in self._active):
            return
        self._routes.pop(version_key, None)

    def _prune_noncurrent_versions_locked(self, key: RouteKey) -> None:
        for version_key in tuple(self._routes):
            if version_key[0] == key:
                self._prune_version_locked(version_key)

    def _retire_unregistered_group_routes_locked(
        self,
        registrations: tuple[RouteRegistration, ...],
    ) -> None:
        desired = {item.key for item in registrations}
        instance_id = registrations[0].key.instance_id
        group_id = registrations[0].key.group_id
        for key in tuple(self._current_routes):
            if key.instance_id == instance_id and key.group_id == group_id and key not in desired:
                self._current_routes.pop(key, None)
                self._prune_noncurrent_versions_locked(key)

    def _retire_unregistered_instance_routes_locked(
        self,
        registrations: tuple[RouteRegistration, ...],
    ) -> None:
        desired = {item.key for item in registrations}
        instance_id = registrations[0].key.instance_id
        for key in tuple(self._current_routes):
            if key.instance_id == instance_id and key not in desired:
                self._current_routes.pop(key, None)
                self._prune_noncurrent_versions_locked(key)

    def _now(self) -> datetime:
        return _as_utc(self._clock())

    def _random_fraction(self) -> float:
        value = self._rng()
        if not isinstance(value, (float, int)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("breaker_rng_value_invalid")
        return float(value)

    def _new_lease_id(self) -> str:
        value = self._lease_factory()
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ValueError("breaker_lease_id_invalid")
        self._lease_sequence = _increment_counter(self._lease_sequence)
        material = f"{self._lease_sequence}:{value}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()


_ROUTE_STATE_FIELDS = {
    "instance_id",
    "group_id",
    "route_role",
    "profile_id",
    "config_revision",
    "route_fingerprint",
    "enabled",
    "state",
    "transition_epoch",
    "consecutive_failures",
    "consecutive_protocol_failures",
    "consecutive_successes",
    "outcomes",
    "open_count",
    "open_until",
    "first_failed_at",
    "last_failed_at",
    "last_succeeded_at",
    "last_failure_category",
    "last_http_status",
    "action_required",
}
_ROUTE_STATE_FIELDS_LEGACY = _ROUTE_STATE_FIELDS - {"last_http_status"}


def _validate_document(document: Mapping[str, object]) -> list[Mapping[str, object]]:
    schema_version = document.get("schema_version")
    if (
        set(document) != {"schema_version", "routes"}
        or type(schema_version) is not int
        or schema_version not in {1, 2}
    ):
        raise BreakerStateStoreError("breaker_state_schema_invalid")
    routes = document.get("routes")
    if not isinstance(routes, list) or len(routes) > 10_000:
        raise BreakerStateStoreError("breaker_state_routes_invalid")
    result: list[Mapping[str, object]] = []
    for route in routes:
        expected_fields = _ROUTE_STATE_FIELDS_LEGACY if schema_version == 1 else _ROUTE_STATE_FIELDS
        if not isinstance(route, Mapping) or frozenset(route) != frozenset(expected_fields):
            raise BreakerStateStoreError("breaker_state_route_schema_invalid")
        result.append(route)
    return result


def _required_string(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise BreakerStateStoreError("breaker_state_string_invalid")
    return value


def _required_bool(payload: Mapping[str, object], name: str) -> bool:
    value = payload.get(name)
    if type(value) is not bool:
        raise BreakerStateStoreError("breaker_state_boolean_invalid")
    return value


def _required_nonnegative_int(
    payload: Mapping[str, object],
    name: str,
    *,
    minimum: int = 0,
) -> int:
    value = payload.get(name)
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        raise BreakerStateStoreError("breaker_state_integer_invalid")
    return value


def _required_state(payload: Mapping[str, object], name: str) -> BreakerState:
    try:
        return BreakerState(_required_string(payload, name))
    except ValueError as exc:
        raise BreakerStateStoreError("breaker_state_value_invalid") from exc


def _optional_datetime(payload: Mapping[str, object], name: str) -> datetime | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise BreakerStateStoreError("breaker_state_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BreakerStateStoreError("breaker_state_timestamp_invalid") from exc
    try:
        return _as_utc(parsed)
    except ValueError as exc:
        raise BreakerStateStoreError("breaker_state_timestamp_invalid") from exc


def _optional_category(payload: Mapping[str, object], name: str) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise BreakerStateStoreError("breaker_state_category_invalid")
    try:
        _validate_category(value)
    except ValueError as exc:
        raise BreakerStateStoreError("breaker_state_category_invalid") from exc
    return value


def _optional_http_status(payload: Mapping[str, object], name: str) -> int | None:
    value = payload.get(name)
    try:
        _validate_http_status(value)
    except ValueError as exc:
        raise BreakerStateStoreError("breaker_state_http_status_invalid") from exc
    return value


def _format_datetime(value: datetime | None) -> str | None:
    return None if value is None else _as_utc(value).isoformat().replace("+00:00", "Z")


def _validate_revision_and_fingerprint(revision: int, fingerprint: str) -> None:
    if type(revision) is not int or revision <= 0:
        raise ValueError("breaker_config_revision_invalid")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise ValueError("breaker_route_fingerprint_invalid")


def _validate_attempt_id(attempt_id: str) -> None:
    if not isinstance(attempt_id, str) or not _IDENTIFIER.fullmatch(attempt_id):
        raise ValueError("breaker_attempt_id_invalid")


def _validate_category(category: str) -> None:
    try:
        validate_failure_category(category)
    except ValueError as exc:
        raise ValueError("breaker_failure_category_invalid") from exc
    if not _CATEGORY.fullmatch(category):
        raise ValueError("breaker_failure_category_invalid")


def _validate_http_status(value: int | None) -> None:
    if value is not None and (type(value) is not int or not 100 <= value <= 599):
        raise ValueError("breaker_http_status_invalid")


def _validate_retry_after_seconds(value: float | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("breaker_retry_after_invalid")
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("breaker_retry_after_invalid")
    return seconds


def _as_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("breaker_clock_requires_aware_datetime")
    return value.astimezone(UTC)


def _increment_counter(
    value: int,
    *,
    error_type: type[Exception] = RuntimeError,
) -> int:
    if type(value) is not int or not 0 <= value < _MAX_COUNTER:
        raise error_type("breaker_counter_exhausted")
    return value + 1
