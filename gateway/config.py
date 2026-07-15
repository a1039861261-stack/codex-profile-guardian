from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
from types import MappingProxyType
from typing import Mapping, Protocol
from threading import Lock

from .cancellation import CancellationToken
from .models import AttemptResult, RequestSnapshot


class AttemptRunner(Protocol):
    async def run(
        self,
        snapshot: RequestSnapshot,
        bearer: str,
        cancellation: CancellationToken,
    ) -> AttemptResult: ...


class SecretResolver(Protocol):
    def resolve(self, secret_ref: str) -> str: ...


class BreakerPolicyLike(Protocol):
    failure_threshold: int
    protocol_failure_threshold: int
    error_rate_threshold: float | None
    minimum_samples: int
    window_size: int
    recovery_success_threshold: int
    base_cooldown_seconds: float
    max_cooldown_seconds: float
    jitter_ratio: float


class RouteRole(StrEnum):
    PRIMARY = "primary"
    BACKUP = "backup"


@dataclass(frozen=True, slots=True)
class RouteIdentity:
    role: RouteRole
    profile_id: str
    fingerprint: str
    adapter_name: str


@dataclass(frozen=True, slots=True)
class PublicRouteIdentity:
    role: RouteRole
    profile_id: str
    adapter_name: str


@dataclass(frozen=True, slots=True)
class FailoverGroupIdentity:
    instance_id: str
    group_id: str
    revision: int
    primary: RouteIdentity
    backup: RouteIdentity


@dataclass(frozen=True, slots=True)
class PublicFailoverGroupIdentity:
    instance_id: str
    group_id: str
    revision: int
    primary: PublicRouteIdentity
    backup: PublicRouteIdentity


@dataclass(frozen=True, slots=True)
class FailoverGroupSchema:
    schema_version: int
    revision: int
    instance_id: str
    active_group_id: str
    groups: tuple[FailoverGroupIdentity, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1 or self.revision <= 0 or not self.instance_id or not self.active_group_id:
            raise ValueError("failover_group_schema_invalid")
        if not self.groups or self.active_group_id not in {group.group_id for group in self.groups}:
            raise ValueError("failover_active_group_invalid")
        object.__setattr__(self, "groups", tuple(self.groups))


class StateCompatibility(StrEnum):
    SHARED = "shared"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class ProbeMode(StrEnum):
    MODELS = "models"
    RESPONSES = "responses"


@dataclass(frozen=True, slots=True)
class ProbePolicy:
    enabled: bool = False
    mode: ProbeMode = ProbeMode.MODELS
    interval_seconds: float = 300.0
    timeout_seconds: float = 5.0
    allow_billable: bool = False
    allow_action_required_auto_retest: bool = False

    def __post_init__(self) -> None:
        if not 30 <= self.interval_seconds <= 7 * 24 * 60 * 60:
            raise ValueError("probe_interval_invalid")
        if not 0 < self.timeout_seconds <= 60:
            raise ValueError("probe_timeout_invalid")
        if self.mode is ProbeMode.RESPONSES and self.enabled and not self.allow_billable:
            raise ValueError("billable_probe_requires_explicit_opt_in")
        if self.mode is ProbeMode.MODELS and self.allow_billable:
            raise ValueError("nonbillable_probe_cannot_be_marked_billable")


@dataclass(frozen=True, slots=True)
class StateCompatibilityEvidence:
    status: StateCompatibility
    config_revision: int
    primary_fingerprint: str
    backup_fingerprint: str
    adapter_name: str
    model: str
    primary_to_backup: bool = False
    backup_to_primary: bool = False

    def shared_for(self, group: FailoverGroupConfig, model: str) -> bool:
        return (
            self.status is StateCompatibility.SHARED
            and self.primary_to_backup
            and self.backup_to_primary
            and self.config_revision == group.revision
            and self.primary_fingerprint == group.primary.fingerprint
            and self.backup_fingerprint == group.backup.fingerprint
            and self.adapter_name == group.primary.adapter_name == group.backup.adapter_name
            and self.model == model
        )


@dataclass(frozen=True, slots=True)
class RouteConfig:
    role: RouteRole
    profile_id: str
    fingerprint: str
    adapter_name: str
    secret_ref: str = field(repr=False)
    runner: AttemptRunner = field(repr=False, compare=False)
    secret_suffix: str = ""
    enabled: bool = True
    protocol_compatibility: Mapping[str, bool] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        for value, error in (
            (self.profile_id, "route_profile_id_required"),
            (self.fingerprint, "route_fingerprint_required"),
            (self.adapter_name, "route_adapter_required"),
            (self.secret_ref, "route_secret_ref_required"),
        ):
            if not value:
                raise ValueError(error)
        if len(self.secret_suffix) > 8 or any(ord(character) < 0x20 for character in self.secret_suffix):
            raise ValueError("route_secret_suffix_invalid")
        object.__setattr__(
            self,
            "protocol_compatibility",
            MappingProxyType(dict(self.protocol_compatibility)),
        )


@dataclass(frozen=True, slots=True)
class FailoverGroupConfig:
    instance_id: str
    group_id: str
    revision: int
    primary: RouteConfig
    backup: RouteConfig
    allowed_models: tuple[str, ...]
    breaker_policy: BreakerPolicyLike
    probe_policy: ProbePolicy = ProbePolicy()
    state_compatibility: Mapping[str, StateCompatibilityEvidence] = field(
        default_factory=lambda: MappingProxyType({})
    )
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported_failover_group_schema")
        if not self.instance_id or not self.group_id or self.revision <= 0:
            raise ValueError("failover_group_identity_invalid")
        if self.primary.role is not RouteRole.PRIMARY or self.backup.role is not RouteRole.BACKUP:
            raise ValueError("failover_group_route_roles_invalid")
        if self.primary.profile_id == self.backup.profile_id:
            raise ValueError("failover_routes_must_be_distinct")
        required_policy_fields = (
            "failure_threshold",
            "protocol_failure_threshold",
            "error_rate_threshold",
            "minimum_samples",
            "window_size",
            "recovery_success_threshold",
            "base_cooldown_seconds",
            "max_cooldown_seconds",
            "jitter_ratio",
        )
        if any(not hasattr(self.breaker_policy, name) for name in required_policy_fields):
            raise ValueError("failover_breaker_policy_invalid")
        models = tuple(dict.fromkeys(model for model in self.allowed_models if model))
        if not models:
            raise ValueError("failover_models_required")
        object.__setattr__(self, "allowed_models", models)
        object.__setattr__(self, "state_compatibility", MappingProxyType(dict(self.state_compatibility)))

    def route_identity(self, route: RouteConfig) -> str:
        material = {
            "instance_id": self.instance_id,
            "group_id": self.group_id,
            "role": route.role.value,
            "profile_id": route.profile_id,
            "fingerprint": route.fingerprint,
            "adapter_name": route.adapter_name,
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def validate_state_dependencies(self, model: str, dependencies: tuple[str, ...]) -> None:
        if not dependencies:
            return
        evidence = self.state_compatibility.get(model)
        if evidence is None or evidence.status is StateCompatibility.UNKNOWN:
            raise StateCompatibilityError("guardian_state_compatibility_unknown")
        if evidence.status is StateCompatibility.INCOMPATIBLE:
            raise StateCompatibilityError("guardian_state_incompatible")
        if not evidence.shared_for(self, model):
            raise StateCompatibilityError("guardian_state_compatibility_stale")

    def public_identity(self) -> PublicFailoverGroupIdentity:
        return PublicFailoverGroupIdentity(
            instance_id=self.instance_id,
            group_id=self.group_id,
            revision=self.revision,
            primary=PublicRouteIdentity(
                self.primary.role,
                self.primary.profile_id,
                self.primary.adapter_name,
            ),
            backup=PublicRouteIdentity(
                self.backup.role,
                self.backup.profile_id,
                self.backup.adapter_name,
            ),
        )


class AtomicGroupConfig:
    def __init__(self, initial: FailoverGroupConfig) -> None:
        self._active = initial
        self._lock = Lock()

    def snapshot(self) -> FailoverGroupConfig:
        with self._lock:
            return self._active

    def activate(self, next_config: FailoverGroupConfig) -> FailoverGroupConfig:
        with self._lock:
            if next_config.instance_id != self._active.instance_id:
                raise ValueError("failover_group_identity_changed")
            if next_config.revision <= self._active.revision:
                raise ValueError("failover_group_revision_must_increase")
            previous = self._active
            self._active = next_config
            return previous


class StateCompatibilityError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
