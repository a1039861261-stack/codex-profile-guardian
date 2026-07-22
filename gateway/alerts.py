from __future__ import annotations

from dataclasses import dataclass

from .breaker import BreakerSnapshot, BreakerState
from .config import RouteConfig


@dataclass(frozen=True, slots=True)
class RouteAlert:
    code: str
    persistent: bool
    route_role: str
    profile_id: str
    key_suffix: str
    failure_category: str
    http_status: int | None
    breaker_state: str
    first_failed_at: str | None
    last_failed_at: str | None
    backup_carrying: bool
    next_action: str


def action_required_alert(
    route: RouteConfig,
    snapshot: BreakerSnapshot,
    *,
    backup_carrying: bool,
) -> RouteAlert | None:
    if not snapshot.action_required:
        return None
    return RouteAlert(
        code="guardian_route_action_required",
        persistent=True,
        route_role=route.role.value,
        profile_id=route.profile_id,
        key_suffix=route.secret_suffix,
        failure_category=snapshot.last_failure_category or "unknown",
        http_status=snapshot.last_http_status,
        breaker_state=snapshot.state.value,
        first_failed_at=_timestamp(snapshot.first_failed_at),
        last_failed_at=_timestamp(snapshot.last_failed_at),
        backup_carrying=backup_carrying,
        next_action="请到中转站检查 Key、分组绑定和模型权限，修复后执行人工复测。",
    )


def _timestamp(value) -> str | None:
    return None if value is None else value.isoformat()
