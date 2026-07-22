from __future__ import annotations

import json

from .config import ProbeMode, ProbePolicy
from .models import GatewayLimits, RequestSnapshot
from .request_snapshot import create_request_snapshot


_PROBE_INPUT = "guardian-route-health-probe"


def create_probe_snapshot(
    model: str,
    limits: GatewayLimits,
    *,
    policy: ProbePolicy | None = None,
    manual_billable_confirmation: bool = False,
) -> RequestSnapshot:
    effective = policy or ProbePolicy(
        enabled=True,
        mode=ProbeMode.RESPONSES,
        allow_billable=True,
    )
    if effective.mode is not ProbeMode.RESPONSES:
        raise ValueError("responses_probe_requires_responses_mode")
    if not effective.enabled:
        raise ValueError("responses_probe_disabled")
    if not effective.allow_billable or not manual_billable_confirmation:
        raise ValueError("billable_probe_requires_manual_confirmation")
    body = json.dumps(
        {
            "model": model,
            "input": _PROBE_INPUT,
            "max_output_tokens": 1,
            "store": False,
            "stream": False,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return create_request_snapshot(body, {"content-type": "application/json"}, limits)


def is_safe_probe(snapshot: RequestSnapshot) -> bool:
    if snapshot.state_dependencies or snapshot.stream:
        return False
    try:
        payload = json.loads(snapshot.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return payload == {
        "model": snapshot.model,
        "input": _PROBE_INPUT,
        "max_output_tokens": 1,
        "store": False,
        "stream": False,
    }
