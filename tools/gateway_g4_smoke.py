from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import aiohttp
from aiohttp import web


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.adapter import OpenAIResponsesAdapter
from gateway.attempts import SingleRouteAttemptRunner
from gateway.breaker import BreakerState, CircuitBreakerPolicy, CircuitBreakerRegistry, RouteKey
from gateway.config import FailoverGroupConfig, RouteConfig, RouteRole
from gateway.failures import FailureClassifier
from gateway.ingress import GatewayIngress
from gateway.models import GatewayLimits
from gateway.protocols.responses import validate_buffered_response
from gateway.runtime import AtomicFailoverRouterProvider
from gateway.secrets import InMemorySecretResolver
from gateway.service import FailoverGatewayCore
from gateway.state import AtomicBreakerStateStore


FIXTURE_BEARER = "fixture-g4-upstream-bearer"
INGRESS_TOKEN = "fixture-g4-ingress-token"
MODEL = "g4-smoke"


def _event(event_type: str, value: dict[str, object]) -> bytes:
    return (
        f"event: {event_type}\n"
        f"data: {json.dumps(value, separators=(',', ':'))}\n\n"
    ).encode("utf-8")


def _backup_sse() -> bytes:
    in_progress = {
        "id": "resp_g4_backup",
        "object": "response",
        "status": "in_progress",
        "output": [],
    }
    completed = dict(in_progress, status="completed")
    return b"".join(
        (
            _event(
                "response.created",
                {
                    "type": "response.created",
                    "sequence_number": 0,
                    "response": in_progress,
                },
            ),
            _event(
                "response.completed",
                {
                    "type": "response.completed",
                    "sequence_number": 1,
                    "response": completed,
                },
            ),
        )
    )


async def _listen(runner: web.AppRunner) -> str:
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    sockets = site._server.sockets if site._server is not None else []
    if not sockets:
        raise RuntimeError("g4_smoke_listener_missing")
    return f"http://127.0.0.1:{sockets[0].getsockname()[1]}"


async def smoke() -> dict[str, object]:
    limits = GatewayLimits(
        max_request_bytes=1024 * 1024,
        max_response_bytes=1024 * 1024,
        read_chunk_bytes=97,
        max_concurrent_requests=2,
        connect_timeout_seconds=1,
        first_byte_timeout_seconds=1,
        idle_timeout_seconds=1,
        total_timeout_seconds=3,
    )
    backup_body = _backup_sse()
    request_hashes: dict[str, list[str]] = {"primary": [], "backup": []}
    calls = {"primary": 0, "backup": 0}

    async def capture(request: web.Request, role: str) -> bytes:
        if request.headers.get("Authorization") != f"Bearer {FIXTURE_BEARER}":
            raise web.HTTPUnauthorized()
        body = await request.read()
        calls[role] += 1
        request_hashes[role].append(hashlib.sha256(body).hexdigest())
        return body

    async def primary(request: web.Request) -> web.Response:
        await capture(request, "primary")
        return web.json_response(
            {"error": {"type": "synthetic_primary_failure", "private": "must-not-leak"}},
            status=503,
        )

    async def backup(request: web.Request) -> web.Response:
        await capture(request, "backup")
        return web.Response(body=backup_body, content_type="text/event-stream")

    primary_app = web.Application()
    primary_app.router.add_post("/v1/responses", primary)
    backup_app = web.Application()
    backup_app.router.add_post("/v1/responses", backup)
    primary_runner = web.AppRunner(primary_app, shutdown_timeout=1)
    backup_runner = web.AppRunner(backup_app, shutdown_timeout=1)
    gateway_runner: web.AppRunner | None = None

    primary_url = await _listen(primary_runner)
    backup_url = await _listen(backup_runner)
    try:
        async with aiohttp.ClientSession() as upstream_session:
            primary_attempt = SingleRouteAttemptRunner(
                upstream_session,
                OpenAIResponsesAdapter(primary_url),
                limits,
            )
            backup_attempt = SingleRouteAttemptRunner(
                upstream_session,
                OpenAIResponsesAdapter(backup_url),
                limits,
            )
            policy = CircuitBreakerPolicy(
                failure_threshold=1,
                protocol_failure_threshold=1,
                error_rate_threshold=None,
                minimum_samples=1,
                window_size=4,
                recovery_success_threshold=1,
                base_cooldown_seconds=30,
                max_cooldown_seconds=300,
                jitter_ratio=0,
            )
            group = FailoverGroupConfig(
                instance_id="smoke-instance",
                group_id="smoke-group",
                revision=1,
                primary=RouteConfig(
                    RouteRole.PRIMARY,
                    "p1",
                    "fp-p1",
                    "openai-responses-v1",
                    "s:p1",
                    primary_attempt,
                ),
                backup=RouteConfig(
                    RouteRole.BACKUP,
                    "p2",
                    "fp-p2",
                    "openai-responses-v1",
                    "s:p2",
                    backup_attempt,
                ),
                allowed_models=(MODEL,),
                breaker_policy=policy,
            )
            breaker = CircuitBreakerRegistry(rng=lambda: 0)
            with tempfile.TemporaryDirectory() as directory:
                state_path = Path(directory) / "breaker.json"
                provider = AtomicFailoverRouterProvider(
                    group,
                    breaker,
                    FailureClassifier(),
                    InMemorySecretResolver(
                        {"s:p1": FIXTURE_BEARER, "s:p2": FIXTURE_BEARER}
                    ),
                    state_store=AtomicBreakerStateStore(state_path),
                )
                core = FailoverGatewayCore(provider, limits)
                ingress = GatewayIngress(
                    core,
                    limits,
                    ingress_token=INGRESS_TOKEN,
                    version="0.0.0-g4-smoke",
                )
                gateway_runner = ingress.create_runner(shutdown_timeout=1)
                gateway_url = await _listen(gateway_runner)
                request_body = json.dumps(
                    {"model": MODEL, "input": "synthetic", "stream": True},
                    separators=(",", ":"),
                ).encode("utf-8")
                expected_hash = hashlib.sha256(request_body).hexdigest()

                async with aiohttp.ClientSession() as client:
                    response = await client.post(
                        gateway_url + "/v1/responses",
                        data=request_body,
                        headers={
                            "Authorization": f"Bearer {INGRESS_TOKEN}",
                            "Content-Type": "application/json",
                        },
                    )
                    status = response.status
                    content_type = response.headers.get("Content-Type", "")
                    delivered = await response.read()

                validated = validate_buffered_response(status, content_type, (delivered,))
                primary_state = breaker.snapshot(
                    RouteKey("smoke-instance", "smoke-group", "primary", "p1")
                )
                persisted = AtomicBreakerStateStore(state_path).load()
                events = core.journal.snapshot()
                transitions = breaker.transition_events()

            attempt_roles = [
                event["route_role"]
                for event in events
                if event["event"] == "attempt_finished"
            ]
            transition_states = [
                (
                    transition.route_key.route_role,
                    transition.old_state.value,
                    transition.new_state.value,
                )
                for transition in transitions
            ]
            ok = bool(
                status == 200
                and delivered == backup_body
                and b"must-not-leak" not in delivered
                and validated.response_id == "resp_g4_backup"
                and calls == {"primary": 1, "backup": 1}
                and request_hashes == {
                    "primary": [expected_hash],
                    "backup": [expected_hash],
                }
                and attempt_roles == ["primary", "backup"]
                and transition_states
                == [
                    ("primary", "unknown", "open_temporary"),
                    ("backup", "unknown", "closed"),
                ]
                and primary_state is not None
                and primary_state.state is BreakerState.OPEN_TEMPORARY
                and persisted is not None
                and len(persisted["routes"]) == 2
                and breaker.active_pin_count() == 0
                and core.active_requests == 0
                and ingress.active_requests == 0
            )
            return {
                "ok": ok,
                "response_id": validated.response_id,
                "primary_calls": calls["primary"],
                "backup_calls": calls["backup"],
                "same_request_hash": request_hashes
                == {"primary": [expected_hash], "backup": [expected_hash]},
                "attempt_roles": attempt_roles,
                "transition_states": transition_states,
                "primary_state": primary_state.state.value if primary_state else None,
                "persisted_routes": len(persisted["routes"]) if persisted else 0,
            }
    finally:
        if gateway_runner is not None:
            await gateway_runner.cleanup()
        await backup_runner.cleanup()
        await primary_runner.cleanup()


def main() -> int:
    value = asyncio.run(smoke())
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
