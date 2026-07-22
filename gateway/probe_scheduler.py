from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable
import uuid

import aiohttp

from .adapter import OpenAIResponsesAdapter
from .breaker import BreakerSignal, BreakerTicket, CircuitBreakerRegistry, RouteKey
from .breaker import BreakerState
from .config import FailoverGroupConfig, RouteConfig, RouteRole


@dataclass(frozen=True, slots=True)
class ModelsProbeResult:
    role: RouteRole
    ok: bool
    http_status: int | None
    category: str


class ModelsProbeScheduler:
    _MAX_RESPONSE_BYTES = 64 * 1024

    def __init__(
        self,
        *,
        config_provider: Callable[[], FailoverGroupConfig],
        breaker: CircuitBreakerRegistry,
        session: aiohttp.ClientSession,
        resolve_secret: Callable[[str], str],
        on_result: Callable[[ModelsProbeResult], None] | None = None,
    ) -> None:
        self._config_provider = config_provider
        self._breaker = breaker
        self._session = session
        self._resolve_secret = resolve_secret
        self._on_result = on_result
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("probe_scheduler_already_started")
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            await task

    async def run_once(self) -> tuple[ModelsProbeResult, ...]:
        config = self._config_provider()
        policy = config.probe_policy
        if not policy.enabled or policy.mode.value != "models":
            return ()
        results = []
        for route in (config.primary, config.backup):
            result = await self._probe_route(config, route)
            results.append(result)
            if self._on_result is not None:
                self._on_result(result)
        return tuple(results)

    async def probe_role(self, role: RouteRole) -> ModelsProbeResult:
        config = self._config_provider()
        route = config.primary if role is RouteRole.PRIMARY else config.backup
        result = await self._probe_route(config, route, explicit_manual_retest=True)
        if self._on_result is not None:
            self._on_result(result)
        return result

    async def _run(self) -> None:
        while not self._stop.is_set():
            config = self._config_provider()
            policy = config.probe_policy
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=policy.interval_seconds)
            except TimeoutError:
                try:
                    await self.run_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue

    async def _probe_route(
        self,
        config: FailoverGroupConfig,
        route: RouteConfig,
        *,
        explicit_manual_retest: bool = False,
    ) -> ModelsProbeResult:
        route_adapter = getattr(route.runner, "_adapter", None)
        if not isinstance(route_adapter, OpenAIResponsesAdapter):
            return ModelsProbeResult(route.role, False, None, "adapter_probe_unsupported")
        key = RouteKey(config.instance_id, config.group_id, route.role.value, route.profile_id)
        current = self._breaker.snapshot(key)
        if current is None:
            return ModelsProbeResult(route.role, False, None, "probe_route_unknown")
        if (
            current.state is BreakerState.OPEN_ACTION_REQUIRED
            and not config.probe_policy.allow_action_required_auto_retest
            and not explicit_manual_retest
        ):
            return ModelsProbeResult(route.role, False, None, "manual_retest_required")
        admission = self._breaker.acquire(
            key,
            config_revision=config.revision,
            route_fingerprint=route.fingerprint,
            attempt_id=f"models-probe-{route.role.value}-{uuid.uuid4().hex}",
            manual_probe=True,
            signal=BreakerSignal.PROBE,
        )
        if not admission.allowed or admission.ticket is None:
            return ModelsProbeResult(route.role, False, None, "probe_not_admitted")
        ticket = admission.ticket
        admitted_state = admission.state
        try:
            bearer = self._resolve_secret(route.secret_ref)
            headers = {"Authorization": f"Bearer {bearer}"}
            timeout = aiohttp.ClientTimeout(total=config.probe_policy.timeout_seconds)
            async with self._session.get(
                route_adapter.models_url,
                headers=headers,
                timeout=timeout,
            ) as response:
                if response.content_length is not None and response.content_length > self._MAX_RESPONSE_BYTES:
                    self._finish_failure(
                        ticket,
                        admitted_state,
                        category="protocol_or_local_error",
                        http_status=response.status,
                    )
                    return ModelsProbeResult(
                        route.role,
                        False,
                        response.status,
                        "probe_response_too_large",
                    )
                payload = await response.content.read(self._MAX_RESPONSE_BYTES + 1)
                if len(payload) > self._MAX_RESPONSE_BYTES:
                    self._finish_failure(
                        ticket,
                        admitted_state,
                        category="protocol_or_local_error",
                        http_status=response.status,
                    )
                    return ModelsProbeResult(
                        route.role,
                        False,
                        response.status,
                        "probe_response_too_large",
                    )
                if 200 <= response.status < 300:
                    self._breaker.record_success(ticket)
                    return ModelsProbeResult(route.role, True, response.status, "success")
                if response.status in {401, 403}:
                    category = "auth_rejected"
                elif response.status == 429:
                    category = "rate_limited"
                elif response.status in {500, 502, 503, 504}:
                    category = "upstream_5xx"
                else:
                    category = "upstream_http_error"
                self._finish_failure(
                    ticket,
                    admitted_state,
                    category=category,
                    http_status=response.status,
                    action_required=response.status in {401, 403},
                )
                return ModelsProbeResult(route.role, False, response.status, category)
        except asyncio.CancelledError:
            self._breaker.record_cancelled(ticket)
            raise
        except Exception:
            self._finish_failure(
                ticket,
                admitted_state,
                category="network_error",
            )
            return ModelsProbeResult(route.role, False, None, "network_error")

    def _finish_failure(
        self,
        ticket: BreakerTicket,
        admitted_state: BreakerState,
        *,
        category: str,
        http_status: int | None = None,
        action_required: bool = False,
    ) -> None:
        if admitted_state is not BreakerState.HALF_OPEN:
            self._breaker.abandon(ticket)
            return
        if action_required:
            self._breaker.record_action_required(
                ticket,
                failure_category=category,
                http_status=http_status,
            )
            return
        self._breaker.record_temporary_failure(
            ticket,
            failure_category=category,
            http_status=http_status,
        )
