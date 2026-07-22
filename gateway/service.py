from __future__ import annotations

import asyncio
from typing import Protocol
import uuid

from .attempts import SingleRouteAttemptRunner
from .cancellation import CancellationToken, RequestCancelled
from .commit import Committer, DownstreamWriter
from .journal import GatewayEvent, MemoryEventJournal
from .models import CommitResult, GatewayError, GatewayLimits
from .request_snapshot import create_request_snapshot
from .router import FailoverRouter
from .errors import all_routes_failed_response, gateway_error_response


class FailoverRouterProvider(Protocol):
    def acquire(self) -> FailoverRouterLease: ...

    def current_config(self): ...


class FailoverRouterLease(Protocol):
    router: FailoverRouter

    def release(self) -> None: ...


class SingleRouteGatewayCore:
    def __init__(
        self,
        runner: SingleRouteAttemptRunner,
        limits: GatewayLimits,
        journal: MemoryEventJournal | None = None,
    ) -> None:
        self._runner = runner
        self._limits = limits
        self._journal = journal or MemoryEventJournal()
        self._capacity_lock = asyncio.Lock()
        self._active_requests = 0

    @property
    def journal(self) -> MemoryEventJournal:
        return self._journal

    @property
    def active_requests(self) -> int:
        return self._active_requests

    async def proxy(
        self,
        body: bytes,
        headers: dict[str, str],
        bearer: str,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
        committer: Committer,
    ) -> CommitResult:
        await self._acquire_capacity()
        try:
            return await self._proxy_with_capacity(
                body,
                headers,
                bearer,
                downstream,
                cancellation,
                committer,
            )
        finally:
            await self._release_capacity()

    async def _proxy_with_capacity(
        self,
        body: bytes,
        headers: dict[str, str],
        bearer: str,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
        committer: Committer,
    ) -> CommitResult:
        if not committer.uncommitted:
            raise RuntimeError("request_committer_already_used")
        request_id = uuid.uuid4().hex
        snapshot = create_request_snapshot(body, headers, self._limits)
        self._journal.append(
            GatewayEvent(
                request_id=request_id,
                event="request_received",
                model=snapshot.model,
                status="buffering",
            )
        )
        attempt = await self._runner.run(snapshot, bearer, cancellation)
        if attempt.cancelled is not None:
            self._journal.append(
                GatewayEvent(
                    request_id=request_id,
                    event="request_cancelled",
                    model=snapshot.model,
                    status=attempt.cancelled.value,
                )
            )
            raise GatewayError("guardian_client_cancelled", "客户端已取消请求。", http_status=499)
        if attempt.failure is not None:
            self._journal.append(
                GatewayEvent(
                    request_id=request_id,
                    event="attempt_failed",
                    model=snapshot.model,
                    status=attempt.failure.public_code,
                )
            )
            status = attempt.failure.http_status or 502
            if status < 400 or status > 599:
                status = 502
            raise GatewayError(attempt.failure.public_code, "上游请求失败。", http_status=status)
        if attempt.complete is None:
            raise RuntimeError("attempt_complete_missing")
        try:
            result = await committer.commit(attempt.complete, downstream, cancellation)
        except RequestCancelled as exc:
            self._journal.append(
                GatewayEvent(
                    request_id=request_id,
                    event="request_cancelled",
                    model=snapshot.model,
                    status=exc.reason.value,
                )
            )
            raise GatewayError("guardian_client_cancelled", "客户端已取消请求。", http_status=499) from exc
        self._journal.append(
            GatewayEvent(
                request_id=request_id,
                event="commit_finished",
                model=snapshot.model,
                status=result.state.value,
                buffer_bytes=attempt.complete.buffer_bytes,
            )
        )
        return result

    async def _acquire_capacity(self) -> None:
        async with self._capacity_lock:
            if self._active_requests >= self._limits.max_concurrent_requests:
                raise GatewayError(
                    "guardian_gateway_busy",
                    "本地网关并发请求已达到上限。",
                    http_status=503,
                )
            self._active_requests += 1

    async def _release_capacity(self) -> None:
        async with self._capacity_lock:
            if self._active_requests <= 0:
                raise RuntimeError("gateway_capacity_underflow")
            self._active_requests -= 1


class FailoverGatewayCore:
    def __init__(
        self,
        router: FailoverRouter | FailoverRouterProvider,
        limits: GatewayLimits,
        journal: MemoryEventJournal | None = None,
    ) -> None:
        if isinstance(router, FailoverRouter):
            self._router = router
            self._router_provider = None
        else:
            self._router = None
            self._router_provider = router
        self._limits = limits
        self._journal = journal or MemoryEventJournal()
        self._capacity_lock = asyncio.Lock()
        self._active_requests = 0

    @property
    def journal(self) -> MemoryEventJournal:
        return self._journal

    @property
    def active_requests(self) -> int:
        return self._active_requests

    def allowed_models(self) -> tuple[str, ...]:
        if self._router_provider is not None:
            return self._router_provider.current_config().allowed_models
        if self._router is None:
            raise RuntimeError("failover_router_missing")
        return self._router.group.allowed_models

    async def proxy(
        self,
        body: bytes,
        headers: dict[str, str],
        _bearer: str,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
        committer: Committer,
    ) -> CommitResult:
        await self._acquire_capacity()
        lease = None
        try:
            if not committer.uncommitted:
                raise RuntimeError("request_committer_already_used")
            if self._router_provider is not None:
                lease = self._router_provider.acquire()
                router = lease.router
            else:
                router = self._router
            if router is None:
                raise RuntimeError("failover_router_missing")
            request_id = uuid.uuid4().hex
            snapshot = create_request_snapshot(body, headers, self._limits)
            self._journal.append(
                GatewayEvent(
                    request_id=request_id,
                    event="request_received",
                    model=snapshot.model,
                    status="routing",
                    instance_id=router.group.instance_id,
                    group_id=router.group.group_id,
                    config_revision=router.group.revision,
                )
            )
            try:
                routed = await router.execute(
                    snapshot,
                    cancellation,
                    can_failover=lambda: committer.uncommitted,
                )
            except Exception as exc:
                error = self._router_error(exc)
                result = await self._commit_gateway_error(
                    request_id,
                    snapshot.model,
                    router,
                    error,
                    downstream,
                    cancellation,
                    committer,
                )
                return result
            for attempt in routed.attempts:
                failure = attempt.result.failure
                self._journal.append(
                    GatewayEvent(
                        request_id=request_id,
                        event="attempt_finished",
                        model=snapshot.model,
                        status=(
                            attempt.result.complete.terminal_status
                            if attempt.result.complete is not None
                            else failure.public_code if failure is not None
                            else attempt.result.cancelled.value
                        ),
                        buffer_bytes=attempt.result.complete.buffer_bytes if attempt.result.complete else 0,
                        instance_id=router.group.instance_id,
                        group_id=router.group.group_id,
                        config_revision=router.group.revision,
                        route_role=attempt.route.role.value,
                        attempt_id=attempt.attempt_id,
                        failover_used=routed.failover_used,
                        possible_double_charge=routed.possible_double_charge,
                        signal=routed.signal.value,
                        breaker_before=attempt.breaker_before,
                        breaker_after=attempt.breaker_after,
                        http_status_category=self._http_status_category(
                            attempt.result.complete.status
                            if attempt.result.complete is not None
                            else failure.http_status if failure is not None else None
                        ),
                        latency_ms=attempt.latency_ms,
                    )
                )
            if routed.cancelled is not None:
                self._append_terminal(
                    request_id,
                    snapshot.model,
                    router,
                    status=routed.cancelled.value,
                    event="request_cancelled",
                    failover_used=routed.failover_used,
                    possible_double_charge=routed.possible_double_charge,
                )
                raise GatewayError("guardian_client_cancelled", "客户端已取消请求。", http_status=499)
            if routed.replay_blocked:
                return await self._commit_gateway_error(
                    request_id,
                    snapshot.model,
                    router,
                    GatewayError(
                    "guardian_automatic_replay_blocked",
                    "请求可能已由上游执行服务端工具，已停止自动重放以避免重复副作用。",
                    http_status=409,
                    ),
                    downstream,
                    cancellation,
                    committer,
                    failover_used=routed.failover_used,
                    possible_double_charge=routed.possible_double_charge,
                )
            if routed.complete is not None:
                result = await committer.commit(routed.complete, downstream, cancellation)
            elif (
                len(routed.attempts) == 1
                and routed.attempts[-1].result.failure is not None
                and routed.attempts[-1].decision is not None
                and not routed.attempts[-1].decision.retry_on_backup
            ):
                failure = routed.attempts[-1].result.failure
                status = failure.http_status or 502
                if status < 400 or status > 599:
                    status = 502
                return await self._commit_gateway_error(
                    request_id,
                    snapshot.model,
                    router,
                    GatewayError(failure.public_code, "上游请求失败。", http_status=status),
                    downstream,
                    cancellation,
                    committer,
                    failover_used=routed.failover_used,
                    possible_double_charge=routed.possible_double_charge,
                )
            else:
                failure_response = all_routes_failed_response(
                    request_id=request_id,
                    primary=routed.primary_failure,
                    backup=routed.backup_failure,
                    possible_double_charge=routed.possible_double_charge,
                    action_required=(
                        routed.action_required
                        or self._unavailable_reason(routed.primary_admission) == "open_action_required"
                        or self._unavailable_reason(routed.backup_admission) == "open_action_required"
                    ),
                    primary_unavailable=self._unavailable_reason(routed.primary_admission),
                    backup_unavailable=self._unavailable_reason(routed.backup_admission),
                )
                result = await committer.commit_error(failure_response, downstream, cancellation)
            self._journal.append(
                GatewayEvent(
                    request_id=request_id,
                    event="commit_finished",
                    model=snapshot.model,
                    status=result.state.value,
                    buffer_bytes=routed.complete.buffer_bytes if routed.complete else 0,
                    instance_id=router.group.instance_id,
                    group_id=router.group.group_id,
                    config_revision=router.group.revision,
                    failover_used=routed.failover_used,
                    possible_double_charge=routed.possible_double_charge,
                    signal=routed.signal.value,
                    http_status_category=self._http_status_category(
                        routed.complete.status if routed.complete is not None else failure_response.status
                    ),
                )
            )
            return result
        finally:
            if lease is not None:
                lease.release()
            await self._release_capacity()

    @staticmethod
    def _unavailable_reason(admission) -> str | None:
        if admission is None or admission.allowed or admission.denied is None:
            return None
        return admission.denied.value

    @staticmethod
    def _router_error(exc: Exception) -> GatewayError:
        code = getattr(exc, "code", "")
        if code in {
            "guardian_state_compatibility_unknown",
            "guardian_state_compatibility_stale",
            "guardian_state_incompatible",
        }:
            return GatewayError(
                code,
                "请求引用的上游状态无法安全跨线路重放。",
                http_status=409,
            )
        if str(exc) == "guardian_upstream_credential_unavailable":
            return GatewayError(
                "guardian_upstream_credential_unavailable",
                "容灾组凭据不可用，网关已安全停止该请求。",
                http_status=500,
            )
        if str(exc) == "guardian_model_not_allowed":
            return GatewayError(
                "guardian_model_not_allowed",
                "请求模型不在当前容灾组已发布目录中。",
                http_status=400,
            )
        return GatewayError("guardian_internal_error", "本地网关内部错误。", http_status=500)

    async def _commit_gateway_error(
        self,
        request_id: str,
        model: str,
        router: FailoverRouter,
        error: GatewayError,
        downstream: DownstreamWriter,
        cancellation: CancellationToken,
        committer: Committer,
        *,
        failover_used: bool = False,
        possible_double_charge: bool = False,
    ) -> CommitResult:
        response = gateway_error_response(
            status=error.http_status,
            code=error.code,
            message=error.public_message,
            request_id=request_id,
        )
        result = await committer.commit_error(response, downstream, cancellation)
        self._append_terminal(
            request_id,
            model,
            router,
            status=result.state.value,
            buffer_bytes=response.buffer_bytes,
            failover_used=failover_used,
            possible_double_charge=possible_double_charge,
            http_status=response.status,
        )
        return result

    def _append_terminal(
        self,
        request_id: str,
        model: str,
        router: FailoverRouter,
        *,
        status: str,
        event: str = "commit_finished",
        buffer_bytes: int = 0,
        failover_used: bool = False,
        possible_double_charge: bool = False,
        http_status: int | None = None,
    ) -> None:
        self._journal.append(
            GatewayEvent(
                request_id=request_id,
                event=event,
                model=model,
                status=status,
                buffer_bytes=buffer_bytes,
                instance_id=router.group.instance_id,
                group_id=router.group.group_id,
                config_revision=router.group.revision,
                failover_used=failover_used,
                possible_double_charge=possible_double_charge,
                http_status_category=self._http_status_category(http_status),
            )
        )

    @staticmethod
    def _http_status_category(status: int | None) -> str:
        if status is None or not 100 <= status <= 599:
            return ""
        return f"{status // 100}xx"

    async def _acquire_capacity(self) -> None:
        async with self._capacity_lock:
            if self._active_requests >= self._limits.max_concurrent_requests:
                raise GatewayError("guardian_gateway_busy", "本地网关并发请求已达到上限。", http_status=503)
            self._active_requests += 1

    async def _release_capacity(self) -> None:
        async with self._capacity_lock:
            if self._active_requests <= 0:
                raise RuntimeError("gateway_capacity_underflow")
            self._active_requests -= 1
