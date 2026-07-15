from __future__ import annotations

import asyncio
from contextlib import suppress
import hmac
from typing import Callable, Iterable, Mapping

from aiohttp import web

from .cancellation import CancellationToken
from .commit import Committer, DownstreamWriter
from .errors import gateway_error_response
from .models import CancelReason, CommitState, GatewayError, GatewayLimits
from .request_snapshot import create_request_snapshot
from .service import FailoverGatewayCore, SingleRouteGatewayCore


class AiohttpDownstreamWriter(DownstreamWriter):
    def __init__(self, request: web.Request) -> None:
        self._request = request
        self._response: web.StreamResponse | None = None
        self._prepared = False

    @property
    def prepared(self) -> bool:
        return self._prepared

    @property
    def response(self) -> web.StreamResponse | None:
        return self._response

    async def prepare(self, status: int, content_type: str, content_length: int) -> None:
        if self._prepared:
            raise RuntimeError("downstream_already_prepared")
        response = web.StreamResponse(status=status)
        response.headers["Content-Type"] = content_type
        response.content_length = content_length
        response.force_close()
        await response.prepare(self._request)
        self._response = response
        self._prepared = True

    async def write(self, chunk: bytes) -> None:
        if self._response is None or not self._prepared:
            raise RuntimeError("downstream_not_prepared")
        await self._response.write(chunk)

    async def finish(self) -> None:
        if self._response is None or not self._prepared:
            raise RuntimeError("downstream_not_prepared")
        await self._response.write_eof()


class GatewayIngress:
    def __init__(
        self,
        core: SingleRouteGatewayCore | FailoverGatewayCore,
        limits: GatewayLimits,
        *,
        ingress_token: str,
        upstream_bearer: str | None = None,
        models: Iterable[str] = (),
        version: str = "0.0.0-g3",
        committer_factory: Callable[[], Committer] | None = None,
        health_metadata: Callable[[], Mapping[str, object]] | None = None,
        admission_check: Callable[[], GatewayError | None] | None = None,
        allowed_hosts: Iterable[str] = (),
    ) -> None:
        if not ingress_token:
            raise ValueError("gateway_ingress_token_must_be_nonempty")
        if isinstance(core, FailoverGatewayCore):
            if upstream_bearer not in (None, ""):
                raise ValueError("failover_ingress_must_not_receive_upstream_bearer")
        elif not upstream_bearer:
            raise ValueError("single_route_upstream_bearer_must_be_nonempty")
        model_ids = tuple(dict.fromkeys(model for model in models if model))
        if not model_ids and not isinstance(core, FailoverGatewayCore):
            raise ValueError("gateway_models_must_be_nonempty")
        self._core = core
        self._limits = limits
        self._ingress_token = ingress_token
        self._upstream_bearer = upstream_bearer or ""
        self._models = model_ids
        self._version = version
        self._health_metadata = health_metadata
        self._admission_check = admission_check
        self._allowed_hosts = frozenset(value.lower() for value in allowed_hosts if value)
        self._committer_factory = committer_factory or (
            lambda: Committer(chunk_bytes=self._limits.read_chunk_bytes)
        )
        self._capacity_lock = asyncio.Lock()
        self._active_requests = 0
        self._accepting = True
        self._active_cancellations: set[CancellationToken] = set()
        self._drained = asyncio.Event()
        self._drained.set()

    def create_app(self) -> web.Application:
        app = web.Application(
            client_max_size=self._limits.max_request_bytes,
            middlewares=(self._reject_browser_origin,),
        )
        app.router.add_get("/health", self.health)
        app.router.add_get("/v1/models", self.models)
        app.router.add_post(
            "/v1/responses",
            self.responses,
            expect_handler=self._reject_expect_header,
        )
        return app

    @web.middleware
    async def _reject_browser_origin(
        self,
        request: web.Request,
        handler: Callable[[web.Request], object],
    ) -> web.StreamResponse:
        if request.headers.get("Origin") or request.headers.get("Access-Control-Request-Method"):
            return self._error_response(
                403,
                "guardian_browser_origin_rejected",
                "本地网关不接受浏览器跨站请求。",
            )
        return await handler(request)

    def create_runner(self, **kwargs) -> web.AppRunner:
        kwargs["handler_cancellation"] = True
        return web.AppRunner(self.create_app(), **kwargs)

    @property
    def active_requests(self) -> int:
        return self._active_requests

    @property
    def accepting(self) -> bool:
        return self._accepting

    async def begin_drain(self) -> int:
        async with self._capacity_lock:
            self._accepting = False
            if self._active_requests == 0:
                self._drained.set()
            else:
                self._drained.clear()
            return self._active_requests

    async def resume(self) -> None:
        async with self._capacity_lock:
            self._accepting = True

    async def wait_drained(self, timeout_seconds: float) -> bool:
        if timeout_seconds < 0:
            raise ValueError("drain_timeout_must_not_be_negative")
        try:
            await asyncio.wait_for(self._drained.wait(), timeout=timeout_seconds)
            return True
        except TimeoutError:
            return False

    async def cancel_active(self, reason: CancelReason = CancelReason.GATEWAY_SHUTDOWN) -> int:
        async with self._capacity_lock:
            cancellations = tuple(self._active_cancellations)
        return sum(cancellation.cancel(reason) for cancellation in cancellations)

    async def health(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._error_response(401, "guardian_unauthorized", "本地网关鉴权失败。")
        mode = "failover_g4" if isinstance(self._core, FailoverGatewayCore) else "single_route_g3"
        payload: dict[str, object] = {
            "ok": True,
            "version": self._version,
            "mode": mode,
            "accepting": self._accepting,
            "active_requests": self._active_requests,
        }
        if self._health_metadata is not None:
            metadata = dict(self._health_metadata())
            if set(metadata) & set(payload):
                raise RuntimeError("gateway_health_metadata_conflict")
            payload.update(metadata)
        return web.json_response(payload)

    async def models(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._error_response(401, "guardian_unauthorized", "本地网关鉴权失败。")
        return web.json_response(
            {
                "object": "list",
                "data": [
                    {
                        "id": model,
                        "object": "model",
                        "created": 1,
                        "owned_by": "guardian_gateway",
                    }
                    for model in self._published_models()
                ],
            }
        )

    async def responses(self, request: web.Request) -> web.StreamResponse:
        cancellation = CancellationToken()
        monitor = asyncio.create_task(self._monitor_disconnect(request, cancellation))
        downstream = AiohttpDownstreamWriter(request)
        committer = self._committer_factory()
        admission_error = await self._try_acquire_request(cancellation)
        capacity_acquired = admission_error is None
        try:
            if admission_error is not None:
                return await self._commit_error(
                    request,
                    committer,
                    downstream,
                    cancellation,
                    admission_error.http_status,
                    admission_error.code,
                    admission_error.public_message,
                )
            if not self._authorized(request):
                return await self._commit_error(
                    request,
                    committer,
                    downstream,
                    cancellation,
                    401,
                    "guardian_unauthorized",
                    "本地网关鉴权失败。",
                )
            if request.content_type != "application/json":
                return await self._commit_error(
                    request,
                    committer,
                    downstream,
                    cancellation,
                    415,
                    "guardian_unsupported_media_type",
                    "请求必须使用 application/json。",
                )
            try:
                body = await request.read()
            except web.HTTPRequestEntityTooLarge:
                return await self._commit_error(
                    request,
                    committer,
                    downstream,
                    cancellation,
                    413,
                    "guardian_request_too_large",
                    "请求超过本地网关大小上限。",
                )

            headers = {name.lower(): value for name, value in request.headers.items()}
            snapshot = create_request_snapshot(body, headers, self._limits)
            if not isinstance(self._core, FailoverGatewayCore) and snapshot.model not in self._models:
                raise GatewayError(
                    "guardian_model_not_allowed",
                    "请求模型不在本地网关已发布目录中。",
                    http_status=400,
                )
            proxy_task = asyncio.create_task(
                self._core.proxy(
                    body,
                    headers,
                    self._upstream_bearer,
                    downstream,
                    cancellation,
                    committer,
                )
            )
            try:
                result = await asyncio.shield(proxy_task)
            except asyncio.CancelledError:
                cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
                with suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(proxy_task)
                raise
            if result.state is CommitState.DELIVERY_UNCERTAIN:
                transport = request.transport
                if transport is not None:
                    transport.close()
            if downstream.response is None:
                raise RuntimeError("commit_finished_without_response")
            return downstream.response
        except GatewayError as exc:
            if cancellation.cancelled:
                transport = request.transport
                if transport is not None:
                    transport.close()
                return web.Response(status=499)
            if not committer.uncommitted:
                transport = request.transport
                if transport is not None:
                    transport.close()
                raise
            return await self._commit_error(
                request,
                committer,
                downstream,
                cancellation,
                exc.http_status,
                exc.code,
                exc.public_message,
            )
        except Exception:
            if cancellation.cancelled:
                transport = request.transport
                if transport is not None:
                    transport.close()
                return web.Response(status=499)
            if not committer.uncommitted:
                transport = request.transport
                if transport is not None:
                    transport.close()
                raise
            return await self._commit_error(
                request,
                committer,
                downstream,
                cancellation,
                500,
                "guardian_internal_error",
                "本地网关内部错误。",
            )
        finally:
            if capacity_acquired:
                await self._release_request(cancellation)
            monitor.cancel()
            try:
                await monitor
            except asyncio.CancelledError:
                pass

    def _published_models(self) -> tuple[str, ...]:
        if isinstance(self._core, FailoverGatewayCore):
            return self._core.allowed_models()
        return self._models

    async def _try_acquire_request(self, cancellation: CancellationToken) -> GatewayError | None:
        async with self._capacity_lock:
            if not self._accepting:
                return GatewayError(
                    "guardian_gateway_draining",
                    "本地网关正在排空，暂不接受新请求。",
                    http_status=503,
                )
            if self._admission_check is not None:
                admission_error = self._admission_check()
                if admission_error is not None:
                    return admission_error
            if self._active_requests >= self._limits.max_concurrent_requests:
                return GatewayError(
                    "guardian_gateway_busy",
                    "本地网关并发请求已达到上限。",
                    http_status=503,
                )
            self._active_requests += 1
            self._active_cancellations.add(cancellation)
            self._drained.clear()
            return None

    async def _reject_expect_header(self, _request: web.Request) -> web.Response:
        return self._error_response(
            417,
            "guardian_expectation_not_supported",
            "本地网关不接受 Expect 请求头。",
        )

    async def _release_request(self, cancellation: CancellationToken) -> None:
        async with self._capacity_lock:
            if self._active_requests <= 0:
                raise RuntimeError("ingress_capacity_underflow")
            if cancellation not in self._active_cancellations:
                raise RuntimeError("ingress_cancellation_missing")
            self._active_cancellations.remove(cancellation)
            self._active_requests -= 1
            if self._active_requests == 0:
                self._drained.set()

    def _authorized(self, request: web.Request) -> bool:
        if self._allowed_hosts:
            host = request.headers.get("Host", "").lower()
            if host not in self._allowed_hosts:
                return False
        authorization = request.headers.get("Authorization", "")
        expected = f"Bearer {self._ingress_token}"
        return hmac.compare_digest(authorization, expected)

    @staticmethod
    async def _monitor_disconnect(request: web.Request, cancellation: CancellationToken) -> None:
        while not cancellation.cancelled:
            transport = request.transport
            if transport is None or transport.is_closing():
                cancellation.cancel(CancelReason.CLIENT_DISCONNECTED)
                return
            await asyncio.sleep(0.01)

    @staticmethod
    def _error_response(status: int, code: str, message: str) -> web.Response:
        response = gateway_error_response(status=status, code=code, message=message)
        return web.Response(status=response.status, body=response.body, content_type="application/json")

    @staticmethod
    def _error_body(code: str, message: str) -> bytes:
        return gateway_error_response(status=500, code=code, message=message).body

    async def _commit_error(
        self,
        request: web.Request,
        committer: Committer,
        downstream: AiohttpDownstreamWriter,
        cancellation: CancellationToken,
        status: int,
        code: str,
        message: str,
    ) -> web.StreamResponse:
        response = gateway_error_response(status=status, code=code, message=message)
        result = await committer.commit_error(response, downstream, cancellation)
        if result.state is CommitState.DELIVERY_UNCERTAIN:
            transport = request.transport
            if transport is not None:
                transport.close()
        if downstream.response is None:
            raise RuntimeError("error_commit_finished_without_response")
        return downstream.response
