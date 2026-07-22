from __future__ import annotations

import hmac
from typing import Awaitable, Callable, Iterable, Mapping

from aiohttp import web


class GatewayControlOperationError(RuntimeError):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class GatewayControlServer:
    def __init__(
        self,
        *,
        control_token: str,
        status: Callable[[], Mapping[str, object]],
        drain: Callable[[float | None], Awaitable[Mapping[str, object]]],
        resume: Callable[[], Awaitable[Mapping[str, object]]],
        reload_config: Callable[[], Awaitable[Mapping[str, object]]],
        prepare_config: Callable[[Mapping[str, object]], Awaitable[Mapping[str, object]]],
        activate_config: Callable[[int, str], Awaitable[Mapping[str, object]]],
        abort_config: Callable[[int, str], Awaitable[Mapping[str, object]]],
        failover_snapshot: Callable[[], Mapping[str, object]],
        failover_events: Callable[[], Mapping[str, object]],
        retest_route: Callable[[str, str], Awaitable[Mapping[str, object]]],
        stop: Callable[[float | None], Awaitable[Mapping[str, object]]],
        allowed_hosts: Iterable[str] = (),
    ) -> None:
        if not control_token:
            raise ValueError("gateway_control_token_must_be_nonempty")
        self._control_token = control_token
        self._status = status
        self._drain = drain
        self._resume = resume
        self._reload_config = reload_config
        self._prepare_config = prepare_config
        self._activate_config = activate_config
        self._abort_config = abort_config
        self._failover_snapshot = failover_snapshot
        self._failover_events = failover_events
        self._retest_route = retest_route
        self._stop = stop
        self._allowed_hosts = frozenset(value.lower() for value in allowed_hosts if value)

    def create_app(self) -> web.Application:
        app = web.Application(client_max_size=1024 * 1024)
        app.router.add_get("/control/v1/status", self.status)
        app.router.add_post("/control/v1/drain", self.drain)
        app.router.add_post("/control/v1/resume", self.resume)
        app.router.add_post("/control/v1/config/prepare", self.prepare_config)
        app.router.add_post("/control/v1/config/activate", self.activate_config)
        app.router.add_post("/control/v1/config/abort", self.abort_config)
        app.router.add_get("/control/v1/failover/snapshot", self.failover_snapshot)
        app.router.add_get("/control/v1/failover/events", self.failover_events)
        app.router.add_post("/control/v1/failover/retest", self.retest_route)
        app.router.add_post("/control/v1/stop", self.stop)
        return app

    def create_runner(self, **kwargs) -> web.AppRunner:
        kwargs["handler_cancellation"] = True
        return web.AppRunner(self.create_app(), **kwargs)

    async def status(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        return self._json(self._status())

    async def drain(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        timeout = await self._timeout(request)
        if isinstance(timeout, web.Response):
            return timeout
        try:
            return self._json(await self._drain(timeout))
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")

    async def resume(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        if request.can_read_body:
            return self._error(400, "guardian_control_body_not_allowed")
        try:
            return self._json(await self._resume())
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")

    async def reload_config(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        if request.can_read_body:
            return self._error(400, "guardian_control_body_not_allowed")
        try:
            return self._json(await self._reload_config())
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")

    async def prepare_config(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        document = await self._json_document(request)
        if isinstance(document, web.Response):
            return document
        try:
            result = await self._prepare_config(document)
        except GatewayControlOperationError as exc:
            return self._error(exc.status, exc.code)
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")
        return self._json(result)

    async def activate_config(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        document = await self._json_document(request)
        if isinstance(document, web.Response):
            return document
        if set(document) != {"revision", "config_sha256"}:
            return self._error(400, "guardian_control_payload_invalid")
        revision = document.get("revision")
        config_sha256 = document.get("config_sha256")
        if type(revision) is not int or revision <= 0:
            return self._error(400, "guardian_control_revision_invalid")
        if (
            not isinstance(config_sha256, str)
            or len(config_sha256) != 64
            or any(character not in "0123456789abcdef" for character in config_sha256)
        ):
            return self._error(400, "guardian_control_config_hash_invalid")
        try:
            result = await self._activate_config(revision, config_sha256)
        except GatewayControlOperationError as exc:
            return self._error(exc.status, exc.code)
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")
        return self._json(result)

    async def abort_config(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        document = await self._json_document(request)
        if isinstance(document, web.Response):
            return document
        if set(document) != {"revision", "config_sha256"}:
            return self._error(400, "guardian_control_payload_invalid")
        revision = document.get("revision")
        config_sha256 = document.get("config_sha256")
        if type(revision) is not int or revision <= 0:
            return self._error(400, "guardian_control_revision_invalid")
        if (
            not isinstance(config_sha256, str)
            or len(config_sha256) != 64
            or any(character not in "0123456789abcdef" for character in config_sha256)
        ):
            return self._error(400, "guardian_control_config_hash_invalid")
        try:
            result = await self._abort_config(revision, config_sha256)
        except GatewayControlOperationError as exc:
            return self._error(exc.status, exc.code)
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")
        return self._json(result)

    async def failover_snapshot(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        return self._json(self._failover_snapshot())

    async def failover_events(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        return self._json(self._failover_events())

    async def retest_route(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        document = await self._json_document(request)
        if isinstance(document, web.Response):
            return document
        if set(document) != {"group_id", "route_role"}:
            return self._error(400, "guardian_control_payload_invalid")
        group_id = document.get("group_id")
        route_role = document.get("route_role")
        if not isinstance(group_id, str) or not group_id or route_role not in {"primary", "backup"}:
            return self._error(400, "guardian_control_retest_invalid")
        try:
            result = await self._retest_route(group_id, route_role)
        except GatewayControlOperationError as exc:
            return self._error(exc.status, exc.code)
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")
        return self._json(result)

    async def stop(self, request: web.Request) -> web.Response:
        unauthorized = self._authorize(request)
        if unauthorized is not None:
            return unauthorized
        timeout = await self._timeout(request)
        if isinstance(timeout, web.Response):
            return timeout
        try:
            result = await self._stop(timeout)
        except RuntimeError:
            return self._error(409, "guardian_control_operation_rejected")
        return self._json(result, status=202)

    def _authorize(self, request: web.Request) -> web.Response | None:
        if self._allowed_hosts and request.headers.get("Host", "").lower() not in self._allowed_hosts:
            return self._error(403, "guardian_control_host_rejected")
        if request.headers.get("Origin") or request.headers.get("Access-Control-Request-Method"):
            return self._error(403, "guardian_control_browser_origin_rejected")
        authorization = request.headers.get("Authorization", "")
        expected = f"Bearer {self._control_token}"
        if not hmac.compare_digest(authorization, expected):
            return self._error(401, "guardian_control_unauthorized")
        return None

    @staticmethod
    async def _timeout(request: web.Request) -> float | None | web.Response:
        if not request.can_read_body:
            return None
        if request.content_type != "application/json":
            return GatewayControlServer._error(415, "guardian_control_json_required")
        try:
            document = await request.json()
        except Exception:
            return GatewayControlServer._error(400, "guardian_control_json_invalid")
        if not isinstance(document, dict) or set(document) - {"timeout_seconds"}:
            return GatewayControlServer._error(400, "guardian_control_payload_invalid")
        timeout = document.get("timeout_seconds")
        if timeout is None:
            return None
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            return GatewayControlServer._error(400, "guardian_control_timeout_invalid")
        value = float(timeout)
        if not 0 <= value <= 300:
            return GatewayControlServer._error(400, "guardian_control_timeout_invalid")
        return value

    @staticmethod
    async def _json_document(request: web.Request) -> Mapping[str, object] | web.Response:
        if not request.can_read_body:
            return GatewayControlServer._error(400, "guardian_control_payload_required")
        if request.content_type != "application/json":
            return GatewayControlServer._error(415, "guardian_control_json_required")
        try:
            document = await request.json()
        except Exception:
            return GatewayControlServer._error(400, "guardian_control_json_invalid")
        if not isinstance(document, dict):
            return GatewayControlServer._error(400, "guardian_control_payload_invalid")
        return document

    @staticmethod
    def _json(payload: Mapping[str, object], *, status: int = 200) -> web.Response:
        response = web.json_response(dict(payload), status=status)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @staticmethod
    def _error(status: int, code: str) -> web.Response:
        return GatewayControlServer._json(
            {"ok": False, "error": {"code": code}},
            status=status,
        )
