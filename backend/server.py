from __future__ import annotations

from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

from .failover import (
    FailoverConflictError,
    FailoverError,
    FailoverNotFoundError,
    FailoverPublishError,
    FailoverStoreError,
    FailoverValidationError,
)
from .guardian import (
    APP_VERSION,
    GuardianDiagnosticError,
    GuardianError,
    GuardianPublicError,
    GuardianService,
)


SESSION_COOKIE = "guardian_session"
MAX_BODY_BYTES = 1024 * 1024


class GuardianHandler(SimpleHTTPRequestHandler):
    server_version = f"CodexProfileGuardian/{APP_VERSION}"

    @property
    def service(self) -> GuardianService:
        return self.server.guardian_service  # type: ignore[attr-defined]

    @property
    def web_root(self) -> Path:
        return self.server.web_root  # type: ignore[attr-defined]

    @property
    def session_token(self) -> str:
        return self.server.session_token  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _allowed_hosts(self) -> frozenset[str]:
        port = int(self.server.server_address[1])
        return frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})

    def _request_host_valid(self) -> bool:
        host = self.headers.get("Host", "").strip().lower()
        return host in self._allowed_hosts()

    def _allowed_origin(self) -> str | None:
        origin = self.headers.get("Origin")
        if origin is None:
            return None
        try:
            parsed = urlparse(origin)
            port = parsed.port
        except ValueError:
            return ""
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in {"", "/"}:
            return ""
        if parsed.query or parsed.fragment or parsed.hostname not in {"127.0.0.1", "localhost"}:
            return ""
        server_port = int(self.server.server_address[1])
        if port == server_port:
            return origin
        if self.server.allow_dev_origin and port == 5173:  # type: ignore[attr-defined]
            return origin
        return ""

    def _session_valid(self) -> bool:
        raw = self.headers.get("Cookie", "")
        try:
            cookies = SimpleCookie()
            cookies.load(raw)
            value = cookies.get(SESSION_COOKIE)
        except Exception:
            return False
        return bool(value and hmac.compare_digest(value.value, self.session_token))

    def _common_headers(self, *, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        origin = self._allowed_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def _json(
        self,
        value: Any,
        status: int = 200,
        *,
        establish_session: bool = False,
    ) -> None:
        payload = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self._common_headers(content_type="application/json; charset=utf-8", length=len(payload))
        if establish_session:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={self.session_token}; Path=/; HttpOnly; SameSite=Strict",
            )
        self.end_headers()
        self.wfile.write(payload)

    def _binary(self, payload: bytes, *, content_type: str, filename: str) -> None:
        if (
            not payload
            or len(payload) > 1024 * 1024
            or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", filename) is None
        ):
            raise GuardianError("诊断包响应无效。")
        self.send_response(200)
        self._common_headers(content_type=content_type, length=len(payload))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(payload)

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        error = {
            "code": code,
            "message": message,
            "retryable": retryable,
        }
        if details:
            error["details"] = details
        self._json(
            {
                "ok": False,
                "error": error,
            },
            status,
        )

    def _authorize(self, *, require_session: bool = True) -> bool:
        if not self._request_host_valid():
            self._error(403, "guardian_management_host_rejected", "管理请求的 Host 无效。")
            return False
        if self._allowed_origin() == "":
            self._error(403, "guardian_management_origin_rejected", "管理请求的 Origin 无效。")
            return False
        if require_session and not self._session_valid():
            self._error(401, "guardian_management_session_required", "管理会话已失效，请重新加载页面。")
            return False
        return True

    def _body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise GuardianError("guardian_chunked_request_rejected")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError as exc:
            raise GuardianError("请求体长度无效。") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise GuardianError("请求体过大。")
        if not length:
            return {}
        if content_type != "application/json":
            raise GuardianError("管理接口只接受 JSON 请求。")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise GuardianError("请求体不完整。")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuardianError("无效的 JSON 请求。") from exc
        if not isinstance(value, dict):
            raise GuardianError("JSON 请求必须是对象。")
        return value

    @staticmethod
    def _required_revision(body: dict[str, Any]) -> int:
        value = body.pop("expected_revision", None)
        if type(value) is not int:
            raise FailoverValidationError("failover_expected_revision_invalid")
        return value

    def _handle_error(self, exc: Exception) -> None:
        if isinstance(exc, FailoverValidationError):
            self._error(400, exc.code, "容灾配置无效，请检查输入。")
        elif isinstance(exc, FailoverNotFoundError):
            self._error(404, exc.code, "找不到对应的容灾配置。")
        elif isinstance(exc, FailoverConflictError):
            self._error(409, exc.code, "配置已变化，请刷新后重试。")
        elif isinstance(exc, FailoverPublishError):
            status = 500 if exc.code == "failover_publish_state_uncertain" else 502
            self._error(status, exc.code, "网关配置发布失败，旧配置已保留。", retryable=status == 502)
        elif isinstance(exc, FailoverStoreError):
            self._error(500, exc.code, "容灾配置库不可用，已停止写入。")
        elif isinstance(exc, FailoverError):
            self._error(400, exc.code, "容灾操作失败。")
        elif isinstance(exc, GuardianDiagnosticError):
            self._error(500, "guardian_diagnostics_failed", "脱敏诊断包生成失败。")
        elif isinstance(exc, GuardianPublicError):
            self._error(
                409,
                exc.code,
                exc.public_message,
                retryable=exc.retryable,
                details=exc.details,
            )
        elif isinstance(exc, GuardianError):
            self._error(400, "guardian_request_failed", "请求未完成，请检查输入和当前状态。")
        else:
            self._error(500, "guardian_internal_error", "管理服务发生内部错误。")

    def do_OPTIONS(self) -> None:
        if not self._authorize(require_session=False):
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        origin = self._allowed_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/session":
            if self._authorize(require_session=False):
                self._json(
                    {"ok": True, "data": {"session": "ready"}},
                    establish_session=True,
                )
            return
        if path.startswith("/api/") and not self._authorize(require_session=path != "/api/health"):
            return
        try:
            if path == "/api/status":
                data = self.service.status()
            elif path == "/api/profiles":
                data = self.service.list_profiles()
            elif path == "/api/backups":
                data = self.service.list_backups()
            elif path == "/api/protection/conflicts":
                data = self.service.history_conflict_report()
            elif path == "/api/logs":
                data = self.service.logs()
            elif path == "/api/health":
                data = {"service": "ready"}
            elif path == "/api/claude-desktop/status":
                data = self.service.claude_desktop_status()
            elif path == "/api/update":
                data = self.service.update_status()
            elif path == "/api/failover/overview":
                query = parse_qs(parsed.query, keep_blank_values=False)
                data = self.service.require_failover().overview(
                    (query.get("group_id") or [None])[0]
                )
            elif path == "/api/failover/events":
                query = parse_qs(parsed.query, keep_blank_values=False)
                try:
                    offset = int((query.get("offset") or ["0"])[0])
                    limit = int((query.get("limit") or ["20"])[0])
                except ValueError as exc:
                    raise FailoverValidationError("failover_event_page_invalid") from exc
                data = self.service.require_failover().list_events(
                    group_id=(query.get("group_id") or [None])[0],
                    offset=offset,
                    limit=limit,
                )
            elif path == "/api/failover/hosts":
                data = self.service.gateway_hosts_status()
            elif path == "/api/failover/diagnostics":
                bundle = self.service.export_failover_diagnostics()
                self._binary(
                    bundle.payload,
                    content_type=bundle.content_type,
                    filename=bundle.filename,
                )
                return
            elif path.startswith("/api/"):
                self._error(404, "guardian_endpoint_not_found", "接口不存在。")
                return
            else:
                if not self._authorize(require_session=False):
                    return
                self._serve_static(path)
                return
            self._json({"ok": True, "data": data})
        except Exception as exc:
            self._handle_error(exc)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self._authorize():
            return
        try:
            body = self._body()
            failover = self.service.failover
            if path == "/api/profiles/official/capture":
                data = self.service.capture_official(body.get("name", ""), body.get("model", ""))
            elif path == "/api/profiles/official/oauth":
                data = self.service.bind_official_oauth(
                    body.get("name", ""),
                    body.get("model", ""),
                )
            elif path == "/api/profiles/api":
                data = self.service.create_api_profile(
                    body.get("name", ""),
                    body.get("base_url", ""),
                    body.get("api_key", ""),
                    body.get("model", ""),
                    body.get("protocol_compatibility"),
                )
            elif match := re.fullmatch(r"/api/profiles/([a-f0-9]+)/edit", path):
                data = self.service.edit_profile(match.group(1), body)
            elif path == "/api/import/cockpit":
                data = self.service.import_cockpit()
            elif match := re.fullmatch(r"/api/profiles/([a-f0-9]+)/test", path):
                data = self.service.test_api_profile(match.group(1))
            elif match := re.fullmatch(r"/api/profiles/([a-f0-9]+)/switch", path):
                data = self.service.switch_profile(match.group(1))
            elif match := re.fullmatch(r"/api/profiles/([a-f0-9]+)/sync", path):
                data = self.service.update_official_profile(match.group(1))
            elif path == "/api/failover/groups":
                expected = self._required_revision(body)
                data = self.service.require_failover().create_group(body, expected_revision=expected)
            elif match := re.fullmatch(r"/api/failover/groups/([0-9a-f-]+)/edit", path):
                expected = self._required_revision(body)
                data = self.service.require_failover().update_group(
                    match.group(1), body, expected_revision=expected
                )
            elif match := re.fullmatch(r"/api/failover/groups/([0-9a-f-]+)/enabled", path):
                expected = self._required_revision(body)
                data = self.service.require_failover().update_group(
                    match.group(1),
                    {"enabled": body.get("enabled")},
                    expected_revision=expected,
                )
            elif match := re.fullmatch(r"/api/failover/groups/([0-9a-f-]+)/publish", path):
                expected = self._required_revision(body)
                data = self.service.require_failover().publish_group(
                    match.group(1), expected_revision=expected
                )
            elif match := re.fullmatch(
                r"/api/failover/groups/([0-9a-f-]+)/routes/(primary|backup)/retest",
                path,
            ):
                expected = self._required_revision(body)
                data = self.service.require_failover().retest_route(
                    match.group(1), match.group(2), expected_revision=expected
                )
            elif path == "/api/failover/provider/activate":
                if set(body) != {"expected_revision", "confirm"}:
                    raise GuardianError("固定 provider 启用参数无效。")
                expected = self._required_revision(body)
                data = self.service.activate_failover_provider(
                    expected_revision=expected,
                    confirmed=body.get("confirm") is True,
                )
            elif path == "/api/failover/provider/restore":
                if set(body) != {"confirm"}:
                    raise GuardianError("恢复直连参数无效。")
                data = self.service.restore_direct_provider(
                    confirmed=body.get("confirm") is True,
                )
            elif path == "/api/failover/hosts/refresh":
                if set(body) != {"confirm_read_only"}:
                    raise GuardianError("远端状态刷新参数无效。")
                data = self.service.refresh_gateway_hosts_status(
                    confirm_read_only=body.get("confirm_read_only") is True
                )
            elif path == "/api/protection/repair":
                data = self.service.repair_visibility()
            elif path == "/api/protection/conflicts/isolate":
                if set(body) != {"confirm"}:
                    raise GuardianError("聊天冲突隔离参数无效。")
                data = self.service.resolve_history_conflicts(
                    confirmed=body.get("confirm") is True
                )
            elif match := re.fullmatch(r"/api/backups/([^/]+)/restore", path):
                data = self.service.restore_backup(match.group(1))
            elif path == "/api/settings":
                data = self.service.update_settings(body)
            elif path == "/api/remote/sync-current":
                data = self.service.sync_current_to_remotes()
            elif path == "/api/quotas/refresh":
                data = self.service.refresh_official_quotas()
            elif path == "/api/update/check":
                data = self.service.check_for_updates()
            elif path == "/api/update/download":
                data = self.service.download_update()
            elif path == "/api/update/install":
                if set(body) != {"confirm"}:
                    raise GuardianError("更新安装参数无效。")
                data = self.service.install_update(confirmed=body.get("confirm") is True)
            elif path == "/api/launch":
                data = {"launched": self.service.launch_codex()}
            elif path == "/api/claude-desktop/providers":
                data = self.service.create_claude_profile(body)
            elif match := re.fullmatch(r"/api/claude-desktop/providers/([a-f0-9]+)/edit", path):
                data = self.service.edit_claude_profile(match.group(1), body)
            elif match := re.fullmatch(r"/api/claude-desktop/providers/([a-f0-9]+)/apply", path):
                if set(body) != {"confirm"}:
                    raise GuardianError("Claude 供应商启用参数无效。")
                data = self.service.apply_claude_profile(
                    match.group(1), confirmed=body.get("confirm") is True
                )
            elif path == "/api/claude-desktop/restore-official":
                if set(body) != {"confirm"}:
                    raise GuardianError("Claude 官方模式恢复参数无效。")
                data = self.service.restore_claude_official(
                    confirmed=body.get("confirm") is True
                )
            elif path == "/api/claude-desktop/import-cc-switch":
                if set(body) != {"confirm"}:
                    raise GuardianError("Claude 迁移参数无效。")
                data = self.service.import_claude_from_cc_switch(
                    confirmed=body.get("confirm") is True
                )
            elif path == "/api/claude-desktop/restart":
                data = self.service.restart_claude_desktop()
            elif path == "/api/open-folder":
                self.service.open_path(body.get("kind", "data"))
                data = {"opened": body.get("kind", "data")}
            elif path == "/api/logs/clear":
                self.service.clear_logs()
                data = {"cleared": True}
            else:
                self._error(404, "guardian_endpoint_not_found", "接口不存在。")
                return
            self._json({"ok": True, "data": data})
        except Exception as exc:
            self._handle_error(exc)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not self._authorize():
            return
        try:
            body = self._body()
            if match := re.fullmatch(r"/api/profiles/([a-f0-9]+)", path):
                self.service.delete_profile(match.group(1))
                data = {"deleted": match.group(1)}
            elif match := re.fullmatch(r"/api/claude-desktop/providers/([a-f0-9]+)", path):
                data = self.service.delete_claude_profile(match.group(1))
            elif match := re.fullmatch(r"/api/failover/groups/([0-9a-f-]+)", path):
                expected = self._required_revision(body)
                data = self.service.require_failover().delete_group(
                    match.group(1), expected_revision=expected
                )
            else:
                self._error(404, "guardian_endpoint_not_found", "接口不存在。")
                return
            self._json({"ok": True, "data": data})
        except Exception as exc:
            self._handle_error(exc)

    def _serve_static(self, request_path: str) -> None:
        relative = request_path.lstrip("/") or "index.html"
        candidate = (self.web_root / relative).resolve()
        if self.web_root not in candidate.parents and candidate != self.web_root:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not candidate.is_file():
            candidate = self.web_root / "index.html"
        if not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Frontend build not found")
            return
        content = candidate.read_bytes()
        content_type = self.guess_type(str(candidate))
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header(
            "Cache-Control",
            "no-store" if candidate.name == "index.html" else "public, max-age=31536000",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if candidate.suffix.lower() == ".html":
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
            )
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={self.session_token}; Path=/; HttpOnly; SameSite=Strict",
            )
        self.end_headers()
        self.wfile.write(content)


class GuardianHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        service: GuardianService,
        web_root: Path,
        *,
        allow_dev_origin: bool = False,
    ) -> None:
        try:
            if not ipaddress.ip_address(address[0]).is_loopback:
                raise ValueError("guardian_management_loopback_required")
        except ValueError as exc:
            raise ValueError("guardian_management_loopback_required") from exc
        super().__init__(address, GuardianHandler)
        self.guardian_service = service
        self.web_root = web_root.resolve()
        self.session_token = secrets.token_urlsafe(48)
        self.allow_dev_origin = bool(allow_dev_origin)


def start_server(
    service: GuardianService,
    web_root: Path,
    host: str,
    port: int,
    *,
    allow_dev_origin: bool | None = None,
) -> GuardianHTTPServer:
    server = GuardianHTTPServer(
        (host, port),
        service,
        web_root,
        allow_dev_origin=service.is_fixture if allow_dev_origin is None else allow_dev_origin,
    )
    thread = threading.Thread(target=server.serve_forever, name="guardian-http", daemon=True)
    thread.start()
    return server
