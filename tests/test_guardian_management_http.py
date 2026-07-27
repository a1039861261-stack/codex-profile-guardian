from __future__ import annotations

import http.client
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from backend.failover import FailoverPublishError
from backend.guardian import GuardianDiagnosticError, GuardianService
from backend.server import SESSION_COOKIE, start_server


PRIVATE_CANARY = "FULL-PRIVATE-HTTP-FIXTURE-CANARY"


class GuardianManagementHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.codex_home = self.root / "codex-home"
        self.data_dir = self.root / "guardian-data"
        self.web_root = self.root / "dist"
        self.codex_home.mkdir()
        self.web_root.mkdir()
        (self.web_root / "index.html").write_text("<!doctype html><title>fixture</title>", encoding="utf-8")
        self.service = GuardianService(codex_home=self.codex_home, data_dir=self.data_dir)
        self._add_profiles()
        self.server = start_server(
            self.service,
            self.web_root,
            "127.0.0.1",
            0,
            allow_dev_origin=True,
        )
        self.port = int(self.server.server_address[1])

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.temporary.cleanup()

    def _add_profiles(self) -> None:
        state = self.service._load_state()
        state["profiles"] = [
            {
                "id": "api-primary",
                "type": "api",
                "name": "主线路样例",
                "base_url": "https://primary.fixture.invalid/v1",
                "wire_api": "responses",
                "model": "fixture-common",
                "secret_file": "api-primary.dpapi",
                "secret_hint": "P111",
                "credential_revision": 1,
            },
            {
                "id": "api-backup",
                "type": "api",
                "name": "备用线路样例",
                "base_url": "https://backup.fixture.invalid/v1",
                "wire_api": "responses",
                "model": "fixture-common",
                "secret_file": "api-backup.dpapi",
                "secret_hint": "B222",
                "credential_revision": 1,
            },
            {
                "id": "api-third",
                "type": "api",
                "name": "第三线路样例",
                "base_url": "https://third.fixture.invalid/v1",
                "wire_api": "responses",
                "model": "fixture-common",
                "secret_file": "api-third.dpapi",
                "secret_hint": "T333",
                "credential_revision": 1,
            },
        ]
        self.service._save_state(state)

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        cookie: str | None = None,
        origin: str | None = None,
        host: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, object] | None]:
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        if cookie:
            headers["Cookie"] = cookie
        if origin:
            headers["Origin"] = origin
        if extra_headers:
            headers.update(extra_headers)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
        parsed = json.loads(raw) if raw and response_headers.get("content-type", "").startswith("application/json") else None
        return response.status, response_headers, parsed

    def _session(self, *, origin: str | None = None) -> str:
        status, headers, payload = self._request("GET", "/api/session", origin=origin)
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True, "data": {"session": "ready"}})
        cookie = headers["set-cookie"].split(";", 1)[0]
        self.assertTrue(cookie.startswith(f"{SESSION_COOKIE}="))
        self.assertIn("HttpOnly", headers["set-cookie"])
        self.assertIn("SameSite=Strict", headers["set-cookie"])
        return cookie

    def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        cookie: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {"Host": f"127.0.0.1:{self.port}"}
        if cookie:
            headers["Cookie"] = cookie
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, raw

    @staticmethod
    def _group_payload(expected_revision: int, *, name: str = "默认容灾组") -> dict[str, object]:
        return {
            "expected_revision": expected_revision,
            "name": name,
            "enabled": True,
            "primary_profile_id": "api-primary",
            "backup_profile_id": "api-backup",
            "allowed_models": ["fixture-common"],
        }

    def test_host_origin_session_and_cors_are_enforced(self) -> None:
        status, _, payload = self._request("GET", "/api/failover/overview")
        self.assertEqual((status, payload["error"]["code"]), (401, "guardian_management_session_required"))

        status, _, payload = self._request("GET", "/api/session", host="fixture.invalid")
        self.assertEqual((status, payload["error"]["code"]), (403, "guardian_management_host_rejected"))
        status, _, payload = self._request("GET", "/api/session", origin="https://evil.fixture.invalid")
        self.assertEqual((status, payload["error"]["code"]), (403, "guardian_management_origin_rejected"))
        status, _, payload = self._request("GET", "/api/session", origin="http://[::1")
        self.assertEqual((status, payload["error"]["code"]), (403, "guardian_management_origin_rejected"))

        origin = "http://127.0.0.1:5173"
        cookie = self._session(origin=origin)
        status, headers, payload = self._request(
            "GET",
            "/api/failover/overview",
            cookie=cookie,
            origin=origin,
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(headers.get("access-control-allow-origin"), origin)
        self.assertEqual(headers.get("access-control-allow-credentials"), "true")

    def test_official_oauth_binding_requires_session_and_calls_isolated_flow(self) -> None:
        status, _, payload = self._request(
            "POST",
            "/api/profiles/official/oauth",
            payload={"name": "Browser account", "model": ""},
        )
        self.assertEqual(
            (status, payload["error"]["code"]),
            (401, "guardian_management_session_required"),
        )

        cookie = self._session()
        expected = {"id": "official-oauth", "name": "Browser account", "type": "official"}
        with patch.object(self.service, "bind_official_oauth", return_value=expected) as bind:
            status, _, payload = self._request(
                "POST",
                "/api/profiles/official/oauth",
                cookie=cookie,
                payload={"name": "Browser account", "model": "gpt-fixture"},
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"], expected)
        bind.assert_called_once_with("Browser account", "gpt-fixture")

    def test_failover_http_crud_publish_retest_delete_and_revision_conflict(self) -> None:
        cookie = self._session()
        status, _, payload = self._request("GET", "/api/failover/overview", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["revision"], 0)

        status, _, payload = self._request(
            "POST",
            "/api/failover/groups",
            cookie=cookie,
            payload=self._group_payload(0),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["overview"]["revision"], 1)
        group_id = payload["data"]["group"]["id"]

        stale = self._group_payload(0, name="过期写入")
        status, _, payload = self._request(
            "POST",
            f"/api/failover/groups/{group_id}/edit",
            cookie=cookie,
            payload=stale,
        )
        self.assertEqual((status, payload["error"]["code"]), (409, "failover_revision_conflict"))

        status, _, payload = self._request(
            "POST",
            f"/api/failover/groups/{group_id}/edit",
            cookie=cookie,
            payload=self._group_payload(1, name="已重命名"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["overview"]["group"]["name"], "已重命名")

        status, _, payload = self._request(
            "POST",
            f"/api/failover/groups/{group_id}/publish",
            cookie=cookie,
            payload={"expected_revision": 2},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["overview"]["group"]["publication_state"], "applied")

        status, _, payload = self._request(
            "POST",
            f"/api/failover/groups/{group_id}/routes/primary/retest",
            cookie=cookie,
            payload={"expected_revision": 3},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["tested_role"], "primary")
        self.assertEqual(payload["data"]["overview"]["summary"]["carrier"], "primary")

        status, _, payload = self._request(
            "POST",
            "/api/failover/groups",
            cookie=cookie,
            payload={
                **self._group_payload(3, name="待删除组"),
                "primary_profile_id": "api-backup",
                "backup_profile_id": "api-third",
            },
        )
        delete_id = payload["data"]["group"]["id"]
        status, _, payload = self._request(
            "DELETE",
            f"/api/failover/groups/{delete_id}",
            cookie=cookie,
            payload={"expected_revision": 4},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["overview"]["revision"], 5)
        self.assertNotIn(delete_id, {item["id"] for item in payload["data"]["overview"]["groups"]})

        status, _, payload = self._request(
            "POST",
            f"/api/failover/groups/{group_id}/enabled",
            cookie=cookie,
            payload={"expected_revision": 5, "enabled": False},
        )
        self.assertEqual((status, payload["error"]["code"]), (409, "failover_active_group_disable_forbidden"))

    def test_provider_activation_and_restore_are_explicit_session_bound_transactions(self) -> None:
        cookie = self._session()
        status, _, created = self._request(
            "POST",
            "/api/failover/groups",
            cookie=cookie,
            payload=self._group_payload(0),
        )
        self.assertEqual(status, 200)
        group_id = created["data"]["group"]["id"]
        status, _, published = self._request(
            "POST",
            f"/api/failover/groups/{group_id}/publish",
            cookie=cookie,
            payload={"expected_revision": 1},
        )
        self.assertEqual(status, 200)
        self.assertTrue(published["data"]["overview"]["capabilities"]["activate_provider"])

        status, _, rejected = self._request(
            "POST",
            "/api/failover/provider/activate",
            cookie=cookie,
            payload={"expected_revision": 2, "confirm": False},
        )
        self.assertEqual((status, rejected["error"]["code"]), (400, "guardian_request_failed"))

        status, _, activated = self._request(
            "POST",
            "/api/failover/provider/activate",
            cookie=cookie,
            payload={"expected_revision": 2, "confirm": True},
        )
        self.assertEqual(status, 200)
        self.assertEqual(activated["data"]["provider"]["status"], "active")
        self.assertTrue(activated["data"]["overview"]["capabilities"]["restore_direct"])
        config = (self.codex_home / "config.toml").read_text(encoding="utf-8")
        self.assertIn('model_provider = "guardian_gateway"', config)
        self.assertIn("request_max_retries = 0", config)
        self.assertIn("stream_max_retries = 0", config)

        status, _, restored = self._request(
            "POST",
            "/api/failover/provider/restore",
            cookie=cookie,
            payload={"confirm": True},
        )
        self.assertEqual(status, 200)
        self.assertEqual(restored["data"]["provider"]["status"], "restored")
        self.assertFalse((self.codex_home / "config.toml").exists())

        status, _, unauthorized = self._request(
            "POST",
            "/api/failover/provider/restore",
            payload={"confirm": True},
        )
        self.assertEqual((status, unauthorized["error"]["code"]), (401, "guardian_management_session_required"))

    def test_internal_and_domain_errors_do_not_leak_exception_text(self) -> None:
        cookie = self._session()
        with patch.object(
            self.service.require_failover(),
            "overview",
            side_effect=RuntimeError(PRIVATE_CANARY),
        ):
            status, _, payload = self._request("GET", "/api/failover/overview", cookie=cookie)
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertEqual((status, payload["error"]["code"]), (500, "guardian_internal_error"))
        self.assertNotIn(PRIVATE_CANARY, serialized)

        with patch.object(
            self.service,
            "capture_official",
            side_effect=Exception(PRIVATE_CANARY),
        ):
            status, _, payload = self._request(
                "POST",
                "/api/profiles/official/capture",
                cookie=cookie,
                payload={"name": "fixture"},
            )
        self.assertEqual(status, 500)
        self.assertNotIn(PRIVATE_CANARY, json.dumps(payload, ensure_ascii=False))

        with patch.object(
            self.service.require_failover(),
            "publish_group",
            side_effect=FailoverPublishError("failover_publish_state_uncertain"),
        ):
            status, _, payload = self._request(
                "POST",
                "/api/failover/groups/00000000-0000-0000-0000-000000000000/publish",
                cookie=cookie,
                payload={"expected_revision": 0},
            )
        self.assertEqual((status, payload["error"]["code"]), (500, "failover_publish_state_uncertain"))
        self.assertFalse(payload["error"]["retryable"])

    def test_chunked_management_bodies_are_rejected(self) -> None:
        cookie = self._session()
        status, _, payload = self._request(
            "POST",
            "/api/failover/groups",
            cookie=cookie,
            extra_headers={"Transfer-Encoding": "chunked"},
        )
        self.assertEqual((status, payload["error"]["code"]), (400, "guardian_request_failed"))

    def test_update_endpoints_require_session_and_exact_install_confirmation(self) -> None:
        status, _, payload = self._request("GET", "/api/update")
        self.assertEqual((status, payload["error"]["code"]), (401, "guardian_management_session_required"))

        cookie = self._session()
        public_status = {"state": "available", "current_version": "1.8.7", "latest_version": "1.9.0"}
        with patch.object(self.service, "update_status", return_value=public_status):
            status, _, payload = self._request("GET", "/api/update", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"], public_status)

        with patch.object(self.service, "check_for_updates", return_value=public_status) as check:
            status, _, payload = self._request("POST", "/api/update/check", cookie=cookie, payload={})
        self.assertEqual(status, 200)
        check.assert_called_once_with()

        with patch.object(self.service, "download_update", return_value={**public_status, "state": "downloaded"}) as download:
            status, _, payload = self._request("POST", "/api/update/download", cookie=cookie, payload={})
        self.assertEqual(status, 200)
        download.assert_called_once_with()

        for body in ({}, {"confirm": False, "extra": True}):
            with self.subTest(body=body):
                status, _, payload = self._request("POST", "/api/update/install", cookie=cookie, payload=body)
                self.assertEqual((status, payload["error"]["code"]), (400, "guardian_request_failed"))

        with patch.object(self.service, "install_update", return_value={**public_status, "state": "installing"}) as install:
            status, _, payload = self._request("POST", "/api/update/install", cookie=cookie, payload={"confirm": True})
        self.assertEqual(status, 200)
        install.assert_called_once_with(confirmed=True)

    def test_claude_desktop_status_and_explicit_actions_use_management_session(self) -> None:
        cookie = self._session()
        fixture_status = {
            "state": "ready",
            "deployment_mode": "third_party",
            "config_owner": "guardian",
        }
        with patch.object(
            self.service,
            "claude_desktop_status",
            return_value=fixture_status,
        ) as status_method:
            status, _, payload = self._request(
                "GET",
                "/api/claude-desktop/status",
                cookie=cookie,
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"], fixture_status)
        status_method.assert_called_once_with()

        with patch.object(
            self.service, "create_claude_profile", return_value={"id": "a" * 32}
        ) as create:
            body = {
                "name": "Fixture",
                "base_url": "https://claude.fixture.invalid",
                "api_key": "secret",
                "models": ["claude-sonnet-5"],
            }
            status, _, payload = self._request(
                "POST", "/api/claude-desktop/providers", cookie=cookie, payload=body
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["data"], {"id": "a" * 32})
            create.assert_called_once_with(body)

        profile_id = "a" * 32
        with patch.object(
            self.service, "apply_claude_profile", return_value={"applied": True}
        ) as apply_profile:
            status, _, payload = self._request(
                "POST",
                f"/api/claude-desktop/providers/{profile_id}/apply",
                cookie=cookie,
                payload={"confirm": True},
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["data"], {"applied": True})
            apply_profile.assert_called_once_with(profile_id, confirmed=True)

        with patch.object(
            self.service, "restore_claude_official", return_value={"restored": True}
        ) as restore:
            status, _, payload = self._request(
                "POST",
                "/api/claude-desktop/restore-official",
                cookie=cookie,
                payload={"confirm": True},
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["data"], {"restored": True})
            restore.assert_called_once_with(confirmed=True)

        with patch.object(
            self.service, "import_claude_from_cc_switch", return_value={"imported": True}
        ) as migrate:
            status, _, payload = self._request(
                "POST",
                "/api/claude-desktop/import-cc-switch",
                cookie=cookie,
                payload={"confirm": True},
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["data"], {"imported": True})
            migrate.assert_called_once_with(confirmed=True)

        with patch.object(
            self.service, "restart_claude_desktop", return_value={"restarted": True}
        ) as restart:
            status, _, payload = self._request(
                "POST", "/api/claude-desktop/restart", cookie=cookie, payload={}
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["data"], {"restarted": True})
            restart.assert_called_once_with()

        status, _, payload = self._request(
            "POST",
            "/api/claude-desktop/restart",
            payload={},
        )
        self.assertEqual((status, payload["error"]["code"]), (401, "guardian_management_session_required"))

    def test_gateway_hosts_get_is_cache_only_and_refresh_requires_explicit_confirmation(self) -> None:
        cookie = self._session()
        cached = {
            "schema_version": 1,
            "checked_at": "2026-07-14T00:30:00+00:00",
            "items": [],
        }
        with patch.object(
            self.service,
            "gateway_hosts_status",
            return_value=cached,
        ) as read:
            status, _, payload = self._request(
                "GET",
                "/api/failover/hosts",
                cookie=cookie,
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"], cached)
        read.assert_called_once_with()

        status, _, payload = self._request(
            "POST",
            "/api/failover/hosts/refresh",
            cookie=cookie,
            payload={},
        )
        self.assertEqual((status, payload["error"]["code"]), (400, "guardian_request_failed"))

        refreshed = {**cached, "items": [{"kind": "windows", "online": True}]}
        with patch.object(
            self.service,
            "refresh_gateway_hosts_status",
            return_value=refreshed,
        ) as refresh:
            status, _, payload = self._request(
                "POST",
                "/api/failover/hosts/refresh",
                cookie=cookie,
                payload={"confirm_read_only": True},
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"], refreshed)
        refresh.assert_called_once_with(confirm_read_only=True)

    def test_failover_diagnostics_download_is_session_bound_and_redacted(self) -> None:
        status, headers, raw = self._request_bytes("GET", "/api/failover/diagnostics")
        self.assertEqual(status, 401)
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assertEqual(json.loads(raw)["error"]["code"], "guardian_management_session_required")

        cookie = self._session()
        status, _, overview = self._request("GET", "/api/failover/overview", cookie=cookie)
        self.assertEqual(status, 200)
        status, _, created = self._request(
            "POST",
            "/api/failover/groups",
            cookie=cookie,
            payload=self._group_payload(overview["data"]["revision"]),
        )
        self.assertEqual(status, 200)
        self.assertIsNotNone(created["data"]["group"]["id"])

        status, headers, raw = self._request_bytes(
            "GET",
            "/api/failover/diagnostics",
            cookie=cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/zip")
        self.assertRegex(
            headers["content-disposition"],
            r'^attachment; filename="guardian-diagnostics-[0-9]{8}T[0-9]{6}Z\.zip"$',
        )
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        with ZipFile(BytesIO(raw), "r") as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    "manifest.json",
                    "gateway-status.json",
                    "gateway-events.json",
                    "gateway-hosts.json",
                ],
            )
            exported = "\n".join(
                archive.read(name).decode("utf-8") for name in archive.namelist()
            )
        for forbidden in (
            "api-primary",
            "api-backup",
            "primary.fixture.invalid",
            "backup.fixture.invalid",
            "P111",
            "B222",
            "profile_id",
            "group_id",
            "host_key",
            "display_name",
        ):
            self.assertNotIn(forbidden, exported)

        with patch.object(
            self.service,
            "export_failover_diagnostics",
            side_effect=GuardianDiagnosticError(PRIVATE_CANARY),
        ):
            status, _, raw = self._request_bytes(
                "GET",
                "/api/failover/diagnostics",
                cookie=cookie,
            )
        payload = json.loads(raw)
        self.assertEqual((status, payload["error"]["code"]), (500, "guardian_diagnostics_failed"))
        self.assertNotIn(PRIVATE_CANARY, json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
