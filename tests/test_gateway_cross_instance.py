from __future__ import annotations

import io
import json
from contextlib import nullcontext
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aiohttp

from gateway.app import GatewayProcessHost
from gateway.platforms.linux import LinuxGatewayLayout, StdinBundleApplier
from gateway.platforms.linux_deployment import LinuxVersionedReleaseStore
from gateway.secrets import PosixFileSecretResolver
from gateway.tokens import PosixTokenStore
from tests.gateway_probe_support import (
    FAKE_BEARER,
    ProgrammableResponsesMock,
    ScriptedScenario,
    fixture_request,
    text_scenario,
)
from tests.test_gateway_g5_lifecycle import (
    _authorization,
    _config_document,
    _free_port,
    _protect,
    _unprotect,
    _write_fixture_install,
)


class GatewayCrossInstanceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.mocks: list[ProgrammableResponsesMock] = []
        self.hosts: list[GatewayProcessHost] = []

    async def asyncTearDown(self) -> None:
        for host in reversed(self.hosts):
            if host.phase not in {"created", "stopped"}:
                await host.close()
        for mock in reversed(self.mocks):
            mock.close()

    def _mock(self, scenario: ScriptedScenario, name: str) -> ProgrammableResponsesMock:
        mock = ProgrammableResponsesMock(lambda _request: scenario, route_name=name).start()
        self.mocks.append(mock)
        return mock

    def _windows_host(
        self,
        primary: ProgrammableResponsesMock,
        backup: ProgrammableResponsesMock,
    ) -> tuple[GatewayProcessHost, dict[str, object]]:
        data_port = _free_port()
        control_port = _free_port(excluding={data_port})
        document = _config_document(
            primary_url=primary.base_url,
            backup_url=backup.base_url,
            data_port=data_port,
            control_port=control_port,
        )
        document["instance_id"] = "windows-fixture-instance"
        config = _write_fixture_install(self.root / "windows", document)
        host = GatewayProcessHost(
            install_root=config.parents[2],
            config_path=config,
            protect=_protect,
            unprotect=_unprotect,
        )
        self.hosts.append(host)
        return host, document

    def _nas_host(
        self,
        primary: ProgrammableResponsesMock,
        backup: ProgrammableResponsesMock,
    ) -> tuple[GatewayProcessHost, dict[str, object], LinuxGatewayLayout]:
        home = self.root / "nas-home"
        layout = LinuxGatewayLayout(home)
        source = self.root / "nas-release"
        (source / "bin").mkdir(parents=True)
        (source / "bin" / "guardian-gateway").write_text("fixture", encoding="utf-8")
        release_store = LinuxVersionedReleaseStore(
            layout,
            transaction_id_factory=lambda: "crossinstance0001",
        )
        release_store.install("v1.7.0", source, architecture="x86_64")
        release_store.activate("v1.7.0")

        data_port = _free_port()
        control_port = _free_port(excluding={data_port})
        document = _config_document(
            primary_url=primary.base_url,
            backup_url=backup.base_url,
            data_port=data_port,
            control_port=control_port,
        )
        document["instance_id"] = "nas-fixture-instance"
        document["gateway_version"] = "v1.7.0"
        document["active_group"]["primary"]["profile_id"] = "nas-primary"
        document["active_group"]["primary"]["secret_ref"] = "profile:nas-primary:r1"
        document["active_group"]["backup"]["profile_id"] = "nas-backup"
        document["active_group"]["backup"]["secret_ref"] = "profile:nas-backup:r1"
        StdinBundleApplier(layout).apply(
            io.BytesIO(
                json.dumps(
                    {
                        "schema_version": 1,
                        "config": document,
                        "secrets": {
                            "nas-primary.r1": FAKE_BEARER,
                            "nas-backup.r1": FAKE_BEARER,
                        },
                    }
                ).encode()
            )
        )
        host = GatewayProcessHost(
            install_root=layout.gateway_root,
            config_path=layout.config / "active.json",
            platform="linux",
            home=home,
        )
        self.hosts.append(host)
        return host, document, layout

    async def _request(self, host: GatewayProcessHost, document: dict[str, object]) -> bytes:
        data_port = int(document["listen"]["data_port"])
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"http://127.0.0.1:{data_port}/v1/responses",
                data=fixture_request(),
                headers={
                    **_authorization(host.ingress_token),
                    "Content-Type": "application/json",
                },
            ) as response:
                body = await response.read()
                self.assertEqual(response.status, 200, body)
                return body

    @staticmethod
    def _read_posix_token_fixture(store: PosixTokenStore, purpose: str) -> str:
        store._validate_purpose(purpose)
        value = store._path(purpose).read_text(encoding="ascii")
        store._validate_token(value)
        return value

    async def test_nas_remains_independent_and_restores_breaker_after_restart(self) -> None:
        windows_primary = self._mock(text_scenario(text="WINDOWS_PRIMARY"), "Windows P1")
        windows_backup = self._mock(text_scenario(text="WINDOWS_BACKUP"), "Windows P2")
        nas_primary = self._mock(
            ScriptedScenario(
                name="nas_primary_503",
                status=503,
                content_type="application/json",
                chunks=(b'{"private":"discarded-nas-primary"}',),
            ),
            "NAS P1",
        )
        nas_backup_scenario = text_scenario(text="NAS_BACKUP_COMPLETE")
        nas_backup = self._mock(nas_backup_scenario, "NAS P2")
        windows, windows_config = self._windows_host(windows_primary, windows_backup)
        nas, nas_config, layout = self._nas_host(nas_primary, nas_backup)

        await windows.start()
        await nas.start()
        await windows.close()
        self.assertEqual(windows.phase, "stopped")
        self.assertEqual(nas.phase, "running")

        permission_fixture = (
            (
                patch.object(PosixFileSecretResolver, "resolve", return_value=FAKE_BEARER),
                patch.object(PosixTokenStore, "_read", new=self._read_posix_token_fixture),
            )
            if os.name == "nt"
            else (nullcontext(), nullcontext())
        )
        with permission_fixture[0], permission_fixture[1]:
            first_body = await self._request(nas, nas_config)
            self.assertEqual(first_body, b"".join(nas_backup_scenario.chunks))
            self.assertNotIn(b"discarded-nas-primary", first_body)
            self.assertEqual((nas_primary.request_count, nas_backup.request_count), (1, 1))
            self.assertEqual((windows_primary.request_count, windows_backup.request_count), (0, 0))
            state_path = layout.state / "breaker.json"
            self.assertIn(b"open_temporary", state_path.read_bytes())

            first_tokens = (nas.ingress_token, nas.control_token)
            await nas.close()
            restarted = GatewayProcessHost(
                install_root=layout.gateway_root,
                config_path=layout.config / "active.json",
                platform="linux",
                home=layout.home,
            )
            self.hosts.append(restarted)
            await restarted.start()
            self.assertEqual((restarted.ingress_token, restarted.control_token), first_tokens)
            self.assertEqual(restarted._provider.restored_routes, 2)

            second_body = await self._request(restarted, nas_config)
        self.assertEqual(second_body, b"".join(nas_backup_scenario.chunks))
        self.assertEqual((nas_primary.request_count, nas_backup.request_count), (1, 2))
        restored = json.loads(state_path.read_text(encoding="utf-8"))
        route_states = {
            (route["route_role"], route["state"])
            for route in restored["routes"]
        }
        self.assertIn(("primary", "open_temporary"), route_states)
        self.assertIn(("backup", "closed"), route_states)


if __name__ == "__main__":
    unittest.main()
