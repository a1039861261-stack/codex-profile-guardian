from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest

import aiohttp

from gateway.app import GatewayProcessHost
from gateway.platforms.linux import LinuxGatewayLayout, StdinBundleApplier
from gateway.platforms.linux_deployment import LinuxVersionedReleaseStore
from tests.test_gateway_g5_lifecycle import _config_document


def _free_port(*, excluding: set[int] | None = None) -> int:
    blocked = excluding or set()
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port >= 1024 and port not in blocked:
            return port


class LinuxGatewayHostTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = (Path(self.temporary.name) / "home").resolve()
        self.layout = LinuxGatewayLayout(self.home)
        source = Path(self.temporary.name) / "source"
        (source / "bin").mkdir(parents=True)
        (source / "bin" / "guardian-gateway").write_text("fixture", encoding="utf-8")
        store = LinuxVersionedReleaseStore(
            self.layout,
            transaction_id_factory=lambda: "fixturetx0001",
        )
        store.install("v1.7.0", source, architecture="x86_64")
        store.activate("v1.7.0")
        self.data_port = _free_port()
        self.control_port = _free_port(excluding={self.data_port})
        document = _config_document(
            primary_url="https://primary.fixture.invalid/v1",
            backup_url="https://backup.fixture.invalid/v1",
            data_port=self.data_port,
            control_port=self.control_port,
            revision=1,
        )
        document["gateway_version"] = "v1.7.0"
        document["active_group"]["primary"]["profile_id"] = "primary"
        document["active_group"]["primary"]["secret_ref"] = "profile:primary:r1"
        document["active_group"]["backup"]["profile_id"] = "backup"
        document["active_group"]["backup"]["secret_ref"] = "profile:backup:r1"
        self.allowed_model = document["active_group"]["allowed_models"][0]
        StdinBundleApplier(self.layout).apply(
            stream=__import__("io").BytesIO(
                json.dumps(
                    {
                        "schema_version": 1,
                        "config": document,
                        "secrets": {
                            "primary.r1": "fixture-primary",
                            "backup.r1": "fixture-backup",
                        },
                    }
                ).encode()
            )
        )
        self.host = GatewayProcessHost(
            install_root=self.layout.gateway_root,
            config_path=self.layout.config / "active.json",
            platform="linux",
            home=self.home,
        )

    async def asyncTearDown(self) -> None:
        if self.host.phase not in {"created", "stopped"}:
            await self.host.close()

    async def test_linux_layout_starts_real_data_and_control_planes(self) -> None:
        await self.host.start()
        self.assertEqual(self.host.phase, "running")
        self.assertNotEqual(self.host.ingress_token, self.host.control_token)
        headers = {"Authorization": f"Bearer {self.host.ingress_token}"}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{self.data_port}/health",
                headers=headers,
            ) as response:
                self.assertEqual(response.status, 200)
                health = await response.json()
            self.assertEqual(health["version"], "v1.7.0")
            self.assertEqual(health["instance_id"], "g5-fixture-instance")
            async with session.get(
                f"http://127.0.0.1:{self.data_port}/v1/models",
                headers=headers,
            ) as response:
                self.assertEqual(response.status, 200)
                models = await response.json()
            self.assertEqual(models["data"][0]["id"], self.allowed_model)
            async with session.get(
                f"http://127.0.0.1:{self.control_port}/control/v1/status",
                headers={"Authorization": f"Bearer {self.host.control_token}"},
            ) as response:
                self.assertEqual(response.status, 200)
                status = await response.json()
            self.assertEqual(status["version"], "v1.7.0")
            self.assertEqual(status["config_revision"], 1)
        self.assertTrue((self.layout.config / "tokens" / "ingress.token").is_file())
        self.assertTrue((self.layout.config / "tokens" / "control.token").is_file())
        runtime_path = self.layout.state / "runtime" / "runtime.json"
        self.assertTrue(runtime_path.is_file())
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        self.assertEqual(runtime["version"], "v1.7.0")
        self.assertEqual(runtime["data_port"], self.data_port)
        self.assertEqual(runtime["control_port"], self.control_port)
        self.assertEqual(Path(runtime["executable_path"]), Path(sys.executable).resolve())
        pointer = json.loads(self.layout.current_pointer.read_text(encoding="utf-8"))
        self.assertEqual(pointer["version"], "v1.7.0")
        release = self.layout.release_path(pointer["version"])
        self.assertTrue((release / "manifest.json").is_file())

    def test_linux_layout_rejects_wrong_roots(self) -> None:
        with self.assertRaisesRegex(ValueError, "gateway_linux_install_root_invalid"):
            GatewayProcessHost(
                install_root=self.home / "wrong",
                config_path=self.layout.config / "active.json",
                platform="linux",
                home=self.home,
            )
        with self.assertRaisesRegex(ValueError, "gateway_linux_config_path_invalid"):
            GatewayProcessHost(
                install_root=self.layout.gateway_root,
                config_path=self.home / "wrong.json",
                platform="linux",
                home=self.home,
            )


if __name__ == "__main__":
    unittest.main()
