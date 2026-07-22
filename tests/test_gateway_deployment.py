from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway.app import GatewayProcessHost
from gateway.deployment import GatewayDeploymentError, GatewayDeploymentManager
from gateway.platforms.windows import ReleaseError, VersionedReleaseStore, WindowsGatewayLayout


class CallbackRecorder:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.failures: dict[str, object] = {}

    async def drain(self):
        return self._record("drain")

    async def stop(self):
        return self._record("stop")

    async def start(self, release):
        return self._record(f"start:{release.version}")

    async def health(self, release):
        return self._record(f"health:{release.version}")

    def _record(self, event: str):
        self.events.append(event)
        result = self.failures.get(event, {"ok": True})
        if isinstance(result, BaseException):
            raise result
        return result


class GatewayDeploymentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.layout = WindowsGatewayLayout(self.root / "fixture-install")
        self.transaction = 0
        self.store = VersionedReleaseStore(
            self.layout,
            transaction_id_factory=self._transaction_id,
        )
        self.old_source = self._source("old-source", "old executable")
        self.old_release = self.store.install("v1.7.0", self.old_source)
        self.old_pointer = self.store.activate("v1.7.0")
        self.config = self.layout.config / "gateway-config.json"
        self.config.parent.mkdir(parents=True)
        self.config.write_text('{"fixture":"preserve"}\n', encoding="utf-8")

    def _transaction_id(self) -> str:
        self.transaction += 1
        return f"fixturetx{self.transaction:04d}"

    def _source(self, name: str, content: str) -> Path:
        source = self.root / name
        source.mkdir()
        (source / "GuardianGateway.exe").write_text(content, encoding="utf-8")
        resources = source / "resources"
        resources.mkdir()
        (resources / "runtime.dat").write_bytes(content.encode("utf-8") + b"-runtime")
        return source

    def _manager(self, callbacks: CallbackRecorder) -> GatewayDeploymentManager:
        return GatewayDeploymentManager(
            self.store,
            drain=callbacks.drain,
            stop=callbacks.stop,
            start=callbacks.start,
            verify_health=callbacks.health,
        )

    async def test_successful_upgrade_uses_atomic_host_compatible_pointer(self) -> None:
        callbacks = CallbackRecorder()
        new_source = self._source("new-source", "new executable")
        result = await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertEqual(callbacks.events, ["drain", "stop", "start:v1.8.0", "health:v1.8.0"])
        self.assertEqual(result.previous_version, "v1.7.0")
        self.assertEqual(result.active_version, "v1.8.0")
        pointer = json.loads(self.layout.current_pointer.read_text(encoding="utf-8"))
        self.assertEqual(
            set(pointer),
            {"schema_version", "version", "relative_path", "manifest_sha256", "previous_version"},
        )
        self.assertEqual(pointer["schema_version"], 1)
        self.assertEqual(pointer["version"], "v1.8.0")
        self.assertEqual(pointer["relative_path"], "gateway/versions/v1.8.0")
        manifest = self.layout.release_path("v1.8.0") / "manifest.json"
        self.assertEqual(pointer["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
        self.assertEqual(self.store.load_pointer().active_version, "v1.8.0")
        host = object.__new__(GatewayProcessHost)
        host.install_root = self.layout.root
        host._ensure_version_pointer("v1.8.0")
        self.assertTrue(self.old_release.path.is_dir())
        self.assertTrue(result.installed_path.is_dir())
        self.assertEqual(self.config.read_text(encoding="utf-8"), '{"fixture":"preserve"}\n')

    async def test_health_failure_restores_old_pointer_and_restarts_old_release(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["health:v1.8.0"] = {"ok": False}
        new_source = self._source("new-source", "new executable")

        with self.assertRaises(GatewayDeploymentError) as caught:
            await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_health_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(
            callbacks.events,
            [
                "drain",
                "stop",
                "start:v1.8.0",
                "health:v1.8.0",
                "stop",
                "start:v1.7.0",
                "health:v1.7.0",
            ],
        )
        self.assertEqual(self.store.load_pointer(), self.old_pointer)
        self.assertTrue(self.layout.release_path("v1.7.0").is_dir())
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())
        self.assertTrue(self.config.is_file())

    async def test_start_failure_restores_old_pointer_and_keeps_both_versions(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["start:v1.8.0"] = RuntimeError("fixture new start failure")
        new_source = self._source("new-source", "new executable")

        with self.assertRaises(GatewayDeploymentError) as caught:
            await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_start_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer(), self.old_pointer)
        self.assertTrue(self.layout.release_path("v1.7.0").is_dir())
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())

    async def test_recovery_stop_failure_keeps_new_pointer_and_never_starts_old_release(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["health:v1.8.0"] = False
        stop_calls = 0

        async def stop():
            nonlocal stop_calls
            stop_calls += 1
            callbacks.events.append("stop")
            return {"ok": stop_calls == 1}

        new_source = self._source("new-source", "new executable")
        manager = GatewayDeploymentManager(
            self.store,
            drain=callbacks.drain,
            stop=stop,
            start=callbacks.start,
            verify_health=callbacks.health,
        )

        with self.assertRaises(GatewayDeploymentError) as caught:
            await manager.upgrade("v1.8.0", new_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_health_failed")
        self.assertFalse(caught.exception.recovered)
        self.assertEqual(
            callbacks.events,
            ["drain", "stop", "start:v1.8.0", "health:v1.8.0", "stop"],
        )
        self.assertEqual(self.store.load_pointer().version, "v1.8.0")
        self.assertNotIn("start:v1.7.0", callbacks.events)

    async def test_drain_failure_leaves_old_process_and_pointer_untouched(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["drain"] = False
        new_source = self._source("new-source", "new executable")

        with self.assertRaises(GatewayDeploymentError) as caught:
            await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_drain_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(callbacks.events, ["drain"])
        self.assertEqual(self.store.load_pointer(), self.old_pointer)
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())

    async def test_ambiguous_stop_failure_does_not_duplicate_healthy_old_release(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["stop"] = {"ok": False}
        new_source = self._source("new-source", "new executable")

        with self.assertRaises(GatewayDeploymentError) as caught:
            await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_stop_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(callbacks.events, ["drain", "stop", "health:v1.7.0"])
        self.assertEqual(self.store.load_pointer(), self.old_pointer)

    async def test_ambiguous_stop_failure_restarts_old_release_only_when_unhealthy(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["stop"] = {"ok": False}
        health_calls = 0

        async def health(release):
            nonlocal health_calls
            event = f"health:{release.version}"
            callbacks.events.append(event)
            health_calls += 1
            return {"ok": health_calls > 1}

        new_source = self._source("new-source", "new executable")
        manager = GatewayDeploymentManager(
            self.store,
            drain=callbacks.drain,
            stop=callbacks.stop,
            start=callbacks.start,
            verify_health=health,
        )

        with self.assertRaises(GatewayDeploymentError) as caught:
            await manager.upgrade("v1.8.0", new_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_stop_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(
            callbacks.events,
            ["drain", "stop", "health:v1.7.0", "start:v1.7.0", "health:v1.7.0"],
        )
        self.assertEqual(self.store.load_pointer(), self.old_pointer)

    async def test_failed_recovery_is_reported_without_deleting_versions_or_config(self) -> None:
        callbacks = CallbackRecorder()
        callbacks.failures["health:v1.8.0"] = False
        callbacks.failures["start:v1.7.0"] = False
        new_source = self._source("new-source", "new executable")

        with self.assertRaises(GatewayDeploymentError) as caught:
            await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertFalse(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer(), self.old_pointer)
        self.assertTrue(self.layout.release_path("v1.7.0").is_dir())
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())
        self.assertEqual(self.config.read_text(encoding="utf-8"), '{"fixture":"preserve"}\n')

    async def test_pointer_replace_failure_keeps_old_active_and_new_installed(self) -> None:
        callbacks = CallbackRecorder()
        new_source = self._source("new-source", "new executable")
        original_replace = os.replace

        def fail_pointer(source, target):
            if Path(target) == self.layout.current_pointer:
                raise OSError("fixture pointer failure")
            return original_replace(source, target)

        with patch("gateway.platforms.windows.os.replace", side_effect=fail_pointer):
            with self.assertRaises(GatewayDeploymentError) as caught:
                await self._manager(callbacks).upgrade("v1.8.0", new_source)

        self.assertTrue(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer(), self.old_pointer)
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())
        self.assertTrue(self.config.is_file())

    def test_manifest_schema_hash_and_content_are_strictly_validated(self) -> None:
        scenarios = ("schema", "manifest_hash", "content_hash")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                source = self._source(f"source-{scenario}", scenario)
                version = {
                    "schema": "v1.8.0",
                    "manifest_hash": "v1.8.1",
                    "content_hash": "v1.8.2",
                }[scenario]
                release = self.store.install(version, source)
                if scenario == "schema":
                    manifest = json.loads((release.path / "manifest.json").read_text(encoding="utf-8"))
                    manifest["schema_version"] = 2
                    (release.path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                    expected = "manifest_invalid"
                elif scenario == "manifest_hash":
                    pointer_document = self.old_pointer.as_document()
                    pointer_document["manifest_sha256"] = "0" * 64
                    self.layout.current_pointer.write_text(json.dumps(pointer_document), encoding="utf-8")
                    expected = "pointer_manifest_mismatch"
                else:
                    (release.path / "GuardianGateway.exe").write_text("tampered", encoding="utf-8")
                    expected = "content_hash_mismatch"
                with self.assertRaisesRegex(ReleaseError, expected):
                    if scenario == "manifest_hash":
                        self.store.load_pointer()
                    else:
                        self.store.inspect(version)
                self.store.restore_pointer(self.old_pointer)

    async def test_install_rejects_preexisting_version_without_lifecycle_callbacks(self) -> None:
        callbacks = CallbackRecorder()
        duplicate_source = self._source("duplicate-source", "duplicate")

        with self.assertRaises(GatewayDeploymentError) as caught:
            await self._manager(callbacks).upgrade("v1.7.0", duplicate_source)

        self.assertEqual(caught.exception.code, "gateway_upgrade_install_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(callbacks.events, [])
        self.assertEqual(self.store.load_pointer(), self.old_pointer)


if __name__ == "__main__":
    unittest.main()
