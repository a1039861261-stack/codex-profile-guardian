from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway.platforms.linux import LinuxGatewayLayout
from gateway.platforms.linux_deployment import (
    LinuxDeploymentBundle,
    LinuxDeploymentError,
    LinuxDeploymentPlan,
    LinuxGatewayDeploymentManager,
    LinuxReleaseError,
    LinuxVersionedReleaseStore,
)


class CallbackRecorder:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.failures: dict[str, object] = {}

    async def stop(self, release):
        return self._record(f"stop:{release.version}")

    async def drain(self, release):
        return self._record(f"drain:{release.version}")

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


class LinuxGatewayDeploymentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.layout = LinuxGatewayLayout(self.root / "home")
        self.transaction = 0
        self.store = LinuxVersionedReleaseStore(
            self.layout,
            transaction_id_factory=self._transaction_id,
        )
        self.unit = (
            self.layout.home
            / ".config"
            / "systemd"
            / "user"
            / "codex-profile-guardian-gateway.service"
        )

    def _transaction_id(self) -> str:
        self.transaction += 1
        return f"fixturetx{self.transaction:04d}"

    def _source(self, name: str, marker: str) -> Path:
        source = self.root / name
        (source / "bin").mkdir(parents=True)
        (source / "bin" / "guardian-gateway").write_text(marker, encoding="utf-8")
        (source / "bin" / "guardian-gateway-supervisor").write_text(
            f"supervisor-{marker}",
            encoding="utf-8",
        )
        (source / "lib").mkdir()
        (source / "lib" / "runtime.py").write_text(f"MARKER = {marker!r}\n", encoding="utf-8")
        return source

    @staticmethod
    def _bundle(
        revision: int,
        secret: str,
        *,
        version: str = "v1.7.0",
    ) -> LinuxDeploymentBundle:
        route_common = {"adapter_name": "openai-responses-v1", "enabled": True}
        return LinuxDeploymentBundle(
            config={
                "schema_version": 1,
                "instance_id": "linux-fixture-instance",
                "gateway_version": version,
                "listen": {
                    "host": "127.0.0.1",
                    "data_port": 43117,
                    "control_port": 43118,
                },
                "limits": {
                    "max_request_bytes": 1024 * 1024,
                    "max_response_bytes": 1024 * 1024,
                    "read_chunk_bytes": 4096,
                    "max_concurrent_requests": 4,
                    "connect_timeout_seconds": 1,
                    "first_byte_timeout_seconds": 1,
                    "idle_timeout_seconds": 2,
                    "total_timeout_seconds": 5,
                },
                "lifecycle": {
                    "minimum_free_bytes": 1024 * 1024,
                    "drain_timeout_seconds": 2,
                },
                "active_group": {
                    "revision": revision,
                    "group_id": "linux-fixture-group",
                    "primary": {
                        **route_common,
                        "profile_id": "primary",
                        "base_url": "https://primary.fixture.invalid/v1",
                        "secret_ref": f"profile:primary:r{revision}",
                        "secret_suffix": "P1",
                    },
                    "backup": {
                        **route_common,
                        "profile_id": "backup",
                        "base_url": "https://backup.fixture.invalid/v1",
                        "secret_ref": f"profile:backup:r{revision}",
                        "secret_suffix": "P2",
                    },
                    "allowed_models": ["fixture-model"],
                    "breaker_policy": {
                        "failure_threshold": 1,
                        "protocol_failure_threshold": 1,
                        "error_rate_threshold": None,
                        "minimum_samples": 1,
                        "window_size": 8,
                        "recovery_success_threshold": 1,
                        "base_cooldown_seconds": 30,
                        "max_cooldown_seconds": 300,
                        "jitter_ratio": 0,
                    },
                    "probe_policy": {
                        "enabled": False,
                        "mode": "models",
                        "interval_seconds": 30,
                        "timeout_seconds": 1,
                        "allow_billable": False,
                        "allow_action_required_auto_retest": False,
                    },
                    "state_compatibility": {},
                },
            },
            secrets={
                f"primary.r{revision}": secret,
                f"backup.r{revision}": secret + "-backup",
            },
        )

    @staticmethod
    def _plan() -> LinuxDeploymentPlan:
        return LinuxDeploymentPlan(
            architecture="x86_64",
            package_mode="locked_venv",
            supervisor="systemd_user",
        )

    def _manager(self, callbacks: CallbackRecorder) -> LinuxGatewayDeploymentManager:
        return LinuxGatewayDeploymentManager(
            self.store,
            unit_path=self.unit,
            drain=callbacks.drain,
            stop=callbacks.stop,
            start=callbacks.start,
            verify_health=callbacks.health,
        )

    def test_release_manifest_pointer_and_content_are_strict(self) -> None:
        source = self._source("release", "v1")
        release = self.store.install("v1.7.0", source, architecture="x86_64")
        self.assertEqual(release.version, "v1.7.0")
        self.assertEqual(release.architecture, "x86_64")
        manifest = json.loads((release.path / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["entrypoint"], "bin/guardian-gateway")
        self.assertEqual({item["mode"] for item in manifest["files"]}, {0o600, 0o700})
        modes = {item["path"]: item["mode"] for item in manifest["files"]}
        self.assertEqual(modes["bin/guardian-gateway-supervisor"], 0o700)
        self.assertEqual(modes["lib/runtime.py"], 0o600)
        pointer = self.store.activate("v1.7.0")
        self.assertEqual(pointer.relative_path, "versions/v1.7.0")
        self.assertEqual(self.store.load_pointer(), pointer)
        (release.path / "lib" / "runtime.py").write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(LinuxReleaseError, "linux_release_content_mismatch"):
            self.store.inspect("v1.7.0")

    def test_release_rejects_links_limits_and_missing_entrypoint(self) -> None:
        source = self._source("linked", "v1")
        if hasattr(os, "symlink"):
            try:
                os.symlink(source / "lib" / "runtime.py", source / "link.py")
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(LinuxReleaseError, "linux_release_link_forbidden"):
                    self.store.install("v1.7.0", source, architecture="x86_64")
                (source / "link.py").unlink()
        (source / "bin" / "guardian-gateway").unlink()
        with self.assertRaisesRegex(LinuxReleaseError, "linux_release_entrypoint_missing"):
            self.store.install("v1.7.1", source, architecture="x86_64")

    async def test_successful_deploy_activates_release_config_unit_and_secret(self) -> None:
        callbacks = CallbackRecorder()
        source = self._source("new", "v1")
        result = await self._manager(callbacks).deploy(
            "v1.7.0",
            source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-secret-v1"),
            plan=self._plan(),
        )
        self.assertEqual(result.previous_version, None)
        self.assertEqual(result.active_version, "v1.7.0")
        self.assertEqual(callbacks.events, ["start:v1.7.0", "health:v1.7.0"])
        self.assertEqual(self.store.load_pointer().version, "v1.7.0")
        self.assertEqual(
            json.loads((self.layout.config / "active.json").read_text(encoding="utf-8"))[
                "active_group"
            ]["revision"],
            1,
        )
        self.assertEqual(
            (self.layout.secrets / "primary.r1.key").read_text(encoding="utf-8"),
            "fixture-secret-v1",
        )
        unit = self.unit.read_text(encoding="utf-8")
        self.assertIn("v1.7.0", unit)
        self.assertNotIn("fixture-secret-v1", unit)
        self.assertNotIn("--token", unit)

    async def test_health_failure_restores_pointer_config_secret_and_unit(self) -> None:
        callbacks = CallbackRecorder()
        old_source = self._source("old", "old")
        await self._manager(callbacks).deploy(
            "v1.7.0",
            old_source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-secret-old"),
            plan=self._plan(),
        )
        old_pointer = self.store.load_pointer()
        old_config = (self.layout.config / "active.json").read_bytes()
        old_secret = (self.layout.secrets / "primary.r1.key").read_bytes()
        old_unit = self.unit.read_bytes()
        callbacks.events.clear()
        callbacks.failures["health:v1.8.0"] = {"ok": False}
        new_source = self._source("new", "new")

        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.8.0",
                new_source,
                architecture="x86_64",
                bundle=self._bundle(2, "fixture-secret-new", version="v1.8.0"),
                plan=self._plan(),
            )

        self.assertEqual(caught.exception.code, "linux_deployment_health_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer(), old_pointer)
        self.assertEqual((self.layout.config / "active.json").read_bytes(), old_config)
        self.assertEqual((self.layout.secrets / "primary.r1.key").read_bytes(), old_secret)
        self.assertFalse((self.layout.secrets / "primary.r2.key").exists())
        self.assertEqual(self.unit.read_bytes(), old_unit)
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())
        self.assertEqual(
            callbacks.events,
            [
                "drain:v1.7.0",
                "stop:v1.7.0",
                "start:v1.8.0",
                "health:v1.8.0",
                "stop:v1.8.0",
                "start:v1.7.0",
                "health:v1.7.0",
            ],
        )
        backup_candidates = [
            path
            for path in self.layout.home.rglob("*")
            if path.suffix in {".bak", ".backup", ".rollback"}
            or ".rollback." in path.name.lower()
        ]
        self.assertEqual(backup_candidates, [])

    async def test_invalid_or_mismatched_plan_stops_before_install_or_callbacks(self) -> None:
        callbacks = CallbackRecorder()
        source = self._source("new", "new")
        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.7.0",
                source,
                architecture="x86_64",
                bundle=self._bundle(1, "fixture-secret"),
                plan=None,
            )
        self.assertEqual(caught.exception.code, "linux_deployment_plan_invalid")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(callbacks.events, [])
        self.assertFalse(self.layout.release_path("v1.7.0").exists())

        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.7.0",
                source,
                architecture="aarch64",
                bundle=self._bundle(1, "fixture-secret"),
                plan=self._plan(),
            )
        self.assertEqual(caught.exception.code, "linux_deployment_architecture_mismatch")
        self.assertFalse(self.layout.release_path("v1.7.0").exists())

    async def test_recovery_stop_failure_reports_uncertain_without_false_rollback(self) -> None:
        callbacks = CallbackRecorder()
        old_source = self._source("old", "old")
        await self._manager(callbacks).deploy(
            "v1.7.0",
            old_source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-old"),
            plan=self._plan(),
        )
        callbacks.events.clear()
        callbacks.failures["health:v1.8.0"] = False
        callbacks.failures["stop:v1.8.0"] = False
        new_source = self._source("new", "new")
        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.8.0",
                new_source,
                architecture="x86_64",
                bundle=self._bundle(2, "fixture-new", version="v1.8.0"),
                plan=self._plan(),
            )
        self.assertFalse(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer().version, "v1.8.0")
        self.assertNotIn("start:v1.7.0", callbacks.events)
        lock = self._manager(callbacks).state_uncertain_path
        self.assertEqual(
            set(json.loads(lock.read_text(encoding="utf-8"))),
            {"schema_version", "error_code", "recorded_at"},
        )
        with self.assertRaises(LinuxDeploymentError) as locked:
            await self._manager(callbacks).deploy(
                "v1.9.0",
                self._source("later", "later"),
                architecture="x86_64",
                bundle=self._bundle(3, "fixture-later"),
                plan=self._plan(),
            )
        self.assertEqual(locked.exception.code, "linux_deployment_state_uncertain_locked")

    async def test_install_failure_is_wrapped_before_callbacks(self) -> None:
        callbacks = CallbackRecorder()
        source = self._source("new", "new")
        await self._manager(callbacks).deploy(
            "v1.7.0",
            source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-secret"),
            plan=self._plan(),
        )
        callbacks.events.clear()
        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.7.0",
                source,
                architecture="x86_64",
                bundle=self._bundle(2, "fixture-secret-new"),
                plan=self._plan(),
            )
        self.assertEqual(
            caught.exception.code,
            "linux_deployment_prepare_failed",
        )
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(callbacks.events, [])

    async def test_unit_write_failure_restores_old_state_before_new_start(self) -> None:
        callbacks = CallbackRecorder()
        old_source = self._source("old", "old")
        await self._manager(callbacks).deploy(
            "v1.7.0",
            old_source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-old"),
            plan=self._plan(),
        )
        old_pointer = self.store.load_pointer()
        old_config = (self.layout.config / "active.json").read_bytes()
        old_unit = self.unit.read_bytes()
        callbacks.events.clear()
        new_source = self._source("new", "new")

        from gateway.platforms import linux_deployment

        original = linux_deployment._atomic_write
        unit_failures = 0

        def fail_unit(path, content, *, mode):
            nonlocal unit_failures
            if Path(path) == self.unit and unit_failures == 0:
                unit_failures += 1
                raise OSError("fixture unit write failure")
            return original(path, content, mode=mode)

        with patch("gateway.platforms.linux_deployment._atomic_write", side_effect=fail_unit):
            with self.assertRaises(LinuxDeploymentError) as caught:
                await self._manager(callbacks).deploy(
                    "v1.8.0",
                    new_source,
                    architecture="x86_64",
                    bundle=self._bundle(2, "fixture-new", version="v1.8.0"),
                    plan=self._plan(),
                )
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer(), old_pointer)
        self.assertEqual((self.layout.config / "active.json").read_bytes(), old_config)
        self.assertEqual(self.unit.read_bytes(), old_unit)
        self.assertFalse((self.layout.secrets / "primary.r2.key").exists())
        self.assertEqual(
            callbacks.events,
            [
                "drain:v1.7.0",
                "stop:v1.7.0",
                "start:v1.7.0",
                "health:v1.7.0",
            ],
        )

    async def test_start_failure_restores_old_state_and_both_versions(self) -> None:
        callbacks = CallbackRecorder()
        old_source = self._source("old", "old")
        await self._manager(callbacks).deploy(
            "v1.7.0",
            old_source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-old"),
            plan=self._plan(),
        )
        old_pointer = self.store.load_pointer()
        callbacks.events.clear()
        callbacks.failures["start:v1.8.0"] = RuntimeError("fixture start failure")
        new_source = self._source("new", "new")
        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.8.0",
                new_source,
                architecture="x86_64",
                bundle=self._bundle(2, "fixture-new", version="v1.8.0"),
                plan=self._plan(),
            )
        self.assertEqual(caught.exception.code, "linux_deployment_start_failed")
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer(), old_pointer)
        self.assertTrue(self.layout.release_path("v1.7.0").is_dir())
        self.assertTrue(self.layout.release_path("v1.8.0").is_dir())
        self.assertEqual(
            callbacks.events,
            [
                "drain:v1.7.0",
                "stop:v1.7.0",
                "start:v1.8.0",
                "stop:v1.8.0",
                "start:v1.7.0",
                "health:v1.7.0",
            ],
        )

    async def test_recovery_start_failure_is_reported_without_false_success(self) -> None:
        callbacks = CallbackRecorder()
        old_source = self._source("old", "old")
        await self._manager(callbacks).deploy(
            "v1.7.0",
            old_source,
            architecture="x86_64",
            bundle=self._bundle(1, "fixture-old"),
            plan=self._plan(),
        )
        callbacks.events.clear()
        callbacks.failures["health:v1.8.0"] = False
        callbacks.failures["start:v1.7.0"] = False
        new_source = self._source("new", "new")
        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.8.0",
                new_source,
                architecture="x86_64",
                bundle=self._bundle(2, "fixture-new", version="v1.8.0"),
                plan=self._plan(),
            )
        self.assertFalse(caught.exception.recovered)
        self.assertEqual(self.store.load_pointer().version, "v1.7.0")
        self.assertIn("start:v1.7.0", callbacks.events)
        self.assertTrue(self._manager(callbacks).state_uncertain_path.is_file())

    async def test_secret_target_symlink_stops_before_service_mutation(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        self.layout.ensure_private_directories()
        outside = self.root / "outside-secret"
        outside.write_text("outside-preserve", encoding="utf-8")
        target = self.layout.secrets / "primary.r1.key"
        try:
            os.symlink(outside, target)
        except OSError:
            self.skipTest("symlink creation unavailable")
        callbacks = CallbackRecorder()
        source = self._source("new", "new")
        with self.assertRaises(LinuxDeploymentError) as caught:
            await self._manager(callbacks).deploy(
                "v1.7.0",
                source,
                architecture="x86_64",
                bundle=self._bundle(1, "fixture-secret"),
                plan=self._plan(),
            )
        self.assertEqual(
            caught.exception.code,
            "linux_deployment_target_link_forbidden",
        )
        self.assertTrue(caught.exception.recovered)
        self.assertEqual(callbacks.events, [])
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside-preserve")


if __name__ == "__main__":
    unittest.main()
