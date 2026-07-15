from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from gateway.platforms.windows import VersionedReleaseStore, WindowsGatewayLayout


class ReleaseInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = Path(__file__).resolve().parents[1]
        self.version = (self.project / "VERSION").read_text(encoding="utf-8").strip()
        self.release_version = f"v{self.version}"
        self.staging = self.root / "staging"
        self.staging.mkdir()
        for name in ("install.ps1", "uninstall.ps1"):
            shutil.copy2(self.project / "installer" / name, self.staging / name)
        shutil.copy2(self.project / "LICENSE", self.staging / "LICENSE")
        shutil.copy2(self.project / "VERSION", self.staging / "VERSION")
        (self.staging / "README-CN.md").write_text("fixture\n", encoding="utf-8")
        for name in (
            "CodexProfileGuardian.exe",
            "CodexProfileGuardianSecret.exe",
            "GuardianGateway.exe",
            "GuardianGatewaySupervisor.exe",
        ):
            (self.staging / name).write_bytes((name + "\n").encode("ascii"))
        self.install_base = self.root / "install" / "Codex Profile Guardian"
        self.start_menu = self.root / "start-menu"
        self.desktop = self.root / "desktop"
        self.desktop.mkdir()
        self.shortcut = self.desktop / "Codex Profile Guardian.lnk"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                *arguments,
            ],
            cwd=self.staging,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    def _isolated_install_arguments(self) -> tuple[str, ...]:
        return (
            "-NoLaunch",
            "-SkipRegistry",
            "-SkipScheduledTask",
            "-InstallBase",
            str(self.install_base),
            "-StartMenuDir",
            str(self.start_menu),
            "-DesktopShortcut",
            str(self.shortcut),
        )

    def test_isolated_install_and_uninstall_preserve_guardian_data(self) -> None:
        installed = self._run(
            self.staging / "install.ps1",
            *self._isolated_install_arguments(),
        )
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)

        layout = WindowsGatewayLayout(self.install_base)
        store = VersionedReleaseStore(layout)
        pointer = store.load_pointer()
        self.assertIsNotNone(pointer)
        self.assertEqual(pointer.version, self.release_version)
        release = store.inspect(self.release_version)
        self.assertTrue((release.path / "GuardianGateway.exe").is_file())
        self.assertTrue((release.path / "GuardianGatewaySupervisor.exe").is_file())

        config_path = layout.config / "active.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(config["gateway_version"], self.release_version)
        self.assertEqual(config["listen"], {"host": "127.0.0.1", "data_port": 18766, "control_port": 18767})
        self.assertFalse(config["active_group"]["primary"]["enabled"])
        self.assertFalse(config["active_group"]["backup"]["enabled"])
        self.assertTrue(self.shortcut.is_file())
        self.assertTrue((self.start_menu / "Codex Profile Guardian.lnk").is_file())

        retained = self.install_base / "profiles.json"
        retained.write_text('{"fixture":true}\n', encoding="utf-8")
        uninstall = self.install_base / "app" / self.release_version / "uninstall.ps1"
        removed = self._run(
            uninstall,
            "-Quiet",
            "-SkipRegistry",
            "-SkipScheduledTask",
            "-StartMenuDir",
            str(self.start_menu),
            "-DesktopShortcut",
            str(self.shortcut),
        )
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertTrue(retained.is_file())
        self.assertTrue(config_path.is_file())
        self.assertFalse((self.install_base / "app").exists())
        self.assertFalse(layout.versions.exists())
        self.assertFalse(layout.current_pointer.exists())
        self.assertFalse(self.shortcut.exists())

    def test_upgrade_from_legacy_layout_keeps_old_version_and_user_data(self) -> None:
        legacy = self.install_base / "app" / "v1.6.2"
        legacy.mkdir(parents=True)
        legacy_main = legacy / "CodexProfileGuardian.exe"
        legacy_main.write_bytes(b"stable-v1.6.2\n")
        retained = self.install_base / "profiles.json"
        retained.write_text('{"fixture":"legacy"}\n', encoding="utf-8")

        installed = self._run(
            self.staging / "install.ps1",
            *self._isolated_install_arguments(),
        )
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.assertEqual(legacy_main.read_bytes(), b"stable-v1.6.2\n")
        self.assertEqual(retained.read_text(encoding="utf-8"), '{"fixture":"legacy"}\n')
        self.assertTrue((self.install_base / "app" / self.release_version / "CodexProfileGuardian.exe").is_file())
        pointer = VersionedReleaseStore(WindowsGatewayLayout(self.install_base)).load_pointer()
        self.assertIsNotNone(pointer)
        self.assertEqual(pointer.version, self.release_version)

    def test_upgrade_updates_existing_gateway_config_version_only(self) -> None:
        config_path = self.install_base / "gateway" / "config" / "active.json"
        config_path.parent.mkdir(parents=True)
        supervisor_path = self.install_base / "gateway" / "state" / "supervisor.json"
        supervisor_path.parent.mkdir(parents=True)
        supervisor_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "crash_times": [1.0, 2.0, 3.0, 4.0],
                    "last_observed_at": 4.0,
                    "safe_stop_reason": "crash_loop",
                }
            ),
            encoding="utf-8",
        )
        existing = {
            "schema_version": 1,
            "gateway_version": "v1.7.0",
            "listen": {"host": "127.0.0.1", "data_port": 18766, "control_port": 18767},
            "fixture_unknown": {"preserved": True},
        }
        config_path.write_text(json.dumps(existing), encoding="utf-8")

        installed = self._run(
            self.staging / "install.ps1",
            *self._isolated_install_arguments(),
        )
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        updated = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(updated["gateway_version"], self.release_version)
        self.assertEqual(updated["listen"], existing["listen"])
        self.assertEqual(updated["fixture_unknown"], existing["fixture_unknown"])
        self.assertFalse(supervisor_path.exists())

    def test_injected_upgrade_failure_restores_release_pointer_and_shortcuts(self) -> None:
        first = self._run(
            self.staging / "install.ps1",
            *self._isolated_install_arguments(),
        )
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        layout = WindowsGatewayLayout(self.install_base)
        app_main = self.install_base / "app" / self.release_version / "CodexProfileGuardian.exe"
        gateway_main = layout.versions / self.release_version / "GuardianGateway.exe"
        before = {
            "app": app_main.read_bytes(),
            "gateway": gateway_main.read_bytes(),
            "pointer": layout.current_pointer.read_bytes(),
            "desktop": self.shortcut.read_bytes(),
            "start": (self.start_menu / "Codex Profile Guardian.lnk").read_bytes(),
        }
        retained = self.install_base / "profiles.json"
        retained.write_text('{"fixture":"keep"}\n', encoding="utf-8")
        config_path = layout.config / "active.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["gateway_version"] = "v1.7.0"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        before["config"] = config_path.read_bytes()
        supervisor_path = layout.state / "supervisor.json"
        supervisor_path.parent.mkdir(parents=True, exist_ok=True)
        supervisor_path.write_text(
            '{"schema_version":1,"crash_times":[],"last_observed_at":null,'
            '"safe_stop_reason":"crash_loop"}\n',
            encoding="utf-8",
        )
        before["supervisor"] = supervisor_path.read_bytes()
        for name in (
            "CodexProfileGuardian.exe",
            "CodexProfileGuardianSecret.exe",
            "GuardianGateway.exe",
            "GuardianGatewaySupervisor.exe",
        ):
            (self.staging / name).write_bytes(("replacement-" + name + "\n").encode("ascii"))

        failed = self._run(
            self.staging / "install.ps1",
            *self._isolated_install_arguments(),
            "-TestFailStage",
            "after_pointer",
        )
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertEqual(app_main.read_bytes(), before["app"])
        self.assertEqual(gateway_main.read_bytes(), before["gateway"])
        self.assertEqual(layout.current_pointer.read_bytes(), before["pointer"])
        self.assertEqual(self.shortcut.read_bytes(), before["desktop"])
        self.assertEqual(
            (self.start_menu / "Codex Profile Guardian.lnk").read_bytes(), before["start"]
        )
        self.assertEqual(config_path.read_bytes(), before["config"])
        self.assertEqual(supervisor_path.read_bytes(), before["supervisor"])
        self.assertEqual(retained.read_text(encoding="utf-8"), '{"fixture":"keep"}\n')
        transactions = self.install_base / "transactions"
        self.assertFalse(transactions.exists() and any(transactions.iterdir()))

    def test_scheduled_task_calls_use_nonthrowing_exit_code_wrapper(self) -> None:
        source = (self.project / "installer" / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("function Invoke-ScheduledTaskCommand", source)
        self.assertIn('Arguments @("/Query", "/TN", $TaskName, "/XML")', source)
        self.assertIn("function Wait-GatewayStartup", source)
        self.assertIn("[string]$Runtime.version -eq $GatewayVersion", source)
        self.assertNotIn("[string]$Runtime.gateway_version", source)
        self.assertNotIn("& schtasks.exe /Query", source)
        self.assertNotIn("& schtasks.exe /End", source)
        self.assertNotIn("& schtasks.exe /Delete", source)

    def test_uninstall_drains_gateway_before_deleting_task_and_files(self) -> None:
        source = (self.project / "installer" / "uninstall.ps1").read_text(encoding="utf-8")
        self.assertIn("function Stop-InstalledGateway", source)
        self.assertIn("/control/v1/drain", source)
        self.assertIn("/control/v1/stop", source)
        self.assertLess(source.index("Stop-InstalledGateway\n"), source.index('Arguments @("/Delete"'))
        self.assertNotIn("& schtasks.exe /End", source)
        self.assertNotIn("& schtasks.exe /Delete", source)


if __name__ == "__main__":
    unittest.main()
