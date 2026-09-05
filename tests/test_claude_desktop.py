from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from backend.claude_desktop import (
    GUARDIAN_PROFILE_ID,
    ClaudeDesktopError,
    ClaudeDesktopIntegration,
)


SECRET_CANARY = "CLAUDE-DESKTOP-SECRET-CANARY"


class ClaudeDesktopIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        # Windows hosted runners may expose TEMP through an 8.3 path alias.
        self.root = Path(self.temporary.name).resolve()
        self.local_appdata = self.root / "local"
        self.cc_switch_home = self.root / "cc-switch"
        self.integration = ClaudeDesktopIntegration(
            local_appdata=self.local_appdata,
            data_dir=self.root / "guardian" / "claude",
            cc_switch_home=self.cc_switch_home,
            protect=lambda payload: b"protected:" + payload,
            unprotect=lambda payload: payload.removeprefix(b"protected:"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_json(path: Path, value: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def _create_profile(self) -> dict[str, object]:
        return self.integration.create_profile(
            "Fixture Claude",
            "https://anthropic.example.test/v1",
            SECRET_CANARY,
            [
                {"name": "claude-fable-5", "label": "Fable 5"},
                {"name": "claude-sonnet-5", "supports_1m": True},
            ],
        )

    def test_profile_store_encrypts_secret_and_public_status_is_redacted(self) -> None:
        profile = self._create_profile()
        self.assertEqual(profile["secret_hint"], "NARY")
        self.assertNotIn(SECRET_CANARY, self.integration.store_path.read_text(encoding="utf-8"))
        protected = next(self.integration.secrets_dir.glob("*.dpapi")).read_bytes()
        self.assertTrue(protected.startswith(b"protected:"))
        self.assertIn(SECRET_CANARY.encode(), protected)
        if os.name == "nt":
            acl = subprocess.run(
                ["icacls.exe", str(next(self.integration.secrets_dir.glob("*.dpapi")))],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            ).stdout
            self.assertNotIn("CodexSandboxUsers", acl)

        serialized = json.dumps(self.integration.status(), ensure_ascii=False)
        self.assertNotIn(SECRET_CANARY, serialized)
        self.assertIn("Fixture Claude", serialized)

    def test_apply_writes_guardian_owned_profile_and_encrypted_rollback(self) -> None:
        self._write_json(self.integration.normal_config_path, {"deploymentMode": "1p", "keep": True})
        self._write_json(self.integration.threep_config_path, {"deploymentMode": "1p", "preferences": {"keep": True}})
        profile = self._create_profile()

        result = self.integration.apply_profile(profile["id"], confirmed=True)

        self.assertTrue(result["applied"])
        self.assertTrue(result["restart_required"])
        normal = json.loads(self.integration.normal_config_path.read_text(encoding="utf-8"))
        threep = json.loads(self.integration.threep_config_path.read_text(encoding="utf-8"))
        deployed = json.loads(self.integration.profile_path.read_text(encoding="utf-8"))
        meta = json.loads(self.integration.meta_path.read_text(encoding="utf-8"))
        self.assertEqual(normal, {"deploymentMode": "3p", "keep": True})
        self.assertEqual(threep["deploymentMode"], "3p")
        self.assertEqual(threep["preferences"], {"keep": True})
        self.assertEqual(deployed["inferenceGatewayBaseUrl"], "https://anthropic.example.test/v1")
        self.assertEqual(deployed["inferenceGatewayApiKey"], SECRET_CANARY)
        self.assertEqual(deployed["inferenceGatewayAuthScheme"], "bearer")
        self.assertEqual(deployed["inferenceProvider"], "gateway")
        self.assertEqual(deployed["inferenceModels"][0]["name"], "claude-fable-5")
        self.assertEqual(meta["appliedId"], GUARDIAN_PROFILE_ID)
        backups = list(self.integration.backups_dir.glob("*.dpapi"))
        self.assertEqual(len(backups), 1)
        self.assertNotIn(SECRET_CANARY.encode(), backups[0].read_bytes())

        status = self.integration.status()
        self.assertEqual(status["state"], "ready")
        self.assertEqual(status["config_owner"], "guardian")
        self.assertEqual(status["credential_state"], "managed_by_guardian")
        self.assertEqual(status["current_profile"]["id"], profile["id"])

    def test_apply_failure_restores_every_claude_file(self) -> None:
        self._write_json(self.integration.normal_config_path, {"deploymentMode": "1p"})
        self._write_json(self.integration.threep_config_path, {"deploymentMode": "1p"})
        profile = self._create_profile()
        before = {
            path: path.read_bytes() if path.is_file() else None
            for path in self.integration._target_paths()
        }
        with patch("backend.claude_desktop._atomic_json", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                self.integration.apply_profile(profile["id"], confirmed=True)
        after = {
            path: path.read_bytes() if path.is_file() else None
            for path in self.integration._target_paths()
        }
        self.assertEqual(after, before)
        self.assertIsNone(self.integration._load_store()["current_profile"])

    def test_restore_official_preserves_other_config_and_removes_guardian_profile(self) -> None:
        self._write_json(self.integration.normal_config_path, {"deploymentMode": "1p", "keep": 1})
        self._write_json(self.integration.threep_config_path, {"deploymentMode": "1p", "preferences": {"keep": 2}})
        profile = self._create_profile()
        self.integration.apply_profile(profile["id"], confirmed=True)

        result = self.integration.restore_official(confirmed=True)

        self.assertTrue(result["restored"])
        self.assertFalse(self.integration.profile_path.exists())
        self.assertEqual(json.loads(self.integration.normal_config_path.read_text())["deploymentMode"], "1p")
        threep = json.loads(self.integration.threep_config_path.read_text())
        self.assertEqual(threep["deploymentMode"], "1p")
        self.assertEqual(threep["preferences"], {"keep": 2})
        self.assertEqual(self.integration.status()["state"], "official")

    def _write_cc_switch_fixture(self, *, api_format: str = "anthropic") -> None:
        self.cc_switch_home.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.integration.cc_switch_db_path)
        try:
            connection.execute(
                "CREATE TABLE providers ("
                "id TEXT, app_type TEXT, name TEXT, settings_config TEXT, meta TEXT, is_current INTEGER)"
            )
            connection.execute(
                "INSERT INTO providers VALUES (?, ?, ?, ?, ?, 1)",
                (
                    "fixture-provider",
                    "claude-desktop",
                    "Fixture CC Provider",
                    json.dumps(
                        {
                            "env": {
                                "ANTHROPIC_BASE_URL": "https://cc.example.test",
                                "ANTHROPIC_AUTH_TOKEN": SECRET_CANARY,
                            }
                        }
                    ),
                    json.dumps(
                        {
                            "apiFormat": api_format,
                            "claudeDesktopModelRoutes": {
                                "claude-sonnet-5": {
                                    "model": "claude-fable-5",
                                    "labelOverride": "Fable 5",
                                },
                                "claude-opus-4-8": {"model": "claude-fable-5"},
                            },
                        }
                    ),
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def test_one_time_cc_switch_import_becomes_guardian_owned_without_plaintext_store(self) -> None:
        self._write_cc_switch_fixture()
        migration = self.integration.migration_status()
        self.assertTrue(migration["available"])
        self.assertTrue(migration["compatible"])

        result = self.integration.import_cc_switch(confirmed=True)

        self.assertTrue(result["imported"])
        profile = result["profile"]
        self.assertEqual(profile["source"], "cc_switch_migration")
        self.assertEqual(profile["base_url"], "https://cc.example.test")
        self.assertEqual([item["name"] for item in profile["models"]], ["claude-fable-5"])
        self.assertNotIn(SECRET_CANARY, self.integration.store_path.read_text(encoding="utf-8"))

    def test_migration_probe_does_not_read_cc_switch_credentials(self) -> None:
        self._write_cc_switch_fixture()
        connection = sqlite3.connect(self.integration.cc_switch_db_path)
        try:
            connection.execute(
                "UPDATE providers SET settings_config = ? WHERE is_current = 1",
                ("not-json-and-must-not-be-read",),
            )
            connection.commit()
        finally:
            connection.close()

        migration = self.integration.migration_status()

        self.assertTrue(migration["available"])
        self.assertTrue(migration["compatible"])
        self.assertFalse(migration["credentials_checked"])

    def test_guardian_profiles_remove_cc_switch_from_daily_status_path(self) -> None:
        self._create_profile()
        with patch.object(
            self.integration,
            "_cc_switch_current",
            side_effect=AssertionError("CC Switch must not be read"),
        ):
            status = self.integration.status()

        self.assertEqual(status["migration"], {"available": False})

    def test_cc_switch_import_rejects_non_anthropic_format(self) -> None:
        self._write_cc_switch_fixture(api_format="openai_chat")
        self.assertFalse(self.integration.migration_status()["compatible"])
        with self.assertRaisesRegex(ClaudeDesktopError, "claude_cc_import_format_unsupported"):
            self.integration.import_cc_switch(confirmed=True)

    @patch("backend.claude_desktop.subprocess.Popen")
    @patch("backend.claude_desktop.subprocess.run")
    def test_restart_targets_only_anthropic_desktop_install(self, run, popen) -> None:
        update = self.local_appdata / "AnthropicClaude" / "Update.exe"
        update.parent.mkdir(parents=True)
        update.write_bytes(b"fixture")
        run.return_value.returncode = 0

        result = self.integration.restart_claude()

        self.assertEqual(result, {"restarted": True})
        powershell = run.call_args.args[0]
        self.assertIn(str(update.parent), powershell[-1])
        self.assertIn("StartsWith", powershell[-1])
        self.assertIn("$targets=@(", powershell[-1])
        self.assertIn("exit 0", powershell[-1])
        self.assertNotIn("taskkill", powershell[-1].lower())
        popen.assert_called_once_with(
            [str(update), "--processStart", "claude.exe"],
            cwd=str(update.parent),
            close_fds=True,
        )


if __name__ == "__main__":
    unittest.main()
