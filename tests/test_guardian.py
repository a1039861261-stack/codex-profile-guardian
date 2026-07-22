from __future__ import annotations

import json
import base64
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib import error as urlerror

from backend.guardian import (
    GuardianError,
    GuardianService,
    normalize_quota_response,
    quota_plan_label,
)
from backend.remote_sync import (
    _REMOTE_API_APPLY_SCRIPT,
    _REMOTE_APPLY_SCRIPT,
    _REMOTE_RECONCILE_SCRIPT,
    portable_config,
    sync_api_profile_to_remotes,
    sync_official_to_remotes,
)


def auth_payload(account: str, refresh: str, *, last_refresh: str = "2026-07-06T00:00:00Z") -> str:
    return json.dumps(
        {
            "OPENAI_API_KEY": None,
            "last_refresh": last_refresh,
            "tokens": {
                "account_id": account,
                "access_token": f"access-{account}-{refresh}",
                "refresh_token": refresh,
                "id_token": f"id-{account}",
            },
        }
    )


class GuardianServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.codex = root / ".codex"
        self.data = root / "guardian-data"
        (self.codex / "sessions" / "2026" / "07" / "06").mkdir(parents=True)
        (self.codex / "archived_sessions").mkdir(parents=True)
        (self.codex / "auth.json").write_text(auth_payload("account-a", "refresh-a"), encoding="utf-8")
        (self.codex / "config.toml").write_text(
            'model = "gpt-5.5"\nmodel_provider = "openai"\n', encoding="utf-8"
        )
        self.active_id = "019f330a-e611-70a2-8b98-74bcc83c5f7f"
        self.archived_id = "019e590d-c1d0-7442-b112-351c719a583f"
        self.active_path = self.codex / "sessions" / "2026" / "07" / "06" / f"rollout-{self.active_id}.jsonl"
        self.archived_path = self.codex / "archived_sessions" / f"rollout-{self.archived_id}.jsonl"
        for path, thread_id in [(self.active_path, self.active_id), (self.archived_path, self.archived_id)]:
            path.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": thread_id, "model_provider": "openai"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        db.execute(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, created_at TEXT, updated_at TEXT, "
            "source TEXT, model_provider TEXT, cwd TEXT, title TEXT, first_user_message TEXT, "
            "has_user_event INTEGER, archived INTEGER, created_at_ms INTEGER)"
        )
        db.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.active_id, str(self.active_path), "2026-07-06", "2026-07-06", "vscode", "openai", str(root), "Active", "Active", 1, 0, 1),
        )
        db.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.archived_id, str(self.archived_path), "2026-05-24", "2026-05-24", "vscode", "openai", str(root), "Archived", "Archived", 1, 1, 0),
        )
        db.commit()
        db.close()
        self.service = GuardianService(
            codex_home=self.codex,
            data_dir=self.data,
            helper_command=["guardian-test.exe"],
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_switch_preserves_shared_history_and_archive_flags(self) -> None:
        official = self.service.capture_official("Fixture Official")
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-test"
        )
        original_index = (
            json.dumps({"id": self.archived_id, "thread_name": "Visible Before", "updated_at": 10}, separators=(",", ":"))
            + "\n"
            + json.dumps({"id": self.active_id, "thread_name": "Active Before", "updated_at": 11}, separators=(",", ":"))
            + "\n"
        )
        (self.codex / "session_index.jsonl").write_text(original_index, encoding="utf-8")
        result = self.service.switch_profile(profile["id"])
        self.assertTrue(result["migration"]["archive_preserved"])
        self.assertTrue(result["migration"]["index_preserved"])
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        rows = list(db.execute("SELECT id, archived, model_provider FROM threads ORDER BY id"))
        db.close()
        self.assertEqual({row[0]: row[1] for row in rows}, {self.active_id: 0, self.archived_id: 1})
        self.assertEqual({row[2] for row in rows}, {profile["provider_id"]})
        self.assertIn(
            f'"model_provider":"{profile["provider_id"]}"',
            self.active_path.read_text(encoding="utf-8"),
        )
        self.assertIn(
            f'"model_provider":"{profile["provider_id"]}"',
            self.archived_path.read_text(encoding="utf-8"),
        )
        self.assertTrue(result["migration"]["shared_history_preserved"])
        self.assertEqual((self.codex / "session_index.jsonl").read_text(encoding="utf-8"), original_index)
        official_result = self.service.switch_profile(official["id"])
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        official_rows = list(db.execute("SELECT archived, model_provider FROM threads"))
        db.close()
        self.assertEqual({row[1] for row in official_rows}, {"openai"})
        self.assertEqual(sorted(row[0] for row in official_rows), [0, 1])
        self.assertTrue(official_result["migration"]["shared_history_preserved"])
        self.assertTrue(official_result["migration"]["index_preserved"])
        self.assertEqual((self.codex / "session_index.jsonl").read_text(encoding="utf-8"), original_index)
        self.assertEqual(len(self.service.list_backups()), 2)

    def test_repeated_account_and_api_switches_keep_one_local_chat_library(self) -> None:
        official = self.service.capture_official("Fixture Official")
        api = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-test"
        )
        index_path = self.codex / "session_index.jsonl"
        index_path.write_text(
            json.dumps({"id": self.active_id, "thread_name": "Shared"}) + "\n",
            encoding="utf-8",
        )
        original_index = index_path.read_bytes()
        protected_paths = sorted(
            path.relative_to(self.codex).as_posix()
            for path in self.codex.rglob("*")
            if path.is_file()
        )
        body_payloads = {
            path: path.read_bytes().split(b"\n", 1)[1]
            for path in (self.active_path, self.archived_path)
        }
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        original_threads = list(
            connection.execute(
                "SELECT id, rollout_path, archived FROM threads ORDER BY id"
            )
        )
        connection.close()

        for profile in (api, official, api):
            result = self.service.switch_profile(profile["id"])
            self.assertTrue(result["migration"]["shared_history_preserved"])
            self.assertTrue(result["migration"]["index_preserved"])
            self.assertEqual(index_path.read_bytes(), original_index)
            connection = sqlite3.connect(self.codex / "state_5.sqlite")
            current_threads = list(
                connection.execute(
                    "SELECT id, rollout_path, archived FROM threads ORDER BY id"
                )
            )
            providers = {
                row[0] for row in connection.execute("SELECT model_provider FROM threads")
            }
            connection.close()
            self.assertEqual(current_threads, original_threads)
            self.assertEqual(providers, {profile["provider_id"]})

        self.assertEqual(
            protected_paths,
            sorted(
                path.relative_to(self.codex).as_posix()
                for path in self.codex.rglob("*")
                if path.is_file()
            ),
        )
        for path, expected_body in body_payloads.items():
            self.assertEqual(path.read_bytes().split(b"\n", 1)[1], expected_body)
        for profile in (api, official):
            profile_root = self.data / "profiles" / profile["id"]
            self.assertFalse((profile_root / "sessions").exists())
            self.assertFalse((profile_root / "archived_sessions").exists())
            self.assertFalse((profile_root / "state_5.sqlite").exists())
            self.assertFalse((profile_root / "session_index.jsonl").exists())

    def test_switch_repairs_prior_half_switch_for_active_threads(self) -> None:
        official = self.service.capture_official("Fixture Official")
        stale_provider = "guardian_stale_api"
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        db.execute(
            "UPDATE threads SET model_provider=? WHERE archived=0",
            (stale_provider,),
        )
        db.commit()
        db.close()
        active_lines = self.active_path.read_text(encoding="utf-8").splitlines()
        active_meta = json.loads(active_lines[0])
        active_meta["payload"]["model_provider"] = stale_provider
        self.active_path.write_text(
            json.dumps(active_meta, separators=(",", ":")) + "\n" + "\n".join(active_lines[1:]),
            encoding="utf-8",
        )

        result = self.service.switch_profile(official["id"])

        db = sqlite3.connect(self.codex / "state_5.sqlite")
        rows = list(db.execute("SELECT archived, model_provider FROM threads ORDER BY archived"))
        db.close()
        self.assertEqual({provider for _, provider in rows}, {"openai"})
        self.assertEqual(result["migration"]["provider_mismatch_count"], 0)
        self.assertEqual(result["migration"]["active_rows_verified"], 1)
        repaired_meta = json.loads(self.active_path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(repaired_meta["payload"]["model_provider"], "openai")

    def test_switch_rolls_back_when_an_active_provider_row_cannot_migrate(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-test"
        )
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        db.execute(
            "CREATE TRIGGER keep_active_provider AFTER UPDATE OF model_provider ON threads "
            "WHEN NEW.archived=0 BEGIN "
            "UPDATE threads SET model_provider='openai' WHERE id=NEW.id; END"
        )
        db.commit()
        db.close()

        with self.assertRaisesRegex(GuardianError, "provider 迁移不完整"):
            self.service.switch_profile(profile["id"])

        db = sqlite3.connect(self.codex / "state_5.sqlite")
        rows = list(db.execute("SELECT archived, model_provider FROM threads ORDER BY archived"))
        db.close()
        self.assertEqual(rows, [(0, "openai"), (1, "openai")])
        self.assertIn('model_provider = "openai"', (self.codex / "config.toml").read_text(encoding="utf-8"))

    def test_api_profile_can_leave_model_blank_without_forcing_old_model(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", ""
        )
        self.service.switch_profile(profile["id"])
        config = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn(f'model_provider = "{profile["provider_id"]}"', config)
        self.assertNotRegex(config, r"(?m)^model\s*=")
        self.assertEqual(profile["model"], "")

    def test_official_profile_can_leave_model_blank_without_forcing_old_model(self) -> None:
        profile = self.service.capture_official("Fixture Official", "")
        self.assertEqual(profile["model"], "")
        (self.codex / "config.toml").write_text(
            'model = "gpt-old"\nmodel_provider = "openai"\n'
            'preferred_auth_method = "chatgpt"\n[features]\nmemories = true\n',
            encoding="utf-8",
        )
        result = self.service.edit_profile(
            profile["id"], {"name": "Fixture Official", "model": ""}
        )
        self.assertTrue(result["current_applied"])
        config = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn('model_provider = "openai"', config)
        self.assertNotRegex(config, r"(?m)^model\s*=")
        self.assertNotRegex(config, r"(?m)^preferred_auth_method\s*=")
        self.assertIn("[features]", config)
        self.assertIn("memories = true", config)

    def test_cockpit_import_leaves_official_model_blank(self) -> None:
        backup_root = self.codex / "account_backup"
        account_root = backup_root / "fixture-account"
        account_root.mkdir(parents=True)
        (backup_root / "profiles.json").write_text(
            json.dumps(
                {
                    "profiles": [
                        {
                            "folder_name": "fixture-account",
                            "account_label": "Imported Official",
                            "plan_name": "Plus",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (account_root / "auth.json").write_text(
            auth_payload("account-imported", "refresh-imported"), encoding="utf-8"
        )
        result = self.service.import_cockpit()
        self.assertEqual(len(result["imported"]), 1)
        imported = next(
            item for item in self.service.list_profiles() if item["name"] == "Imported Official"
        )
        self.assertEqual(imported["model"], "")

    def test_quota_normalization_uses_weekly_window_and_reset_cards(self) -> None:
        response = {
            "email": "private@example.test",
            "access_token": "secret-token",
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "limitName": None,
                    "planType": "plus",
                    "account_id": "private-account-id",
                    "primary": {
                        "usedPercent": 20,
                        "windowDurationMins": 10080,
                        "resetsAt": "1784334377",
                    },
                }
            },
            "rateLimitResetCredits": {
                "availableCount": 2,
                "credits": [
                    {"resetType": "codexRateLimits", "expiresAt": 1786555855},
                    {"resetType": "codexRateLimits", "expiresAt": "1787000000"},
                ],
            },
        }
        quota = normalize_quota_response(response, "prolite")
        self.assertEqual(quota["plan_type"], "prolite")
        self.assertEqual(quota["plan_label"], "Pro 5x")
        self.assertNotIn("five_hour", quota)
        self.assertEqual(quota["weekly"]["remaining_percent"], 80)
        self.assertEqual(quota["weekly"]["resets_at"], 1784334377)
        self.assertEqual(quota["reset_cards"]["available_count"], 2)
        self.assertEqual(quota["reset_cards"]["next_expires_at"], 1786555855)
        serialized = json.dumps(quota)
        self.assertNotIn("private@example.test", serialized)
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("private-account-id", serialized)

    def test_quota_plan_labels_distinguish_plus_and_both_pro_tiers(self) -> None:
        self.assertEqual(quota_plan_label("plus"), "Plus")
        self.assertEqual(quota_plan_label("prolite"), "Pro 5x")
        self.assertEqual(quota_plan_label("pro"), "Pro 20x")
        self.assertEqual(quota_plan_label("unknown", "Codex Pro 5x"), "Pro 5x")

    def test_quota_normalization_rejects_missing_or_invalid_usage(self) -> None:
        for invalid in (None, "not-a-number", True):
            response = {
                "rateLimitsByLimitId": {
                    "codex": {
                        "limitId": "codex",
                        "planType": "plus",
                        "primary": {"windowDurationMins": 10080, "usedPercent": invalid},
                    }
                }
            }
            with self.subTest(invalid=invalid), self.assertRaises(GuardianError):
                normalize_quota_response(response)

    def test_quota_app_server_handshake_does_not_persist_account_identity(self) -> None:
        profile = self.service.capture_official("Fixture Official")
        fake_server = Path(self.temp.name) / "fake_app_server.py"
        fake_server.write_text(
            """
import json, sys
for line in sys.stdin:
    item = json.loads(line)
    request_id = item.get("id")
    if request_id == 1:
        result = {"userAgent": "fixture"}
    elif request_id == 2:
        result = {
            "requiresOpenaiAuth": True,
            "account": {
                "type": "chatgpt",
                "planType": "prolite",
                "email": "quota-sensitive@example.test",
                "accountId": "quota-sensitive-account",
                "accessToken": "quota-sensitive-token",
            },
        }
    elif request_id == 3:
        result = {
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "planType": "plus",
                    "primary": {"usedPercent": 50, "windowDurationMins": 10080, "resetsAt": 200},
                }
            },
            "rateLimitResetCredits": {
                "availableCount": 1,
                "credits": [{"resetType": "codexRateLimits", "expiresAt": 300}],
            },
        }
    else:
        continue
    print(json.dumps({"id": request_id, "result": result}), flush=True)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        with patch.object(
            self.service,
            "_codex_app_server_command",
            return_value=[sys.executable, "-u", str(fake_server)],
        ):
            result = self.service.refresh_official_quotas(profile["id"])
        self.assertEqual(result["updated_count"], 1)
        quota = next(
            item for item in self.service.list_profiles() if item["id"] == profile["id"]
        )["quota"]
        self.assertEqual(quota["plan_type"], "prolite")
        self.assertEqual(quota["plan_label"], "Pro 5x")
        self.assertEqual(quota["reset_cards"]["available_count"], 1)
        public_state = json.dumps(result["status"], ensure_ascii=False)
        disk_state = self.service.profiles_path.read_text(encoding="utf-8")
        logs = self.service.logs_path.read_text(encoding="utf-8")
        for canary in (
            "quota-sensitive@example.test",
            "quota-sensitive-account",
            "quota-sensitive-token",
        ):
            self.assertNotIn(canary, public_state)
            self.assertNotIn(canary, disk_state)
            self.assertNotIn(canary, logs)

    def test_quota_timeout_records_unavailable_then_marks_cached_value_stale(self) -> None:
        profile = self.service.capture_official("Fixture Official")
        with patch.object(
            self.service,
            "_query_official_quota",
            side_effect=subprocess.TimeoutExpired(["codex", "app-server"], 30),
        ):
            result = self.service.refresh_official_quotas(profile["id"])
        self.assertEqual(result["failed_count"], 1)
        unavailable = next(
            item for item in self.service.list_profiles() if item["id"] == profile["id"]
        )["quota"]
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertEqual(unavailable["error"], "额度查询超时")

        state = self.service._load_state()
        target = next(item for item in state["profiles"] if item["id"] == profile["id"])
        target["quota"] = normalize_quota_response(
            {
                "rateLimitsByLimitId": {
                    "codex": {
                        "limitId": "codex",
                        "planType": "plus",
                        "primary": {"usedPercent": 30, "windowDurationMins": 10080},
                    }
                }
            }
        )
        self.service._save_state(state)
        with patch.object(
            self.service,
            "_query_official_quota",
            side_effect=GuardianError("官方登录已失效，请先更新登录。"),
        ):
            self.service.refresh_official_quotas(profile["id"])
        stale = next(
            item for item in self.service.list_profiles() if item["id"] == profile["id"]
        )["quota"]
        self.assertTrue(stale["stale"])
        self.assertEqual(stale["status"], "ready")
        self.assertIn("登录已失效", stale["error"])

    @patch("backend.guardian.os.name", "nt")
    def test_windows_store_codex_cli_is_cached_before_execution(self) -> None:
        package_root = self.data / "store-package"
        source = package_root / "app" / "resources" / "codex.exe"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"MZ-store-codex")
        discovery = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "version": "26.707.6957.0",
                    "install_location": str(package_root),
                }
            ),
        )
        with patch("backend.guardian.subprocess.run", return_value=discovery), patch.object(
            self.service, "_codex_cli_is_runnable", return_value=True
        ):
            cached = self.service._cached_windows_store_codex_cli()

        expected = (
            self.service.data_dir
            / "runtime"
            / "codex"
            / "26.707.6957.0"
            / "codex.exe"
        )
        self.assertEqual(cached, expected)
        self.assertEqual(expected.read_bytes(), source.read_bytes())
        metadata = json.loads(expected.with_name("source.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["source_size"], source.stat().st_size)

    @patch("backend.guardian.os.name", "nt")
    def test_windows_store_codex_cli_reuses_matching_valid_cache(self) -> None:
        package_root = self.data / "store-package"
        source = package_root / "app" / "resources" / "codex.exe"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"MZ-store-codex")
        discovery = Mock(
            returncode=0,
            stdout=json.dumps(
                {"version": "1.2.3.4", "install_location": str(package_root)}
            ),
        )
        with patch("backend.guardian.subprocess.run", return_value=discovery), patch.object(
            self.service, "_codex_cli_is_runnable", return_value=True
        ):
            first = self.service._cached_windows_store_codex_cli()
            with patch("backend.guardian.shutil.copy2") as copy_again:
                second = self.service._cached_windows_store_codex_cli()
        self.assertEqual(first, second)
        copy_again.assert_not_called()

    def test_switch_preserves_missing_session_index(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-test"
        )
        index_path = self.codex / "session_index.jsonl"
        self.assertFalse(index_path.exists())
        result = self.service.switch_profile(profile["id"])
        self.assertFalse(result["migration"]["index_preserved"])
        self.assertEqual(result["migration"]["index_rows"], 0)
        self.assertFalse(index_path.exists())

    def test_rewrite_preserves_new_session_meta_fields_and_chat_body(self) -> None:
        meta = {
            "type": "session_meta",
            "payload": {
                "id": self.active_id,
                "model_provider": "openai",
                "memory_mode": "disabled",
                "history_mode": "full",
                "context_window": 200000,
                "source": {"sub_agent": {"role": "worker"}},
                "dynamic_tools": [{"name": "fixture"}],
            },
        }
        body = b'{"type":"response_item","payload":{"marker":"body-unchanged"}}\n' + (b"z" * 4096)
        self.active_path.write_bytes(
            json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            + b"\n"
            + body
        )
        changed = self.service._rewrite_rollouts("guardian_fixture_provider")
        self.assertGreaterEqual(changed, 1)
        first_line, rest = self.active_path.read_bytes().split(b"\n", 1)
        patched = json.loads(first_line)
        self.assertEqual(rest, body)
        self.assertEqual(patched["payload"]["model_provider"], "guardian_fixture_provider")
        self.assertEqual(patched["payload"]["memory_mode"], "disabled")
        self.assertEqual(patched["payload"]["history_mode"], "full")
        self.assertEqual(patched["payload"]["source"], {"sub_agent": {"role": "worker"}})
        self.assertEqual(patched["payload"]["dynamic_tools"], [{"name": "fixture"}])

    def test_backup_snapshots_rollout_first_lines_without_copying_bodies(self) -> None:
        original_first_line = self.active_path.read_bytes().split(b"\n", 1)[0] + b"\n"
        self.active_path.write_bytes(original_first_line + (b"x" * (1024 * 1024)))
        backup = self.service.create_backup("fixture-lightweight", prune=False)
        backup_root = self.data / "backups" / backup["name"]
        self.assertFalse((backup_root / "files" / "sessions").exists())
        self.assertFalse((backup_root / "files" / "archived_sessions").exists())
        snapshot = backup_root / "rollout-first-lines.jsonl"
        self.assertTrue(snapshot.is_file())
        self.assertLess(snapshot.stat().st_size, 20_000)
        manifest = json.loads((backup_root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["backup_mode"], "lightweight-first-line")
        self.assertEqual(manifest["rollout_file_count"], 2)
        self.assertFalse((backup_root / "files" / "auth.json").exists())
        encrypted_auth = backup_root / "files" / "auth.json.dpapi"
        self.assertTrue(encrypted_auth.is_file())
        self.assertNotIn(b"refresh-a", encrypted_auth.read_bytes())
        self.assertEqual(
            manifest["sensitive_files_encrypted"],
            [
                {
                    "source": "auth.json",
                    "stored": "auth.json.dpapi",
                    "protection": "windows-dpapi-current-user",
                }
            ],
        )

        self.service._rewrite_rollouts("guardian_fixture")
        changed_first_line = self.active_path.read_bytes().split(b"\n", 1)[0] + b"\n"
        self.assertNotEqual(changed_first_line, original_first_line)
        self.service._restore_files_from_backup(backup_root)
        restored_first_line = self.active_path.read_bytes().split(b"\n", 1)[0] + b"\n"
        self.assertEqual(restored_first_line, original_first_line)

    def test_api_backup_never_persists_plaintext_key_and_restores_auth(self) -> None:
        api_key = "sk-fixture-backup-plaintext-regression"
        api_auth = json.dumps({"OPENAI_API_KEY": api_key}).encode("utf-8")
        (self.codex / "auth.json").write_bytes(api_auth)

        backup = self.service.create_backup("fixture-api-secret", prune=False)
        backup_root = self.data / "backups" / backup["name"]
        self.assertFalse((backup_root / "files" / "auth.json").exists())
        encrypted_auth = backup_root / "files" / "auth.json.dpapi"
        self.assertTrue(encrypted_auth.is_file())
        for path in backup_root.rglob("*"):
            if path.is_file():
                self.assertNotIn(api_key.encode("utf-8"), path.read_bytes())

        (self.codex / "auth.json").write_text('{"changed":true}', encoding="utf-8")
        self.service._restore_files_from_backup(backup_root)
        self.assertEqual((self.codex / "auth.json").read_bytes(), api_auth)

    def test_encrypted_auth_takes_precedence_over_legacy_plaintext_copy(self) -> None:
        original_auth = (self.codex / "auth.json").read_bytes()
        backup = self.service.create_backup("fixture-auth-precedence", prune=False)
        backup_root = self.data / "backups" / backup["name"]
        (backup_root / "files" / "auth.json").write_text(
            '{"OPENAI_API_KEY":"legacy-plaintext-must-not-win"}',
            encoding="utf-8",
        )
        (self.codex / "auth.json").write_text('{"changed":true}', encoding="utf-8")

        self.service._restore_files_from_backup(backup_root)

        self.assertEqual((self.codex / "auth.json").read_bytes(), original_auth)

    def test_database_restore_removes_stale_wal_and_shm(self) -> None:
        backup = self.service.create_backup("fixture-restore", prune=False)
        backup_root = self.data / "backups" / backup["name"]
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        db.execute("UPDATE threads SET model_provider='changed-after-backup'")
        db.commit()
        db.close()
        wal = self.codex / "state_5.sqlite-wal"
        shm = self.codex / "state_5.sqlite-shm"
        wal.write_bytes(b"stale-wal")
        shm.write_bytes(b"stale-shm")
        self.service._restore_files_from_backup(backup_root)
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        restored = sqlite3.connect(self.codex / "state_5.sqlite")
        providers = {row[0] for row in restored.execute("SELECT model_provider FROM threads")}
        integrity = restored.execute("PRAGMA integrity_check").fetchone()[0]
        restored.close()
        self.assertEqual(providers, {"openai"})
        self.assertEqual(integrity, "ok")

    def test_list_backups_compacts_legacy_full_rollout_copies(self) -> None:
        backup_root = self.data / "backups" / "20260710-000000-legacy-full"
        legacy_rollout = backup_root / "files" / "sessions" / "2026" / "07" / "06" / self.active_path.name
        legacy_rollout.parent.mkdir(parents=True)
        first_line = self.active_path.read_bytes().split(b"\n", 1)[0] + b"\n"
        legacy_rollout.write_bytes(first_line + (b"x" * (1024 * 1024)))
        atomic_manifest = {
            "name": backup_root.name,
            "created_at": "2026-07-10T00:00:00Z",
            "reason": "legacy-full",
            "copied_files": [str(legacy_rollout.relative_to(backup_root / "files"))],
            "rollout_file_count": 1,
            "archived_flags": {},
            "archived_count": 0,
            "active_count": 0,
        }
        (backup_root / "manifest.json").write_text(json.dumps(atomic_manifest), encoding="utf-8")
        backups = self.service.list_backups()
        legacy = next(item for item in backups if item["name"] == backup_root.name)
        self.assertLess(legacy["size_mb"], 0.1)
        self.assertEqual(legacy["backup_mode"], "lightweight-first-line-compacted")
        self.assertFalse((backup_root / "files" / "sessions").exists())
        self.assertTrue((backup_root / "rollout-first-lines.jsonl").is_file())

    def test_list_backups_accepts_utf8_bom_manifest_from_powershell(self) -> None:
        backup_root = self.data / "backups" / "20260710-010000-bom-manifest"
        backup_root.mkdir(parents=True)
        manifest = {
            "name": backup_root.name,
            "created_at": "2026-07-10T01:00:00Z",
            "reason": "bom-manifest",
            "backup_mode": "lightweight-first-line-compacted",
            "copied_files": [],
            "rollout_file_count": 0,
            "archived_count": 0,
            "active_count": 0,
        }
        (backup_root / "manifest.json").write_bytes(
            b"\xef\xbb\xbf" + json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        )

        backups = self.service.list_backups()

        bom_backup = next(item for item in backups if item["name"] == backup_root.name)
        self.assertEqual(bom_backup["reason"], "bom-manifest")
        self.assertEqual(bom_backup["backup_mode"], "lightweight-first-line-compacted")

    def test_api_models_forbidden_is_recorded_as_warning(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "https://api.example.test/v1", "secret-key", ""
        )
        forbidden = urlerror.HTTPError(
            "https://api.example.test/v1/models",
            403,
            "Forbidden",
            {},
            io.BytesIO(b'{"error":"models forbidden"}'),
        )
        try:
            with patch("backend.guardian.urlrequest.urlopen", side_effect=forbidden):
                result = self.service.test_api_profile(profile["id"])
        finally:
            forbidden.close()
        self.assertFalse(result["ok"])
        self.assertTrue(result["warning"])
        self.assertEqual(result["status"], 403)
        stored = next(item for item in self.service.list_profiles() if item["id"] == profile["id"])
        self.assertFalse(stored["last_test"]["ok"])
        self.assertTrue(stored["last_test"]["warning"])
        self.assertIn("模型列表未开放", stored["last_test"]["message"])

    def test_edit_current_api_profile_keeps_blank_key_and_applies_config(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-old"
        )
        self.service.switch_profile(profile["id"])
        result = self.service.edit_profile(
            profile["id"],
            {
                "name": "Edited API",
                "base_url": "https://api.example.test/v1",
                "api_key": "",
                "model": "",
            },
        )
        self.assertTrue(result["current_applied"])
        self.assertEqual(self.service.decrypt_secret(profile["id"]), b"secret-key")
        config = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn('base_url = "https://api.example.test/v1"', config)
        self.assertNotRegex(config, r"(?m)^model\s*=")
        edited = next(item for item in self.service.list_profiles() if item["id"] == profile["id"])
        self.assertEqual(edited["name"], "Edited API")
        self.assertEqual(edited["base_url"], "https://api.example.test/v1")
        self.assertIsNone(edited["last_test"])

    def test_edit_current_api_marks_previous_remote_sync_stale(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-old"
        )
        self.service.switch_profile(profile["id"])
        state = self.service._load_state()
        state["settings"]["sync_ssh_api"] = True
        state["remote_status"] = {
            "host_count": 1,
            "success_count": 1,
            "results": [{"ok": True}],
            "synced_at": "2026-07-13T10:50:31+00:00",
        }
        self.service._save_state(state)

        with patch(
            "backend.guardian.discover_remote_hosts",
            return_value=[
                {
                    "target": "fixture",
                    "port": 22,
                    "display_name": "Fixture",
                    "host_id": "fixture",
                }
            ],
        ):
            result = self.service.edit_profile(
                profile["id"],
                {
                    "name": "Fixture API",
                    "base_url": "https://api.example.test/v1",
                    "api_key": "new-secret-key",
                    "model": "gpt-new",
                },
            )

        self.assertTrue(result["remote_sync_required"])
        self.assertEqual(result["remote_host_count"], 1)
        remote = self.service._load_state()["remote_status"]
        self.assertTrue(remote["stale"])
        self.assertEqual(remote["success_count"], 0)
        self.assertEqual(remote["previous_synced_at"], "2026-07-13T10:50:31+00:00")

    def test_manual_remote_sync_keeps_incomplete_result_stale(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "https://api.example.test/v1", "secret-key", "gpt-test"
        )
        self.service.switch_profile(profile["id"])
        state = self.service._load_state()
        state["settings"]["sync_ssh_api"] = True
        self.service._save_state(state)
        self.service.is_fixture = False

        with patch(
            "backend.guardian.sync_api_profile_to_remotes",
            return_value={
                "host_count": 1,
                "success_count": 0,
                "results": [{"ok": False, "error": "fixture"}],
                "synced_at": "2026-07-14T08:00:00+00:00",
            },
        ):
            result = self.service.sync_current_to_remotes()

        self.assertTrue(result["stale"])
        self.assertEqual(result["stale_reason"], "remote_sync_incomplete")
        self.assertTrue(self.service._load_state()["remote_status"]["stale"])

    def test_edit_api_profile_can_replace_key_when_provided(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "http://127.0.0.1:8317/v1", "old-key", "gpt-old"
        )
        self.assertEqual(
            profile["protocol_compatibility"],
            {
                "allow_terminal_output_omission": False,
                "allow_terminal_output_missing_item_ids": False,
                "allow_terminal_output_missing_item_status": False,
                "allow_function_call_arguments_done_missing_name": False,
            },
        )
        result = self.service.edit_profile(
            profile["id"],
            {
                "name": "Fixture API",
                "base_url": "http://127.0.0.1:8317/v1",
                "api_key": "new-secret-key",
                "model": "gpt-new",
                "protocol_compatibility": {
                    "allow_terminal_output_missing_item_ids": True,
                    "allow_terminal_output_missing_item_status": True,
                    "allow_function_call_arguments_done_missing_name": True,
                },
            },
        )
        self.assertFalse(result["current_applied"])
        self.assertEqual(self.service.decrypt_secret(profile["id"]), b"new-secret-key")
        edited = next(item for item in self.service.list_profiles() if item["id"] == profile["id"])
        self.assertTrue(edited["secret_hint"].endswith("key"))
        self.assertEqual(edited["model"], "gpt-new")
        self.assertTrue(
            edited["protocol_compatibility"][
                "allow_terminal_output_missing_item_status"
            ]
        )
        self.assertTrue(
            edited["protocol_compatibility"][
                "allow_function_call_arguments_done_missing_name"
            ]
        )
        with self.assertRaisesRegex(GuardianError, "协议兼容设置无效"):
            self.service.edit_profile(
                profile["id"],
                {
                    "protocol_compatibility": {
                        "allow_unknown_relaxation": True,
                    }
                },
            )

    def test_edit_official_profile_updates_name_and_default_model(self) -> None:
        official = self.service.capture_official("Fixture Official")
        result = self.service.edit_profile(
            official["id"], {"name": "Renamed Official", "model": "gpt-5.4"}
        )
        self.assertTrue(result["current_applied"])
        self.assertIn(b"refresh-a", self.service.decrypt_secret(official["id"]))
        config = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn('model_provider = "openai"', config)
        self.assertIn('model = "gpt-5.4"', config)
        edited = next(item for item in self.service.list_profiles() if item["id"] == official["id"])
        self.assertEqual(edited["name"], "Renamed Official")

    def test_official_credentials_are_encrypted_and_restored(self) -> None:
        profile = self.service.capture_official("Official")
        encrypted = self.service._secret_path(profile["id"]).read_bytes()
        self.assertNotIn(b"refresh-a", encrypted)
        (self.codex / "auth.json").write_text('{"changed":true}', encoding="utf-8")
        self.service.switch_profile(profile["id"])
        self.assertIn("refresh-a", (self.codex / "auth.json").read_text(encoding="utf-8"))

    def test_capture_same_account_updates_instead_of_duplicating(self) -> None:
        first = self.service.capture_official("Official old")
        (self.codex / "auth.json").write_text(
            auth_payload("account-a", "refresh-a-new", last_refresh="2026-07-06T01:00:00Z"),
            encoding="utf-8",
        )
        second = self.service.capture_official("Official new")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.service.list_profiles()), 1)
        self.assertIn(b"refresh-a-new", self.service.decrypt_secret(first["id"]))

    def test_switch_saves_rotated_live_token_before_overwrite(self) -> None:
        account_a = self.service.capture_official("Account A")
        (self.codex / "auth.json").write_text(auth_payload("account-b", "refresh-b"), encoding="utf-8")
        account_b = self.service.capture_official("Account B")
        state = self.service._load_state()
        state["current_profile"] = account_a["id"]
        self.service._save_state(state)
        (self.codex / "auth.json").write_text(
            auth_payload("account-a", "refresh-a-rotated", last_refresh="2026-07-06T02:00:00Z"),
            encoding="utf-8",
        )
        self.service.switch_profile(account_b["id"])
        self.assertIn(b"refresh-a-rotated", self.service.decrypt_secret(account_a["id"]))
        self.assertIn("refresh-b", (self.codex / "auth.json").read_text(encoding="utf-8"))

    def test_switch_preserves_latest_global_config_instead_of_old_profile_snapshot(self) -> None:
        (self.codex / "config.toml").write_text(
            'model = "gpt-5.5"\nmodel_provider = "openai"\nservice_tier = "fast"\n[features]\nmemories = true\n',
            encoding="utf-8",
        )
        account_a = self.service.capture_official("Account A", "gpt-5.5")
        (self.codex / "auth.json").write_text(auth_payload("account-b", "refresh-b"), encoding="utf-8")
        (self.codex / "config.toml").write_text(
            'model = "gpt-5.4"\nmodel_provider = "openai"\nservice_tier = "default"\n[features]\nmemories = false\n',
            encoding="utf-8",
        )
        account_b = self.service.capture_official("Account B", "gpt-5.4")
        latest_global = (
            'model = "gpt-5.4"\nmodel_provider = "openai"\nservice_tier = "flex"\n'
            '[features]\nmemories = false\njs_repl = true\n'
            '[plugins."sites@openai-bundled"]\nenabled = true\n'
            '[mcp_servers.future-app-setting]\nurl = "https://example.invalid/mcp"\n'
            '[desktop]\nconversationDetailMode = "expanded"\n'
        )
        (self.codex / "config.toml").write_text(latest_global, encoding="utf-8")
        self.service.switch_profile(account_a["id"])
        config_a = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn('model = "gpt-5.5"', config_a)
        self.assertIn('service_tier = "flex"', config_a)
        self.assertIn("memories = false", config_a)
        self.assertIn('[plugins."sites@openai-bundled"]', config_a)
        self.assertIn("[mcp_servers.future-app-setting]", config_a)
        self.assertIn('conversationDetailMode = "expanded"', config_a)
        self.service.switch_profile(account_b["id"])
        config_b = (self.codex / "config.toml").read_text(encoding="utf-8")
        self.assertIn('model = "gpt-5.4"', config_b)
        self.assertIn('service_tier = "flex"', config_b)
        self.assertIn("memories = false", config_b)
        self.assertIn('[plugins."sites@openai-bundled"]', config_b)
        self.assertIn("[mcp_servers.future-app-setting]", config_b)

    def test_remote_portable_config_excludes_windows_only_tables(self) -> None:
        payload = portable_config(
            b'model = "gpt-5.5"\npreferred_auth_method = "chatgpt"\nsandbox_mode = "workspace-write"\n[features]\nmemories = true\n[mcp_servers.local]\ncommand = "C:\\\\tool.exe"\n[projects."C:\\\\repo"]\ntrust_level = "trusted"\n'
        )
        self.assertEqual(payload["top"]["model"], "gpt-5.5")
        self.assertEqual(payload["top"]["sandbox_mode"], "workspace-write")
        self.assertEqual(payload["tables"]["features"]["memories"], True)
        self.assertNotIn("preferred_auth_method", payload["top"])
        self.assertNotIn("mcp_servers", payload["tables"])
        self.assertNotIn("projects", payload["tables"])

    def test_remote_scripts_remove_stale_model_when_profile_model_is_blank(self) -> None:
        self.assertIn(
            'lines = remove_top_keys(lines, {"preferred_auth_method"})',
            _REMOTE_APPLY_SCRIPT,
        )
        self.assertIn('if "model" not in top:', _REMOTE_APPLY_SCRIPT)
        self.assertIn('lines = remove_top_keys(lines, {"model"})', _REMOTE_APPLY_SCRIPT)
        self.assertIn(
            'lines = remove_top_keys(lines, {"preferred_auth_method"})',
            _REMOTE_API_APPLY_SCRIPT,
        )
        self.assertIn('top.pop("model", None)', _REMOTE_API_APPLY_SCRIPT)
        self.assertIn('lines = remove_top_keys(lines, {"model"})', _REMOTE_API_APPLY_SCRIPT)

    def test_remote_newer_token_becomes_authority_before_projection(self) -> None:
        local = auth_payload(
            "account-a", "refresh-old", last_refresh="2026-07-06T01:00:00Z"
        ).encode()
        remote = auth_payload(
            "account-a", "refresh-new", last_refresh="2026-07-06T02:00:00Z"
        ).encode()
        history = {
            "target": "openai",
            "shared_history_preserved": True,
            "archives": {},
            "paths": {},
            "index_sha256": None,
        }
        responses = [
            subprocess.CompletedProcess([], 0, base64.b64encode(remote).decode(), ""),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps({"ok": True, "backup": "fixture", "config_bytes": 50})
                + "\n"
                + json.dumps(history)
                + "\n",
                "",
            ),
            subprocess.CompletedProcess([], 0, '{"ok":true,"post_restart_verified":true}\n', ""),
        ]
        with patch(
            "backend.remote_sync.discover_remote_hosts",
            return_value=[{"target": "fixture", "port": 22, "display_name": "Fixture", "host_id": "fixture"}],
        ), patch("backend.remote_sync.subprocess.run", side_effect=responses):
            result, authority = sync_official_to_remotes(
                local, b'model = "gpt-5.5"\n', Path("fixture-state.json")
            )
        self.assertEqual(result["success_count"], 1)
        self.assertIn(b"refresh-new", authority)

    def test_remote_api_profile_sync_uses_redacted_result(self) -> None:
        profile = {
            "provider_id": "guardian_fixture",
            "name": "Fixture API",
            "base_url": "https://example.test/v1",
            "model": "gpt-test",
        }
        history = {
            "target": "guardian_fixture",
            "shared_history_preserved": True,
            "archives": {},
            "paths": {},
            "index_sha256": None,
        }
        responses = [
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "ok": True,
                        "backup": "fixture",
                        "config_bytes": 180,
                        "provider_id": "guardian_fixture",
                        "key_path": "/home/me/.codex/guardian-api-profiles/guardian_fixture.key",
                    }
                )
                + "\n"
                + json.dumps(history)
                + "\n",
                "",
            ),
            subprocess.CompletedProcess([], 0, '{"ok":true,"post_restart_verified":true}\n', ""),
        ]
        with patch(
            "backend.remote_sync.discover_remote_hosts",
            return_value=[{"target": "fixture", "port": 22, "display_name": "Fixture", "host_id": "fixture"}],
        ), patch("backend.remote_sync.subprocess.run", side_effect=responses) as run:
            result = sync_api_profile_to_remotes(
                profile,
                b"sk-fixture-secret",
                b'model = "gpt-test"\n',
                Path("fixture-state.json"),
            )
        self.assertEqual(result["success_count"], 1)
        self.assertNotIn("sk-fixture-secret", json.dumps(result))
        self.assertIn("guardian-api-profiles", result["results"][0]["key_path"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][-1], "python3 -")

    def test_remote_api_profile_sync_allows_blank_model(self) -> None:
        profile = {
            "provider_id": "guardian_fixture",
            "name": "Fixture API",
            "base_url": "https://example.test/v1",
            "model": "",
        }
        history = {
            "target": "guardian_fixture",
            "shared_history_preserved": True,
            "archives": {},
            "paths": {},
            "index_sha256": None,
        }
        responses = [
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "ok": True,
                        "backup": "fixture",
                        "config_bytes": 180,
                        "provider_id": "guardian_fixture",
                        "key_path": "/home/me/.codex/guardian-api-profiles/guardian_fixture.key",
                    }
                )
                + "\n"
                + json.dumps(history)
                + "\n",
                "",
            ),
            subprocess.CompletedProcess([], 0, '{"ok":true,"post_restart_verified":true}\n', ""),
        ]
        with patch(
            "backend.remote_sync.discover_remote_hosts",
            return_value=[{"target": "fixture", "port": 22, "display_name": "Fixture", "host_id": "fixture"}],
        ), patch("backend.remote_sync.subprocess.run", side_effect=responses) as run:
            result = sync_api_profile_to_remotes(
                profile,
                b"sk-fixture-secret",
                b'model = "gpt-old"\n',
                Path("fixture-state.json"),
            )
        script_input = run.call_args_list[0].kwargs["input"]
        encoded_payload = script_input.split("base64.b64decode('", 1)[1].split("')", 1)[0]
        payload = json.loads(base64.b64decode(encoded_payload))
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(payload["provider"]["model"], "")

    def test_remote_reconcile_patches_large_jsonl_meta_without_moving_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex = root / ".codex"
            sessions = codex / "sessions" / "2026" / "07" / "09"
            sessions.mkdir(parents=True)
            (codex / "config.toml").write_text(
                'model_provider = "guardian_fixture"\n', encoding="utf-8"
            )
            thread_id = "019f40ce-dc00-7000-9000-000000000001"
            rollout = sessions / f"rollout-{thread_id}.jsonl"
            meta = {
                "type": "session_meta",
                "payload": {
                    "id": thread_id,
                    "timestamp": "2026-07-09T12:30:00Z",
                    "cwd": str(root),
                    "originator": "vscode",
                    "cli_version": "0.142.4",
                    "source": "vscode",
                    "thread_source": "remote",
                    "model_provider": "openai",
                    "base_instructions": "x" * 200,
                    "dynamic_tools": [],
                    "memory_mode": "disabled",
                },
            }
            body = b'{"type":"response_item","payload":{"marker":"body-stays-put"}}\n' + (b"x" * 8192)
            rollout.write_bytes(json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n" + body)
            before = rollout.read_bytes()
            before_first, before_rest = before.split(b"\n", 1)
            before_mtime = rollout.stat().st_mtime_ns

            db = sqlite3.connect(codex / "state_5.sqlite")
            db.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, updated_at TEXT, "
                "source TEXT, model_provider TEXT, title TEXT, first_user_message TEXT, "
                "archived INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER)"
            )
            db.execute(
                "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    thread_id,
                    str(rollout),
                    "2026-07-09T12:30:00Z",
                    "vscode",
                    "openai",
                    "Remote Active",
                    "Remote Active",
                    0,
                    1783600200000,
                    1783600200000,
                ),
            )
            archived_id = "019f40ce-dc00-7000-9000-000000000002"
            archived = codex / "archived_sessions" / f"rollout-{archived_id}.jsonl"
            archived.parent.mkdir(parents=True)
            archived.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {
                            "id": archived_id,
                            "source": "vscode",
                            "model_provider": "openai",
                            "memory_mode": "disabled",
                        },
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            db.execute(
                "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    archived_id,
                    str(archived),
                    "2026-07-09T12:00:00Z",
                    "vscode",
                    "openai",
                    "Archived Remote",
                    "Archived Remote",
                    1,
                    1783598400000,
                    1783598400000,
                ),
            )
            db.commit()
            db.close()

            env = os.environ.copy()
            env["HOME"] = str(root)
            env["USERPROFILE"] = str(root)
            completed = subprocess.run(
                [sys.executable, "-c", _REMOTE_RECONCILE_SCRIPT],
                cwd=str(root),
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["rollout_files_updated"], 2)
            self.assertEqual(result["rollout_stream_rewrites"], 2)
            self.assertEqual(result["memory_mode_removed"], 0)
            self.assertFalse(result["index_preserved"])
            self.assertEqual(result["index_rows"], 0)

            after = rollout.read_bytes()
            after_first, after_rest = after.split(b"\n", 1)
            self.assertGreater(len(after_first), len(before_first))
            self.assertEqual(after_rest, before_rest)
            self.assertEqual(rollout.stat().st_mtime_ns, before_mtime)
            patched_meta = json.loads(after_first)
            self.assertEqual(patched_meta["payload"]["model_provider"], "guardian_fixture")
            self.assertEqual(patched_meta["payload"]["memory_mode"], "disabled")

            db = sqlite3.connect(codex / "state_5.sqlite")
            rows = list(db.execute("SELECT model_provider, archived FROM threads"))
            db.close()
            self.assertEqual(sorted(rows), [("guardian_fixture", 0), ("guardian_fixture", 1)])
            self.assertFalse((codex / "session_index.jsonl").exists())

    def test_remote_reconcile_quarantines_prefix_duplicate_without_changing_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex = root / ".codex"
            active_dir = codex / "sessions" / "2026" / "07" / "09"
            archived_dir = codex / "archived_sessions"
            active_dir.mkdir(parents=True)
            archived_dir.mkdir(parents=True)
            (codex / "config.toml").write_text('model_provider = "guardian_fixture"\n', encoding="utf-8")
            thread_id = "019f40ce-dc00-7000-9000-000000000201"
            meta = {
                "type": "session_meta",
                "payload": {"id": thread_id, "model_provider": "openai", "memory_mode": "disabled"},
            }
            first = json.dumps(meta, separators=(",", ":")).encode("utf-8") + b"\n"
            body = b'{"type":"response_item","payload":{"marker":"complete"}}\n' + (b"z" * 4096)
            canonical = active_dir / f"rollout-{thread_id}.jsonl"
            duplicate = archived_dir / f"rollout-{thread_id}.jsonl"
            canonical.write_bytes(first + body)
            duplicate.write_bytes(first + body[:40])
            old_mtime = canonical.stat().st_mtime_ns - 10_000_000
            os.utime(canonical, ns=(old_mtime, old_mtime))
            before_body = canonical.read_bytes().split(b"\n", 1)[1]
            db = sqlite3.connect(codex / "state_5.sqlite")
            db.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, archived INTEGER, rollout_path TEXT, model_provider TEXT)"
            )
            db.execute(
                "INSERT INTO threads VALUES (?,?,?,?)",
                (thread_id, 0, str(canonical), "openai"),
            )
            db.commit()
            db.close()
            env = os.environ.copy()
            env["HOME"] = str(root)
            env["USERPROFILE"] = str(root)
            completed = subprocess.run(
                [sys.executable, "-c", _REMOTE_RECONCILE_SCRIPT],
                cwd=str(root), env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["duplicate_thread_count"], 1)
            self.assertEqual(result["duplicate_files_quarantined"], 1)
            self.assertTrue(result["shared_history_preserved"])
            self.assertFalse(duplicate.exists())
            quarantine = codex / "guardian-quarantine"
            self.assertEqual(len(list(quarantine.rglob("*.jsonl"))), 1)
            after = canonical.read_bytes()
            self.assertEqual(after.split(b"\n", 1)[1], before_body)
            self.assertEqual(canonical.stat().st_mtime_ns, old_mtime)
            db = sqlite3.connect(codex / "state_5.sqlite")
            row = db.execute("SELECT archived, rollout_path, model_provider FROM threads").fetchone()
            db.close()
            self.assertEqual(row, (0, str(canonical), "guardian_fixture"))

    def test_remote_reconcile_refuses_divergent_duplicate_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex = root / ".codex"
            active_dir = codex / "sessions"
            archived_dir = codex / "archived_sessions"
            active_dir.mkdir(parents=True)
            archived_dir.mkdir(parents=True)
            (codex / "config.toml").write_text('model_provider = "guardian_fixture"\n', encoding="utf-8")
            thread_id = "019f40ce-dc00-7000-9000-000000000202"
            first = json.dumps(
                {"type": "session_meta", "payload": {"id": thread_id, "model_provider": "openai"}},
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            left = active_dir / f"rollout-{thread_id}.jsonl"
            right = archived_dir / f"rollout-{thread_id}.jsonl"
            left.write_bytes(first + b"left-only\n")
            right.write_bytes(first + b"right-only\n")
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (left, right)}
            db = sqlite3.connect(codex / "state_5.sqlite")
            db.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, archived INTEGER, rollout_path TEXT, model_provider TEXT)"
            )
            db.execute("INSERT INTO threads VALUES (?,?,?,?)", (thread_id, 0, str(left), "openai"))
            db.commit()
            db.close()
            env = os.environ.copy()
            env["HOME"] = str(root)
            env["USERPROFILE"] = str(root)
            completed = subprocess.run(
                [sys.executable, "-c", _REMOTE_RECONCILE_SCRIPT],
                cwd=str(root), env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(
                {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (left, right)},
                before,
            )
            db = sqlite3.connect(codex / "state_5.sqlite")
            self.assertEqual(db.execute("SELECT archived, rollout_path, model_provider FROM threads").fetchone(), (0, str(left), "openai"))
            db.close()

    def test_api_switch_rejects_invalid_credential_before_closing_codex(self) -> None:
        profile = self.service.create_api_profile(
            "Fixture API", "https://api.example.test/v1", "secret-key", "gpt-test"
        )
        state = self.service._load_state()
        state["settings"]["sync_ssh_api"] = True
        self.service._save_state(state)
        self.service.is_fixture = False
        with patch.object(
            self.service,
            "test_api_profile",
            return_value={"ok": False, "warning": False, "message": "HTTP 401"},
        ), patch.object(self.service, "_ensure_codex_closed") as close:
            with self.assertRaises(GuardianError) as error:
                self.service.switch_profile(profile["id"])
        self.assertIn("HTTP 401", str(error.exception))
        close.assert_not_called()

    def test_remote_reconcile_preserves_existing_session_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex = root / ".codex"
            codex.mkdir(parents=True)
            (codex / "config.toml").write_text(
                'model_provider = "guardian_fixture"\n', encoding="utf-8"
            )
            active_id = "019f40ce-dc00-7000-9000-000000000101"
            archived_id = "019f40ce-dc00-7000-9000-000000000102"
            original_index = (
                json.dumps({"id": active_id, "thread_name": "Kept Active", "updated_at": 22}, separators=(",", ":"))
                + "\n"
            )
            (codex / "session_index.jsonl").write_text(original_index, encoding="utf-8")
            active_rollout = codex / "sessions" / "rollout-active-index.jsonl"
            archived_rollout = codex / "archived_sessions" / "rollout-archived-index.jsonl"
            for path, thread_id in ((active_rollout, active_id), (archived_rollout, archived_id)):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {
                            "type": "session_meta",
                            "payload": {"id": thread_id, "model_provider": "openai"},
                        },
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
            db = sqlite3.connect(codex / "state_5.sqlite")
            db.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, source TEXT, "
                "model_provider TEXT, title TEXT, first_user_message TEXT, archived INTEGER, "
                "created_at_ms INTEGER, updated_at_ms INTEGER)"
            )
            db.executemany(
                "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (active_id, str(active_rollout), "vscode", "openai", "Active", "Active", 0, 1, 2),
                    (archived_id, str(archived_rollout), "vscode", "openai", "Archived", "Archived", 1, 3, 4),
                ],
            )
            db.commit()
            db.close()

            env = os.environ.copy()
            env["HOME"] = str(root)
            env["USERPROFILE"] = str(root)
            completed = subprocess.run(
                [sys.executable, "-c", _REMOTE_RECONCILE_SCRIPT],
                cwd=str(root),
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["index_preserved"])
            self.assertEqual(result["index_rows"], 1)
            self.assertEqual((codex / "session_index.jsonl").read_text(encoding="utf-8"), original_index)
            db = sqlite3.connect(codex / "state_5.sqlite")
            rows = list(db.execute("SELECT model_provider, archived FROM threads ORDER BY id"))
            db.close()
            self.assertEqual(rows, [("guardian_fixture", 0), ("guardian_fixture", 1)])

    def test_failed_switch_rolls_back(self) -> None:
        profile = self.service.create_api_profile("Fixture", "http://localhost/v1", "key", "model")
        original_config = (self.codex / "config.toml").read_bytes()
        original_method = self.service._update_config

        def fail(target):
            original_method(target)
            raise RuntimeError("fixture failure")

        self.service._update_config = fail  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError):
            self.service.switch_profile(profile["id"])
        self.service._update_config = original_method  # type: ignore[method-assign]
        self.assertEqual((self.codex / "config.toml").read_bytes(), original_config)

    def test_auto_close_falls_back_to_force_for_remaining_process_tree(self) -> None:
        self.service.is_fixture = False
        self.service._codex_related_running = Mock(side_effect=[True, False])  # type: ignore[method-assign]
        with patch("backend.guardian.subprocess.run") as run, patch(
            "backend.guardian.time.time", side_effect=[0, 10, 10, 11]
        ):
            self.assertTrue(self.service.request_close_codex())
        self.assertEqual(run.call_count, 2)
        graceful = run.call_args_list[0].args[0][-1]
        forced = run.call_args_list[1].args[0][-1]
        self.assertIn("taskkill.exe /PID", graceful)
        self.assertIn("/T", graceful)
        self.assertIn("ChatGPT.exe", graceful)
        self.assertIn("OpenAI\\.Codex_", graceful)
        self.assertIn("resources\\\\codex", graceful)
        self.assertIn("app-server", graceful)
        self.assertNotIn("/F /PID", graceful)
        self.assertIn("taskkill.exe /F /PID", forced)
        self.assertIn("/T", forced)

    def test_ensure_closed_handles_orphaned_packaged_app_server(self) -> None:
        self.service.is_fixture = False
        self.service._codex_related_running = Mock(return_value=True)  # type: ignore[method-assign]
        self.service.request_close_codex = Mock(return_value=True)  # type: ignore[method-assign]

        self.service._ensure_codex_closed()

        self.service.request_close_codex.assert_called_once()  # type: ignore[attr-defined]

    def test_launch_uses_new_chatgpt_app_id_and_verifies_process(self) -> None:
        self.service.is_fixture = False
        self.service.codex_running = Mock(return_value=True)  # type: ignore[method-assign]
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("backend.guardian.subprocess.run", return_value=completed) as run:
            self.assertTrue(self.service.launch_codex())
        command = run.call_args.args[0]
        script = command[-1]
        self.assertIn("OpenAI.Codex_*!App", script)
        self.assertIn("@('ChatGPT','Codex')", script)
        self.assertEqual(command[:3], ["powershell.exe", "-NoProfile", "-Command"])

    def test_helper_is_copied_to_stable_versioned_path(self) -> None:
        source = Path(self.temp.name) / "zip-temp" / "CodexProfileGuardianSecret.exe"
        source.parent.mkdir()
        source.write_bytes(b"fixture-helper-v1")
        installed = self.service._install_stable_helper(source)
        self.assertEqual(installed.parent, (self.data / "bin").resolve())
        self.assertTrue(installed.name.startswith("CodexProfileGuardianSecret-"))
        self.assertEqual(installed.read_bytes(), b"fixture-helper-v1")
        source.unlink()
        self.assertEqual(self.service._install_stable_helper(source), installed)

    def test_frozen_default_helper_never_points_at_zip_temp(self) -> None:
        source = Path(self.temp.name) / "zip-temp" / "CodexProfileGuardianSecret.exe"
        source.parent.mkdir()
        source.write_bytes(b"fixture-helper-v2")
        executable = source.with_name("CodexProfileGuardian.exe")
        with patch.object(sys, "frozen", True, create=True), patch.object(
            sys, "executable", str(executable)
        ):
            service = GuardianService(codex_home=self.codex, data_dir=self.data)
        command = Path(service.helper_command[0])
        self.assertEqual(command.parent, (self.data / "bin").resolve())
        self.assertNotIn("zip-temp", str(command))


if __name__ == "__main__":
    unittest.main()
