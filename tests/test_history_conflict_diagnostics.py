from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

import backend.guardian as guardian
from backend.guardian import GuardianError, GuardianPublicError
from backend.server import start_server
from tests import test_guardian as baseline


PRIVATE_CANARY = "PRIVATE-CONFLICT-DIAGNOSTIC-CANARY"


class HistoryConflictDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reuse only fixture lifecycle, not the baseline test class/test methods.
        with patch("backend.claude_desktop._restrict_private_path"):
            baseline.GuardianServiceTests.setUp(self)
        self.active_path.write_bytes(
            self.active_path.read_bytes()
            + b'{"type":"response_item","payload":{"marker":"keep-fixture"}}\n'
        )
        self.duplicate = self.codex / "archived_sessions" / f"duplicate-{self.active_id}.jsonl"
        self.duplicate.write_bytes(
            self.active_path.read_bytes().split(b"\n", 1)[0]
            + b'\n{"type":"response_item","payload":{"marker":"quarantine-fixture"}}\n'
        )
        (self.codex / "session_index.jsonl").write_text(
            json.dumps({"id": self.active_id, "thread_name": PRIVATE_CANARY}) + "\n",
            encoding="utf-8",
        )

    tearDown = baseline.GuardianServiceTests.tearDown

    def protected_hashes(self) -> dict[str, str]:
        return {
            path.relative_to(self.codex).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.codex.rglob("*") if path.is_file()
        }

    def events(self) -> list[dict]:
        if not self.service.logs_path.is_file():
            return []
        return [json.loads(line) for line in self.service.logs_path.read_text(encoding="utf-8").splitlines()]

    def add_trigger(self) -> None:
        with sqlite3.connect(self.codex / "state_5.sqlite") as db:
            db.execute(
                f'CREATE TRIGGER "{PRIVATE_CANARY}" AFTER UPDATE ON threads BEGIN SELECT 1; END'
            )
        db.close()

    def assert_safe_failure(self, failure: GuardianPublicError, code: str, stage: str) -> None:
        self.assertEqual(failure.code, code)
        self.assertEqual(failure.details["stage"], stage)
        events = [event for event in self.events() if event["action"] == "history.conflict_isolate"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "error")
        self.assertEqual(events[0]["details"]["code"], code)
        self.assertEqual(events[0]["details"]["diagnostic_id"], failure.details["diagnostic_id"])
        self.assertIn(code, events[0]["message"])
        public = json.dumps(
            {"message": failure.public_message, "details": failure.details, "events": events},
            ensure_ascii=False,
        )
        for private in (PRIVATE_CANARY, str(self.codex), self.active_id, "refresh-a", "keep-fixture"):
            self.assertNotIn(private, public)

    def test_trigger_block_after_cold_backup_is_visible_and_preserves_every_file(self) -> None:
        self.add_trigger()
        before = self.protected_hashes()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service.resolve_history_conflicts(confirmed=True)
        failure = raised.exception
        self.assert_safe_failure(failure, "history_conflict_database_triggers_present", "database_preflight")
        self.assertTrue(failure.details["cold_backup_complete"])
        self.assertFalse(failure.details["history_writes_started"])
        self.assertIn("threads 触发器", failure.public_message)
        self.assertEqual(self.protected_hashes(), before)
        cold = list(self.service.history_cold_backups_dir.iterdir())
        self.assertEqual(len(cold), 1)
        self.assertTrue((cold[0] / "manifest.json").is_file())
        self.assertFalse(any(event["status"] == "success" and event["action"] == "history.conflict_isolate" for event in self.events()))

    def test_missing_required_column_reports_schema_error_after_backup(self) -> None:
        with sqlite3.connect(self.codex / "state_5.sqlite") as db:
            db.execute("ALTER TABLE threads DROP COLUMN model_provider")
        db.close()
        before = self.protected_hashes()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "history_conflict_database_schema_incompatible", "database_preflight")
        self.assertTrue(raised.exception.details["cold_backup_complete"])
        self.assertEqual(self.protected_hashes(), before)

    def test_integrity_failure_after_successful_backup_is_not_generic(self) -> None:
        original_backup = self.service.create_history_cold_backup
        original_connect = sqlite3.connect
        backup_done = False

        class Connection:
            def __init__(self, inner):
                self.inner = inner

            def execute(self, sql, *args):
                if sql == "PRAGMA integrity_check":
                    class Cursor:
                        def fetchone(self):
                            return (PRIVATE_CANARY,)
                    return Cursor()
                return self.inner.execute(sql, *args)

            def set_authorizer(self, callback):
                self.inner.set_authorizer(callback)

            def close(self):
                self.inner.close()

        def backup(*args, **kwargs):
            nonlocal backup_done
            result = original_backup(*args, **kwargs)
            backup_done = True
            return result

        def connect(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            if backup_done and kwargs.get("uri"):
                return Connection(connection)
            return connection

        before = self.protected_hashes()
        with patch.object(self.service, "create_history_cold_backup", side_effect=backup):
            with patch.object(guardian.sqlite3, "connect", side_effect=connect):
                with self.assertRaises(GuardianPublicError) as raised:
                    self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "history_conflict_database_integrity_failed", "database_preflight")
        self.assertEqual(self.protected_hashes(), before)

    def test_cold_backup_permission_failure_redacts_paths_and_raw_exception(self) -> None:
        before = self.protected_hashes()
        with patch.object(self.service, "create_history_cold_backup", side_effect=PermissionError(PRIVATE_CANARY)):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "history_conflict_permission_denied", "cold_backup")
        self.assertFalse(raised.exception.details["cold_backup_complete"])
        self.assertFalse(raised.exception.details["history_writes_started"])
        self.assertEqual(self.protected_hashes(), before)

    def test_unknown_database_preflight_failure_is_stage_specific_and_private(self) -> None:
        original_backup = self.service.create_history_cold_backup
        original_connect = sqlite3.connect
        backup_done = False

        def backup(*args, **kwargs):
            nonlocal backup_done
            result = original_backup(*args, **kwargs)
            backup_done = True
            return result

        def connect(*args, **kwargs):
            if backup_done and kwargs.get("uri"):
                raise RuntimeError(PRIVATE_CANARY)
            return original_connect(*args, **kwargs)

        before = self.protected_hashes()
        with patch.object(self.service, "create_history_cold_backup", side_effect=backup):
            with patch.object(guardian.sqlite3, "connect", side_effect=connect):
                with self.assertRaises(GuardianPublicError) as raised:
                    self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "history_conflict_database_preflight_failed", "database_preflight")
        self.assertEqual(self.protected_hashes(), before)

    def fail_verification(self):
        original_inventory = self.service._rollout_inventory
        calls = 0

        def inventory(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError(PRIVATE_CANARY)
            return original_inventory(*args, **kwargs)

        return patch.object(self.service, "_rollout_inventory", side_effect=inventory)

    def test_late_failure_retains_rollback_and_one_safe_audit_event(self) -> None:
        before = self.protected_hashes()
        with self.fail_verification():
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "history_conflict_verification_failed", "verification")
        self.assertTrue(raised.exception.details["history_writes_started"])
        self.assertEqual(raised.exception.details["recovery"], "restored")
        self.assertFalse(raised.exception.details["history_result_verified"])
        self.assertEqual(self.protected_hashes(), before)

    def test_rollback_failure_requires_manual_recovery_and_keeps_backups(self) -> None:
        original_copy = guardian.shutil.copy2

        def copy(source, destination, *args, **kwargs):
            if self.service.history_conflicts_dir in Path(source).parents:
                raise PermissionError(PRIVATE_CANARY)
            return original_copy(source, destination, *args, **kwargs)

        with self.fail_verification():
            with patch.object(guardian.shutil, "copy2", side_effect=copy):
                with self.assertRaises(GuardianPublicError) as raised:
                    self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "history_conflict_rollback_incomplete", "verification")
        self.assertEqual(raised.exception.details["recovery"], "incomplete")
        self.assertFalse(raised.exception.retryable)
        self.assertIn("保持 Codex 关闭", raised.exception.public_message)
        self.assertTrue(self.active_path.is_file())
        self.assertEqual(len(list(self.service.history_cold_backups_dir.iterdir())), 1)
        quarantine = next(self.service.history_conflicts_dir.iterdir())
        self.assertTrue(json.loads((quarantine / "INCOMPLETE.json").read_text())["restore_failed"])

    def test_audit_write_failure_does_not_mask_trigger_diagnosis(self) -> None:
        self.add_trigger()
        original_log = self.service._log

        def log(action, *args, **kwargs):
            if action == "history.conflict_isolate":
                raise PermissionError(PRIVATE_CANARY)
            return original_log(action, *args, **kwargs)

        before = self.protected_hashes()
        with patch.object(self.service, "_log", side_effect=log):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(confirmed=True)
        self.assertEqual(raised.exception.code, "history_conflict_database_triggers_present")
        self.assertFalse(raised.exception.details["audit_log_written"])
        self.assertIn("操作日志写入失败", raised.exception.public_message)
        self.assertNotIn(PRIVATE_CANARY, raised.exception.public_message)
        self.assertEqual(self.protected_hashes(), before)

    def test_success_audit_failure_does_not_claim_the_verified_repair_was_rolled_back(self) -> None:
        original_log = self.service._log

        def log(action, *args, **kwargs):
            if action == "history.conflict_isolate":
                raise PermissionError(PRIVATE_CANARY)
            return original_log(action, *args, **kwargs)

        with patch.object(self.service, "_log", side_effect=log):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(confirmed=True)
        failure = raised.exception
        self.assertEqual(failure.code, "history_conflict_result_record_failed")
        self.assertTrue(failure.details["history_result_verified"])
        self.assertEqual(failure.details["recovery"], "not_needed")
        self.assertFalse(failure.retryable)
        self.assertIn("不要重复处理", failure.public_message)
        self.assertNotIn("已尝试恢复", failure.public_message)
        self.assertNotIn("未移动聊天", failure.public_message)
        self.assertFalse(self.duplicate.exists())
        self.assertTrue(self.active_path.is_file())

    def test_active_turn_guard_remains_fail_closed_with_public_reason(self) -> None:
        before = self.protected_hashes()
        with patch.object(
            self.service, "_ensure_codex_closed",
            side_effect=GuardianPublicError("codex_active_turn", "检测到活动任务。", details={"active_count": 1}),
        ):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(confirmed=True)
        self.assert_safe_failure(raised.exception, "codex_active_turn", "codex_close")
        self.assertEqual(raised.exception.details["active_count"], 1)
        self.assertEqual(self.protected_hashes(), before)
        self.assertEqual(list(self.service.history_cold_backups_dir.iterdir()), [])

    def test_invalid_selection_is_logged_before_backup_and_ids_are_per_attempt(self) -> None:
        diagnostic_ids = []
        for _ in range(2):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(confirmed=True, selections=[{"private": PRIVATE_CANARY}])
            self.assertEqual(raised.exception.code, "history_conflict_selection_invalid")
            self.assertEqual(raised.exception.details["stage"], "validation")
            diagnostic_ids.append(raised.exception.details["diagnostic_id"])
        self.assertNotEqual(*diagnostic_ids)
        self.assertNotIn(PRIVATE_CANARY, json.dumps(self.events()))
        self.assertEqual(list(self.service.history_cold_backups_dir.iterdir()), [])

    def test_real_management_http_returns_trigger_reason_and_safe_progress(self) -> None:
        self.add_trigger()
        web_root = self.data / "fixture-web"
        web_root.mkdir()
        (web_root / "index.html").write_text("<title>isolated fixture</title>")
        server = start_server(self.service, web_root, "127.0.0.1", 0)
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=15)
            connection.request("GET", "/api/session")
            response = connection.getresponse()
            response.read()
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            connection.request(
                "POST", "/api/protection/conflicts/isolate",
                body=json.dumps({"confirm": True}),
                headers={"Cookie": cookie, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 409)
            self.assertEqual(payload["error"]["code"], "history_conflict_database_triggers_present")
            self.assertIn("threads 触发器", payload["error"]["message"])
            self.assertNotIn("请求未完成", payload["error"]["message"])
            self.assertTrue(payload["error"]["details"]["cold_backup_complete"])
            self.assertFalse(payload["error"]["details"]["history_writes_started"])
            self.assertNotIn(PRIVATE_CANARY, json.dumps(payload))
            connection.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
