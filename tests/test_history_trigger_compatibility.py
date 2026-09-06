from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

import backend.guardian as guardian
from backend.guardian import GuardianError, GuardianPublicError
from tests import test_history_conflict_diagnostics as diagnostic


MIGRATIONS = Path(__file__).parent / "fixtures" / "codex-state-migrations"


class HistoryTriggerCompatibilityTests(unittest.TestCase):
    tearDown = diagnostic.HistoryConflictDiagnosticsTests.tearDown
    protected_hashes = diagnostic.HistoryConflictDiagnosticsTests.protected_hashes
    events = diagnostic.HistoryConflictDiagnosticsTests.events
    assert_safe_failure = diagnostic.HistoryConflictDiagnosticsTests.assert_safe_failure

    def setUp(self) -> None:
        diagnostic.HistoryConflictDiagnosticsTests.setUp(self)
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            # Adapt the old synthetic table, then execute the unmodified,
            # commit-pinned official migrations, including their indexes.
            connection.execute("ALTER TABLE threads DROP COLUMN created_at_ms")
            connection.execute("ALTER TABLE threads ADD COLUMN preview TEXT NOT NULL DEFAULT ''")
            connection.execute("UPDATE threads SET created_at=1770000000, updated_at=1770001000")
            for name in ("0025_thread_timestamps_millis.sql", "0039_threads_recency_at.sql"):
                connection.executescript((MIGRATIONS / name).read_text(encoding="utf-8"))
            connection.execute("CREATE TABLE fixture_effects (value TEXT)")
            connection.commit()
        finally:
            connection.close()

    def snapshot(self, database=None) -> dict:
        connection = sqlite3.connect(
            f"file:{Path(database or self.codex / 'state_5.sqlite').as_posix()}?mode=ro", uri=True,
        )
        try:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(threads)")]
            return {
                "rows": [dict(zip(columns, row)) for row in connection.execute("SELECT * FROM threads ORDER BY id")],
                "schema": list(connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
                )),
                "effects": list(connection.execute("SELECT * FROM fixture_effects")),
                "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
            }
        finally:
            connection.close()

    def non_database_hashes(self) -> dict:
        return {name: digest for name, digest in self.protected_hashes().items()
                if not Path(name).name.startswith("state_5.sqlite")}

    def manual_request(self) -> dict:
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            connection.execute(
                "UPDATE threads SET rollout_path=? WHERE id=?",
                (str(self.codex / "sessions" / "missing-fixture.jsonl"), self.active_id),
            )
            connection.commit()
        finally:
            connection.close()
        report = self.service.history_conflict_report()
        conflict = report["conflicts"][0]
        chosen = next(copy for copy in conflict["copies"] if copy["location"] == "archived")
        return {
            "confirmed": True,
            "report_revision": report["report_revision"],
            "selections": [{"conflict_ref": conflict["conflict_ref"], "keep_copy_ref": chosen["copy_ref"]}],
        }

    def add_affecting_trigger(self, event="AFTER UPDATE OF archived, rollout_path", body=None) -> None:
        body = body or "INSERT INTO fixture_effects VALUES ('fixture-effect');"
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            connection.execute(f'CREATE TRIGGER "fixture-sensitive-trigger" {event} ON threads BEGIN {body} END')
            connection.commit()
        finally:
            connection.close()

    def assert_success_preserved(self, before: dict, result: dict, changed: bool) -> None:
        expected_rows = [dict(row) for row in before["rows"]]
        if changed:
            row = next(row for row in expected_rows if row["id"] == self.active_id)
            row["archived"] = 1
            row["rollout_path"] = str(self.duplicate)
        after = self.snapshot()
        self.assertEqual(after["rows"], expected_rows)
        self.assertEqual(after["schema"], before["schema"])
        self.assertEqual(after["effects"], [])
        self.assertEqual(after["integrity"], "ok")
        self.assertEqual(result["database_rows_repointed"], int(changed))
        self.assertEqual(result["database_unchanged"], not changed)
        self.assertTrue(result["all_original_copies_recoverable"])
        self.assertEqual(
            self.snapshot(Path(result["cold_backup"]["path"]) / "database-logical.sqlite"), before,
        )

    def test_official_triggers_allow_automatic_isolation_without_database_writes(self) -> None:
        before = self.snapshot()
        hashes = self.protected_hashes()
        result = self.service.resolve_history_conflicts(confirmed=True)
        self.assert_success_preserved(before, result, changed=False)
        self.assertEqual(self.protected_hashes(), {
            path: digest for path, digest in hashes.items()
            if path != self.duplicate.relative_to(self.codex).as_posix()
        })

    def test_official_triggers_allow_manual_repoint_and_preserve_every_other_column(self) -> None:
        request = self.manual_request()
        before = self.snapshot()
        hashes = self.non_database_hashes()
        result = self.service.resolve_history_conflicts(**request)
        self.assert_success_preserved(before, result, changed=True)
        self.assertEqual(self.non_database_hashes(), {
            path: digest for path, digest in hashes.items()
            if path != self.active_path.relative_to(self.codex).as_posix()
        })
        for path, digest in hashes.items():
            if path.endswith(".jsonl"):
                backup = Path(result["cold_backup"]["path"]) / "files" / path
                self.assertEqual(hashlib.sha256(backup.read_bytes()).hexdigest(), digest)

    def test_retained_official_timestamp_trigger_still_operates_after_repair(self) -> None:
        self.service.resolve_history_conflicts(confirmed=True)
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            connection.execute("UPDATE threads SET updated_at=1770001234 WHERE id=?", (self.active_id,))
            updated_ms = connection.execute(
                "SELECT updated_at_ms FROM threads WHERE id=?", (self.active_id,),
            ).fetchone()[0]
            self.assertEqual(updated_ms, 1770001234000)
        finally:
            connection.close()

    def test_official_triggers_allow_verified_late_rollback(self) -> None:
        request = self.manual_request()
        before = self.snapshot()
        hashes = self.non_database_hashes()
        original = guardian.atomic_json

        def fail_completion(path, payload):
            if Path(path).name == "manifest.json" and payload.get("state") == "complete":
                raise RuntimeError(diagnostic.PRIVATE_CANARY)
            return original(path, payload)

        with patch.object(guardian, "atomic_json", side_effect=fail_completion):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(**request)
        self.assertEqual(raised.exception.details["recovery"], "restored")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.non_database_hashes(), hashes)

    def test_path_trigger_is_rejected_before_any_move_or_update(self) -> None:
        request = self.manual_request()
        self.add_affecting_trigger()
        hashes = self.protected_hashes()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service.resolve_history_conflicts(**request)
        self.assert_safe_failure(raised.exception, "history_conflict_database_triggers_present", "database_preflight")
        self.assertEqual(self.protected_hashes(), hashes)
        self.assertEqual(self.snapshot()["effects"], [])
        self.assertTrue(raised.exception.details["cold_backup_complete"])

    def test_trigger_with_official_name_but_changed_event_is_rejected(self) -> None:
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            connection.executescript(
                "DROP TRIGGER threads_created_at_ms_after_update;"
                "CREATE TRIGGER threads_created_at_ms_after_update AFTER UPDATE OF archived ON threads "
                "BEGIN UPDATE threads SET title='fixture-spoof' WHERE id=NEW.id; END;"
            )
        finally:
            connection.close()
        hashes = self.protected_hashes()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service.resolve_history_conflicts(confirmed=True)
        self.assertEqual(raised.exception.code, "history_conflict_database_triggers_present")
        self.assertEqual(self.protected_hashes(), hashes)

    def test_unconditional_before_trigger_with_no_writes_is_still_rejected(self) -> None:
        self.add_affecting_trigger(event="BEFORE UPDATE", body="SELECT 1;")
        hashes = self.protected_hashes()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service.resolve_history_conflicts(confirmed=True)
        self.assertEqual(raised.exception.code, "history_conflict_database_triggers_present")
        self.assertEqual(self.protected_hashes(), hashes)

    def test_quoted_unrelated_event_trigger_is_retained_without_name_allowlist(self) -> None:
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            connection.execute(
                'CREATE TRIGGER "fixture "" quoted trigger" AFTER UPDATE OF "title" ON "threads" '
                "BEGIN INSERT INTO fixture_effects VALUES ('unrelated-fixture'); END"
            )
            connection.commit()
        finally:
            connection.close()
        request = self.manual_request()
        before = self.snapshot()
        result = self.service.resolve_history_conflicts(**request)
        self.assert_success_preserved(before, result, changed=True)

    def test_trigger_added_after_preflight_is_blocked_by_the_write_connection(self) -> None:
        request = self.manual_request()
        before = self.snapshot()
        hashes = self.non_database_hashes()
        original = self.service._copy_verified_history_file
        added = False

        def copy(source, destination, **kwargs):
            nonlocal added
            result = original(source, destination, **kwargs)
            if not added and self.service.history_conflicts_dir in Path(destination).parents:
                self.add_affecting_trigger()
                added = True
            return result

        with patch.object(self.service, "_copy_verified_history_file", side_effect=copy):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(**request)
        failure = raised.exception
        self.assertTrue(added)
        self.assertEqual(failure.code, "history_conflict_database_triggers_present")
        self.assertEqual(failure.details["stage"], "database_update")
        self.assertEqual(failure.details["recovery"], "restored")
        self.assertEqual(self.snapshot()["rows"], before["rows"])
        self.assertEqual(self.snapshot()["effects"], [])
        self.assertEqual(self.non_database_hashes(), hashes)

    def test_trigger_added_before_rollback_cannot_run_and_reports_incomplete_recovery(self) -> None:
        request = self.manual_request()
        hashes = self.non_database_hashes()
        original = guardian.atomic_json

        def fail_completion(path, payload):
            if Path(path).name == "manifest.json" and payload.get("state") == "complete":
                self.add_affecting_trigger()
                raise RuntimeError(diagnostic.PRIVATE_CANARY)
            return original(path, payload)

        with patch.object(guardian, "atomic_json", side_effect=fail_completion):
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.resolve_history_conflicts(**request)
        self.assertEqual(raised.exception.code, "history_conflict_rollback_incomplete")
        self.assertEqual(raised.exception.details["recovery"], "incomplete")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(self.snapshot()["effects"], [])
        self.assertEqual(self.non_database_hashes(), hashes)
        self.assertEqual(len(list(self.service.history_cold_backups_dir.iterdir())), 1)

    def test_read_only_explain_never_updates_rows_or_calls_trigger_functions(self) -> None:
        database = self.codex / "state_5.sqlite"
        self.add_affecting_trigger(body="SELECT fixture_function(NEW.id);")
        before = self.protected_hashes()
        called = []
        connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
        connection.create_function("fixture_function", 1, lambda value: called.append(value))
        try:
            with self.assertRaises(GuardianError):
                with guardian._guard_history_conflict_sql(connection):
                    connection.execute(
                        "EXPLAIN " + guardian.HISTORY_CONFLICT_UPDATE_SQL,
                        (1, str(self.duplicate), self.active_id, 0, str(self.active_path)),
                    ).fetchall()
            self.assertEqual(called, [])
            self.assertEqual(connection.total_changes, 0)
        finally:
            connection.close()
        self.assertEqual(self.protected_hashes(), before)

    def test_authorizer_rejects_schema_change_and_is_removed_after_failure(self) -> None:
        connection = sqlite3.connect(self.codex / "state_5.sqlite")
        parameters = (0, str(self.active_path), self.active_id, 0, str(self.active_path))
        try:
            # Prepare/cache the actual statement before a schema change.
            connection.execute(guardian.HISTORY_CONFLICT_UPDATE_SQL, parameters)
            connection.commit()
            connection.execute(
                "CREATE TRIGGER fixture_cached AFTER UPDATE ON threads "
                "BEGIN INSERT INTO fixture_effects VALUES ('cache-fixture'); END"
            )
            with self.assertRaises(GuardianError):
                with guardian._guard_history_conflict_sql(connection):
                    connection.execute(guardian.HISTORY_CONFLICT_UPDATE_SQL, parameters)
            connection.rollback()
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM fixture_effects").fetchone()[0], 0)
            # The callback does not leak beyond its owned connection scope.
            connection.execute(guardian.HISTORY_CONFLICT_UPDATE_SQL, parameters)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM fixture_effects").fetchone()[0], 1)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
