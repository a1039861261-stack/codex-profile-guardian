from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from backend.guardian import GuardianPublicError
from tests import test_guardian as baseline


class PaginatedHistoryTests(unittest.TestCase):
    def setUp(self):
        with patch("backend.claude_desktop._restrict_private_path"):
            baseline.GuardianServiceTests.setUp(self)
        self.original = self.active_path.with_name(
            "rollout-2026-09-06T00-00-00-" + self.active_id + ".jsonl"
        )
        self.active_path.rename(self.original)
        self.source_id = self.active_id
        self.replacement_id = "11111111-2222-7333-8444-555555555555"
        self.current = self.original.with_name(
            "rollout-2026-09-06T00-01-00-" + self.active_id + "_" + self.replacement_id + ".jsonl"
        )
        self.write_rollout(self.original)
        source_lines = self.original.read_bytes().splitlines(keepends=True)
        self.base = {
            "thread_id": self.source_id,
            "end_ordinal_exclusive": 2,
            "end_byte_offset": sum(map(len, source_lines[:2])),
        }
        self.write_rollout(self.current, self.base)
        self.active_path = self.current
        with sqlite3.connect(self.codex / "state_5.sqlite") as db:
            db.execute("ALTER TABLE threads ADD COLUMN history_mode TEXT DEFAULT 'legacy'")
            db.execute(
                "UPDATE threads SET rollout_path=?, history_mode='paginated' WHERE id=?",
                (str(self.current), self.active_id),
            )
        db.close()

    tearDown = baseline.GuardianServiceTests.tearDown

    def write_rollout(self, path, base=None, *, padding=512, thread_id=None):
        meta = {
            "type": "session_meta", "ordinal": base["end_ordinal_exclusive"] if base else 0,
            "payload": {
                "id": thread_id or self.active_id, "session_id": self.active_id,
                "model_provider": "openai", "history_mode": "paginated",
            },
        }
        if base:
            meta["payload"]["history_base"] = base
        first = json.dumps(meta, separators=(",", ":")).encode() + b" " * padding + b"\n"
        ordinal = meta["ordinal"]
        body = b"".join(
            json.dumps({
                "type": "event_msg", "ordinal": ordinal + offset,
                "payload": {"type": "shutdown_complete"},
            }, separators=(",", ":")).encode() + b"\n"
            for offset in (1, 2)
        )
        path.write_bytes(first + body)

    def hashes(self):
        return {
            p.relative_to(self.codex).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.codex.rglob("*") if p.is_file()
        }

    def rows(self):
        db = sqlite3.connect(self.codex / "state_5.sqlite")
        try:
            return list(db.execute("SELECT id, archived, rollout_path, history_mode FROM threads ORDER BY id"))
        finally:
            db.close()

    def history_body(self):
        # Independent fixture oracle follows the canonical filename's immutable
        # rollout ID and decoded byte cutoff, not Guardian's grouping algorithm.
        def read(path, seen):
            lines = path.read_bytes().splitlines(keepends=True)
            meta = json.loads(lines[0])["payload"]
            base = meta.get("history_base")
            prefix = []
            if base:
                wanted = base["thread_id"]
                self.assertNotIn(wanted, seen)
                seen = seen | {wanted}
                choices = [p for p in self.codex.rglob("rollout-*.jsonl")
                           if p.stem.rsplit("_", 1)[-1].endswith(wanted)]
                self.assertEqual(len(choices), 1)
                source = choices[0]
                data = source.read_bytes()[:base["end_byte_offset"]]
                self.assertTrue(data.endswith(b"\n"))
                source_items = [json.loads(line) for line in data.splitlines()]
                self.assertTrue(all(item["ordinal"] < base["end_ordinal_exclusive"] for item in source_items))
                prefix = [item for item in source_items if item["type"] != "session_meta"]
            return prefix + [json.loads(line) for line in lines[1:]]
        return read(self.current, set())

    def test_revert_rollouts_are_not_conflicts_and_isolation_keeps_every_file(self):
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertEqual(report["divergent_duplicate_id_count"], 0)
        self.assertTrue(report["lineage"]["ready"])
        self.assertEqual(report["lineage"]["protected_rollout_count"], 2)
        self.assertFalse(report["can_isolate"])
        self.assertEqual(self.service.resolve_history_conflicts(confirmed=True)["resolved"], 0)
        self.assertEqual(self.hashes(), before)
        self.assertEqual(list(self.service.history_conflicts_dir.iterdir()), [])

    def test_switch_to_api_then_official_preserves_lineage_bytes_and_sidebar(self):
        official = self.service.capture_official("Fixture Official")
        api = self.service.create_api_profile("Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-test")
        index = self.codex / "session_index.jsonl"
        index.write_bytes(b'{"id":"fixture-index","thread_name":"untouched"}\n')
        original_rows = self.rows()
        expected_history = self.history_body()
        offsets = {p: len(p.read_bytes().splitlines(keepends=True)[0]) for p in (self.original, self.current)}
        for profile in (api, official):
            result = self.service.switch_profile(profile["id"])
            self.assertTrue(result["migration"]["archive_preserved"])
            self.assertEqual(self.rows(), original_rows)
            self.assertEqual(self.history_body(), expected_history)
            self.assertEqual(index.read_bytes(), b'{"id":"fixture-index","thread_name":"untouched"}\n')
            for path, size in offsets.items():
                self.assertTrue(path.is_file())
                self.assertEqual(len(path.read_bytes().splitlines(keepends=True)[0]), size)
            self.assertTrue(self.service.history_conflict_report()["lineage"]["ready"])

    def test_missing_ancestor_blocks_switch_before_backup_and_redacts_metadata(self):
        profile = self.service.capture_official("Fixture Official")
        self.original.unlink()
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertEqual(report["lineage"]["issue_counts"]["missing_source_rollout"], 1)
        self.assertFalse(report["safe_to_switch"])
        self.assertFalse(self.service.status()["health"]["safe"])
        with patch.object(self.service, "create_backup") as backup:
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.switch_profile(profile["id"])
        backup.assert_not_called()
        self.assertEqual(raised.exception.code, "history_lineage_invalid")
        self.assertEqual(self.hashes(), before)
        public = json.dumps(raised.exception.details)
        for private in (self.active_id, str(self.codex), "refresh-a"):
            self.assertNotIn(private, public)

    def test_missing_ancestor_blocks_isolation_even_if_unrelated_legacy_conflict_exists(self):
        self.original.unlink()
        extra = self.archived_path.with_name("duplicate-legacy.jsonl")
        extra.write_bytes(self.archived_path.read_bytes() + b'{"type":"event_msg","payload":{"type":"shutdown_complete"}}\n')
        before = self.hashes()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service.resolve_history_conflicts(confirmed=True)
        self.assertEqual(raised.exception.code, "history_lineage_invalid")
        self.assertEqual(self.hashes(), before)
        self.assertFalse(raised.exception.details["history_writes_started"])

    def test_missing_current_path_does_not_fall_back_to_old_same_thread_file(self):
        self.current.unlink()
        report = self.service.history_conflict_report()
        self.assertEqual(report["lineage"]["issue_counts"]["missing_current_rollout"], 1)
        self.assertFalse(report["safe_to_switch"])
        before = self.hashes()
        with self.assertRaises(GuardianPublicError):
            self.service.repair_visibility()
        self.assertEqual(self.hashes(), before)

    def test_archived_source_can_remain_shared_with_active_current_rollout(self):
        destination = self.codex / "archived_sessions" / self.original.name
        self.original.rename(destination)
        self.original = destination
        report = self.service.history_conflict_report()
        self.assertTrue(report["lineage"]["ready"])
        self.assertEqual(report["divergent_duplicate_id_count"], 0)
        self.assertEqual(len(self.history_body()), 3)

    def test_provider_growth_is_refused_before_any_write(self):
        api = self.service.create_api_profile("Fixture API", "http://127.0.0.1:8317/v1", "secret-key", "gpt-test")
        self.write_rollout(self.current, self.base, padding=0)
        before = self.hashes()
        with patch.object(self.service, "create_backup") as backup:
            with self.assertRaises(GuardianPublicError) as raised:
                self.service.switch_profile(api["id"])
        backup.assert_not_called()
        self.assertEqual(raised.exception.code, "history_lineage_header_growth")
        self.assertEqual(self.hashes(), before)

    def test_compressed_rollouts_are_not_silently_ignored_or_rewritten(self):
        compressed = self.current.with_suffix(".jsonl.zst")
        compressed.write_bytes(b"fixture compressed bytes")
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertFalse(report["safe_to_switch"])
        self.assertEqual(report["lineage"]["compressed_rollout_count"], 1)
        with self.assertRaises(GuardianPublicError):
            self.service.repair_visibility()
        self.assertEqual(self.hashes(), before)

    def test_cycle_and_out_of_bounds_sources_are_rejected(self):
        self.write_rollout(self.original, {
            "thread_id": self.replacement_id, "end_ordinal_exclusive": 1, "end_byte_offset": 0,
        })
        self.assertIn("lineage_cycle", self.service.history_conflict_report()["lineage"]["issue_counts"])
        self.write_rollout(self.original)
        self.write_rollout(self.current, {**self.base, "end_byte_offset": 999999})
        self.assertIn("source_offset_out_of_bounds", self.service.history_conflict_report()["lineage"]["issue_counts"])

    def test_startup_provider_match_does_not_hide_missing_lineage(self):
        self.original.unlink()
        with self.assertRaises(GuardianPublicError) as raised:
            self.service._verify_history_provider("openai")
        self.assertEqual(raised.exception.code, "history_lineage_invalid")

    def test_restoring_exact_source_fixture_recovers_lineage_without_database_changes(self):
        original = self.original.read_bytes()
        rows = self.rows()
        expected = self.history_body()
        self.original.unlink()
        self.assertFalse(self.service.history_conflict_report()["lineage"]["ready"])
        # Fixture-only demonstration; production code never restores automatically.
        self.original.write_bytes(original)
        self.assertTrue(self.service.history_conflict_report()["lineage"]["ready"])
        self.assertEqual(self.rows(), rows)
        self.assertEqual(self.history_body(), expected)

    def test_ambiguous_sources_are_preserved_and_refused(self):
        duplicate = self.codex / "archived_sessions" / self.original.name
        duplicate.write_bytes(self.original.read_bytes())
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertIn("ambiguous_source_rollout", report["lineage"]["issue_counts"])
        self.assertFalse(report["can_isolate"])
        with self.assertRaises(GuardianPublicError):
            self.service.resolve_history_conflicts(confirmed=True)
        self.assertEqual(self.hashes(), before)

    def test_malformed_base_is_blocked_without_exposing_or_mutating_data(self):
        lines = self.current.read_bytes().splitlines(keepends=True)
        item = json.loads(lines[0])
        item["payload"]["history_base"] = {"thread_id": "PRIVATE-invalid-source", "end_byte_offset": True}
        self.current.write_bytes(json.dumps(item).encode() + b"\n" + b"".join(lines[1:]))
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertIn("invalid_history_base", report["lineage"]["issue_counts"])
        self.assertNotIn("PRIVATE-invalid-source", json.dumps(report["lineage"]))
        self.assertFalse(report["can_isolate"])
        self.assertEqual(self.hashes(), before)


    def set_current_reference(self, path):
        with sqlite3.connect(self.codex / "state_5.sqlite") as db:
            db.execute("UPDATE threads SET rollout_path=? WHERE id=?", (str(path), self.active_id))
        db.close()

    @unittest.skipUnless(os.name == "nt", "Windows extended path regression")
    def test_extended_windows_current_path_switch_preserves_raw_reference_and_history(self):
        extended = Path("\\\\?\\" + str(self.current))
        self.assertTrue(extended.samefile(self.current))
        self.set_current_reference(extended)
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertTrue(report["safe_to_switch"], report["lineage"])
        self.assertEqual(self.hashes(), before)
        self.test_switch_to_api_then_official_preserves_lineage_bytes_and_sidebar()
        self.assertEqual(next(row[2] for row in self.rows() if row[0] == self.active_id), str(extended))

    @unittest.skipUnless(os.name == "nt", "Windows extended path regression")
    def test_extended_windows_original_rollout_is_not_a_missing_current_file(self):
        self.set_current_reference(Path("\\\\?\\" + str(self.original)))
        before = self.hashes()
        self.assertTrue(self.service.history_conflict_report()["safe_to_switch"])
        self.assertEqual(self.hashes(), before)

    @unittest.skipUnless(os.name == "nt", "Windows extended path regression")
    def test_extended_missing_current_still_refuses_older_same_thread_rollout(self):
        self.set_current_reference(Path("\\\\?\\" + str(self.current)))
        self.test_missing_current_path_does_not_fall_back_to_old_same_thread_file()

    @unittest.skipUnless(os.name == "nt", "Windows extended path regression")
    def test_extended_current_archive_mismatch_still_blocks(self):
        self.set_current_reference(Path("\\\\?\\" + str(self.current)))
        with sqlite3.connect(self.codex / "state_5.sqlite") as db:
            db.execute("UPDATE threads SET archived=1 WHERE id=?", (self.active_id,))
        db.close()
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertFalse(report["safe_to_switch"])
        self.assertEqual(report["lineage"]["issue_counts"]["current_archive_mismatch"], 1)
        self.assertEqual(self.hashes(), before)

    @unittest.skipUnless(os.name == "nt", "Windows extended path regression")
    def test_different_file_with_identical_bytes_is_not_a_path_alias(self):
        outside = self.data / self.current.name
        outside.write_bytes(self.current.read_bytes())
        self.set_current_reference(Path("\\\\?\\" + str(outside)))
        before = self.hashes()
        report = self.service.history_conflict_report()
        self.assertFalse(report["safe_to_switch"])
        self.assertEqual(report["lineage"]["issue_counts"]["missing_current_rollout"], 1)
        self.assertEqual(self.hashes(), before)

    @unittest.skipUnless(os.name == "nt", "Windows extended path regression")
    def test_unverifiable_path_alias_keeps_switch_blocked(self):
        self.set_current_reference(Path("\\\\?\\" + str(self.current)))
        before = self.hashes()
        with patch.object(Path, "samefile", side_effect=PermissionError("fixture denied")):
            report = self.service.history_conflict_report()
        self.assertFalse(report["safe_to_switch"])
        self.assertEqual(report["lineage"]["issue_counts"]["missing_current_rollout"], 1)
        self.assertEqual(self.hashes(), before)
