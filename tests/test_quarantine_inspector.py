from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "inspect-history-quarantine.ps1"
THREAD = "11111111-1111-4111-8111-111111111111"
SOURCE = "22222222-2222-4222-8222-222222222222"
CURRENT = "33333333-3333-4333-8333-333333333333"
PRIVATE_TEXT = "PRIVATE_CHAT_BODY_MUST_NOT_APPEAR"
SECRET_TEXT = "PRIVATE_SESSION_INSTRUCTIONS_MUST_NOT_APPEAR"


@unittest.skipUnless(os.name == "nt", "Windows PowerShell acceptance")
class QuarantineInspectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.codex = self.root / "codex"
        self.codex.mkdir()
        self.guardian = self.root / "guardian"
        self.batch = self.guardian / "history-conflicts" / "20260101-000001-000001-divergent-history"
        self.cold_name = "20260101-000000-000001-before-conflict-isolation"
        self.cold = self.guardian / "history-cold-backups" / self.cold_name
        self.batch.mkdir(parents=True)
        self.cold.mkdir(parents=True)
        self.relative = rf"sessions\2026\01\01\rollout-2026-01-01T00-00-00-{THREAD}_{SOURCE}.jsonl"
        self.kept_relative = rf"sessions\2026\01\01\rollout-2026-01-01T00-01-00-{THREAD}_{CURRENT}.jsonl"
        payload = {"id": THREAD, "history_mode": "paginated", "instructions": SECRET_TEXT}
        self.body = (json.dumps({"type": "session_meta", "payload": payload}) + "\n" +
                     json.dumps({"type": "response_item", "payload": PRIVATE_TEXT}) + "\n").encode()
        self.entry = {"relative": self.relative, "size": len(self.body),
                      "sha256": hashlib.sha256(self.body).hexdigest()}
        for base in [self.batch, self.cold]:
            self.write(base / "files" / self.relative, self.body)
        kept_payload = dict(payload, history_base={"thread_id": SOURCE, "end_byte_offset": len(self.body),
                                                   "end_ordinal_exclusive": 3})
        kept = (json.dumps({"type": "session_meta", "payload": kept_payload}) + "\n").encode()
        kept_entry = {"relative": self.kept_relative, "size": len(kept),
                      "sha256": hashlib.sha256(kept).hexdigest()}
        self.write(self.cold / "files" / self.kept_relative, kept)
        self.write(self.codex / self.kept_relative, kept)
        self.qm = {"schema_version": 1, "state": "complete", "cold_backup": self.cold_name,
                   "files": [self.entry], "database_rows_repointed": 1}
        self.cm = {"schema_version": 1, "name": self.cold_name, "backup_mode": "full-history-cold",
                   "codex_home": str(self.codex), "files": [self.entry, kept_entry],
                   "database": {"integrity": "ok", "thread_count": 1}}
        self.save_manifests()
        self.report = self.root / "report.json"

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def save_manifests(self):
        (self.batch / "manifest.json").write_text(json.dumps(self.qm), encoding="utf-8")
        (self.cold / "manifest.json").write_text(json.dumps(self.cm), encoding="utf-8")

    def fingerprint(self):
        return {str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for base in [self.codex, self.guardian] for path in base.rglob("*") if path.is_file()}

    def run_check(self, report=None):
        before = self.fingerprint()
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
             "-QuarantinePath", str(self.batch), "-ReportPath", str(report or self.report)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        self.assertEqual(before, self.fingerprint(), "diagnosis must not change protected fixture files")
        return result

    def read_report(self):
        raw = self.report.read_text(encoding="utf-8-sig")
        self.assertNotIn(PRIVATE_TEXT, raw)
        self.assertNotIn(SECRET_TEXT, raw)
        return json.loads(raw)

    def test_inspects_missing_source_and_paginated_dependency_without_private_content(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.read_report()
        self.assertEqual(report.get("verified_quarantine_files"), 1, report)
        self.assertEqual(report["verified_cold_files"], 1)
        self.assertEqual(report["missing_original_files"], 1)
        self.assertFalse(report["restore_ready"])
        self.assertFalse(report["database_opened"])
        self.assertEqual(report["related_current_files"][0]["current"]["history_base"]["thread_id"], SOURCE)
        self.assertEqual(report["files"][0]["quarantine"]["thread_id"], THREAD)

    def test_existing_current_file_is_only_observed(self):
        self.write(self.codex / self.relative, self.body + b"\n")
        self.assertEqual(self.run_check().returncode, 0)
        report = self.read_report()
        self.assertEqual(report.get("missing_original_files"), 0, report)
        self.assertTrue(report["files"][0]["current"]["exists"])
        self.assertNotEqual(report["files"][0]["current"]["sha256"], self.entry["sha256"])

    def test_corrupt_quarantine_does_not_pass_hash_check(self):
        self.write(self.batch / "files" / self.relative, self.body + b"\n")
        self.assertEqual(self.run_check().returncode, 0)
        report = self.read_report()
        self.assertEqual(report.get("verified_quarantine_files"), 0, report)
        self.assertEqual(report["verified_cold_files"], 1)

    def test_missing_cold_source_is_reported(self):
        (self.cold / "files" / self.relative).unlink()
        self.assertEqual(self.run_check().returncode, 0)
        report = self.read_report()
        self.assertEqual(report.get("verified_cold_files"), 0, report)

    def test_traversal_is_rejected_without_reading_outside_source_roots(self):
        self.qm["files"] = [dict(self.entry, relative=r"..\outside.jsonl")]
        self.save_manifests()
        self.assertEqual(self.run_check().returncode, 0)
        report = self.read_report()
        self.assertEqual(report.get("failed_stage"), "quarantine_files", report)
        self.assertNotIn("files", report)

    def test_incomplete_backup_is_rejected(self):
        (self.cold / "INCOMPLETE.json").write_text("{}", encoding="utf-8")
        self.assertEqual(self.run_check().returncode, 0)
        report = self.read_report()
        self.assertEqual(report.get("failed_stage"), "quarantine_manifest", report)

    def test_report_cannot_overwrite_existing_file(self):
        self.report.write_text("keep existing report", encoding="utf-8")
        self.assertNotEqual(self.run_check().returncode, 0)
        self.assertEqual(self.report.read_text(), "keep existing report")

    def test_report_cannot_be_written_inside_protected_history(self):
        target = self.codex / "not-allowed.json"
        self.assertNotEqual(self.run_check(target).returncode, 0)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
