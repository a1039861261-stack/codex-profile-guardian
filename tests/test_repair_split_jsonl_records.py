from __future__ import annotations

import json
import unittest

from tools.repair_split_jsonl_records import logical_records, records_after_session_meta


class RepairSplitJsonlRecordsTests(unittest.TestCase):
    def test_preserves_valid_lines_and_repairs_split_control_character_record(self) -> None:
        first = b'{"type":"session_meta","payload":{"id":"fixture"}}\n'
        broken = b'{"type":"message","payload":{"text":"first\nsecond"}}\n'
        last = b'{"type":"event","payload":{"ok":true}}\n'
        records, repairs = logical_records(first + broken + last)
        self.assertEqual(records[0], first)
        self.assertEqual(records[-1], last)
        self.assertEqual(len(records), 3)
        self.assertEqual(len(repairs), 1)
        self.assertEqual(json.loads(records[1])["payload"]["text"], "first\nsecond")

    def test_rejects_unrecoverable_tail(self) -> None:
        payload = b'{"type":"session_meta","payload":{}}\n{"type":"message"'
        with self.assertRaisesRegex(RuntimeError, "repair_record_unrecoverable"):
            logical_records(payload)

    def test_requires_session_metadata_first(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "repair_session_meta_invalid"):
            logical_records(b'{"type":"message","payload":{}}\n')

    def test_duplicate_comparison_ignores_only_session_metadata(self) -> None:
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "active.jsonl"
            archived = root / "archived.jsonl"
            suffix = b'{"type":"message","payload":{"text":"fixture"}}\n'
            active.write_bytes(b'{"type":"session_meta","payload":{"archived":false}}\n' + suffix)
            archived.write_bytes(b'{"type":"session_meta","payload":{"archived":true}}\n' + suffix)
            self.assertEqual(records_after_session_meta(active), records_after_session_meta(archived))


if __name__ == "__main__":
    unittest.main()
