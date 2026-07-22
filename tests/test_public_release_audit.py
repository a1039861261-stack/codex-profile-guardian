from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.public_release_audit import audit_paths


class PublicReleaseAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for relative in ("README.md", "SECURITY.md", "docs/PUBLIC-RELEASE-CHECKLIST.md"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _paths(self, *extra: str) -> list[str]:
        return ["README.md", "SECURITY.md", "docs/PUBLIC-RELEASE-CHECKLIST.md", *extra]

    def test_repository_preparation_can_explicitly_allow_missing_license(self) -> None:
        findings = audit_paths(self.root, self._paths(), require_license=False)
        self.assertEqual(findings, [])

    def test_final_audit_requires_owner_selected_license(self) -> None:
        findings = audit_paths(self.root, self._paths(), require_license=True)
        self.assertEqual([(item.code, item.path) for item in findings], [("license_missing", "LICENSE")])

    def test_reports_private_file_without_reading_its_contents(self) -> None:
        secret = self.root / "auth.json"
        secret.write_text("do-not-print", encoding="utf-8")
        findings = audit_paths(self.root, self._paths("auth.json"), require_license=False)
        self.assertEqual([(item.code, item.path, item.line) for item in findings], [("private_runtime_file", "auth.json", None)])

    def test_reports_user_path_and_private_key_by_code_and_location(self) -> None:
        sample = self.root / "sample.txt"
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        sample.write_text(
            f"cache=C:\\Users\\someone\\project\\cache\n{private_key_marker}\n",
            encoding="utf-8",
        )
        findings = audit_paths(self.root, self._paths("sample.txt"), require_license=False)
        self.assertEqual(
            [(item.code, item.path, item.line) for item in findings],
            [
                ("private_key_material", "sample.txt", 2),
                ("windows_user_path", "sample.txt", 1),
            ],
        )

    def test_allows_explicit_fixture_tokens(self) -> None:
        sample = self.root / "fixture.txt"
        sample.write_text(
            "sk-fixture-secret-value-1234567890\nBearer fixture-ingress-token-abcdefghijklmnopqrstuvwxyz\n",
            encoding="utf-8",
        )
        findings = audit_paths(self.root, self._paths("fixture.txt"), require_license=False)
        self.assertEqual(findings, [])

    def test_allows_png_assets_only_when_the_signature_is_valid(self) -> None:
        valid = self.root / "docs" / "valid.png"
        valid.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        invalid = self.root / "docs" / "invalid.png"
        invalid.write_text("not a png", encoding="utf-8")

        valid_findings = audit_paths(
            self.root, self._paths("docs/valid.png"), require_license=False
        )
        invalid_findings = audit_paths(
            self.root, self._paths("docs/invalid.png"), require_license=False
        )

        self.assertEqual(valid_findings, [])
        self.assertEqual(
            [(item.code, item.path) for item in invalid_findings],
            [("binary_asset_signature_invalid", "docs/invalid.png")],
        )

    def test_allows_ico_assets_only_when_the_signature_is_valid(self) -> None:
        valid = self.root / "assets" / "valid.ico"
        valid.parent.mkdir(parents=True)
        valid.write_bytes(b"\x00\x00\x01\x00fixture")
        invalid = self.root / "assets" / "invalid.ico"
        invalid.write_bytes(b"not-an-icon")

        self.assertEqual(
            audit_paths(self.root, self._paths("assets/valid.ico"), require_license=False),
            [],
        )
        findings = audit_paths(
            self.root, self._paths("assets/invalid.ico"), require_license=False
        )
        self.assertEqual(
            [(item.code, item.path) for item in findings],
            [("binary_asset_signature_invalid", "assets/invalid.ico")],
        )


if __name__ == "__main__":
    unittest.main()
