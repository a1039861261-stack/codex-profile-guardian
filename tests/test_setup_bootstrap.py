from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from installer import setup_bootstrap


class SetupBootstrapTests(unittest.TestCase):
    def make_payload(self, root: Path) -> dict[str, object]:
        files = []
        for name, content in (
            ("install.ps1", b"payload"),
            ("uninstall.ps1", b"payload"),
            ("VERSION", b"9.8.7"),
            ("guardian.ico", b"icon"),
        ):
            path = root / name
            path.write_bytes(content)
            files.append(
                {
                    "name": name,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest().upper(),
                }
            )
        manifest = {
            "schema_version": 1,
            "product": setup_bootstrap.PRODUCT,
            "version": "9.8.7",
            "files": files,
        }
        (root / "payload-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest

    def test_payload_identity_and_hashes_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_payload(root)
            self.assertEqual(setup_bootstrap.verify_payload(root, manifest), "9.8.7")
            manifest["product"] = "Other Product"
            with self.assertRaisesRegex(RuntimeError, "清单无效"):
                setup_bootstrap.verify_payload(root, manifest)
            manifest["product"] = setup_bootstrap.PRODUCT
            (root / "install.ps1").write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "校验失败"):
                setup_bootstrap.verify_payload(root, manifest)

    def test_duplicate_or_missing_required_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_payload(root)
            manifest["files"].append(dict(manifest["files"][0]))
            with self.assertRaisesRegex(RuntimeError, "名称无效"):
                setup_bootstrap.verify_payload(root, manifest)
            manifest = self.make_payload(root)
            manifest["files"] = [item for item in manifest["files"] if item["name"] != "guardian.ico"]
            with self.assertRaisesRegex(RuntimeError, "必要载荷缺失"):
                setup_bootstrap.verify_payload(root, manifest)

    def test_smoke_command_is_isolated_and_noninteractive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "payload"
            root.mkdir()
            smoke = Path(temporary) / "smoke"
            command = setup_bootstrap.build_install_command(root, smoke_root=smoke)
            joined = "\n".join(command)
            self.assertIn("-NoSuccessPopup", command)
            self.assertIn("-NoLaunch", command)
            self.assertIn("-SkipRegistry", command)
            self.assertIn("-SkipScheduledTask", command)
            self.assertIn(str(smoke / "install"), command)
            self.assertNotIn(str(Path.home() / "AppData" / "Local" / setup_bootstrap.PRODUCT), joined)

    def test_default_command_runs_real_transaction_without_test_overrides(self) -> None:
        root = Path("C:/fixture/payload")
        command = setup_bootstrap.build_install_command(root, smoke_root=None)
        self.assertIn(str(root / "install.ps1"), command)
        self.assertIn("-NoSuccessPopup", command)
        self.assertNotIn("-NoLaunch", command)
        self.assertNotIn("-SkipRegistry", command)
        self.assertNotIn("-SkipScheduledTask", command)

    def test_result_file_is_atomic_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            setup_bootstrap.write_result(path, {"ok": True, "version": "9.8.7"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], "9.8.7")
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_gui_smoke_does_not_get_forced_into_silent_branch(self) -> None:
        with mock.patch.object(
            setup_bootstrap,
            "parse_args",
            return_value=type(
                "Args",
                (),
                {
                    "silent": False,
                    "smoke_root": "C:/isolated",
                    "result_file": None,
                    "gui_smoke": True,
                    "auto_close": True,
                },
            )(),
        ), mock.patch.object(setup_bootstrap, "run_gui", return_value=0) as run_gui:
            self.assertEqual(setup_bootstrap.main(), 0)
            run_gui.assert_called_once()


if __name__ == "__main__":
    unittest.main()
