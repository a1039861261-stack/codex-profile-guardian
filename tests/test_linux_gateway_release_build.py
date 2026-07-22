from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.build_linux_gateway_release import build


class LinuxGatewayReleaseBuildTests(unittest.TestCase):
    def test_build_uses_fixed_wrappers_and_locked_vendored_wheels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            wheels = root / "wheels"
            wheels.mkdir()
            with zipfile.ZipFile(wheels / "fixture-1.0-py3-none-any.whl", "w") as archive:
                archive.writestr("fixture_dependency/__init__.py", "MARKER = True\n")
                archive.writestr("fixture-1.0.dist-info/METADATA", "Name: fixture\nVersion: 1.0\n")
            destination = root / "release"
            result = build(destination, wheels=wheels)
            self.assertTrue(result["ok"])
            gateway = (destination / "bin" / "guardian-gateway").read_text(encoding="utf-8")
            supervisor = (destination / "bin" / "guardian-gateway-supervisor").read_text(encoding="utf-8")
            self.assertIn("/usr/bin/python3", gateway)
            self.assertIn("PYTHONNOUSERSITE=1", gateway)
            self.assertIn('GUARDIAN_RELEASE_ROOT="$RELEASE_ROOT"', supervisor)
            self.assertIn('PYTHONPATH="$RELEASE_ROOT/app:$RELEASE_ROOT/lib"', supervisor)
            self.assertTrue((destination / "lib" / "fixture_dependency" / "__init__.py").is_file())
            self.assertFalse(any(path.name == "__pycache__" for path in destination.rglob("*")))
            self.assertLess(int(result["bytes"]), 64 * 1024 * 1024)
            if os.name != "nt":
                self.assertTrue(os.access(destination / "bin" / "guardian-gateway", os.X_OK))


if __name__ == "__main__":
    unittest.main()
