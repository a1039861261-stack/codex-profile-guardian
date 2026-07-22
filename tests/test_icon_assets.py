from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

from PIL import Image

from tools.generate_guardian_icon import ICON_SIZES, generate_icon
from tools.stamp_pe_icon import has_group_icon, stamp_executable_icon


class GuardianIconTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_generator_writes_multi_size_windows_icon(self) -> None:
        target = self.root / "guardian.ico"
        generate_icon(target)
        self.assertEqual(target.read_bytes()[:4], b"\x00\x00\x01\x00")
        count = struct.unpack_from("<H", target.read_bytes(), 4)[0]
        self.assertEqual(count, len(ICON_SIZES))
        with Image.open(target) as image:
            self.assertEqual(image.format, "ICO")
            self.assertIn((256, 256), image.info["sizes"])
            self.assertIn((16, 16), image.info["sizes"])

    @unittest.skipUnless(os.name == "nt", "PE resources are Windows-only")
    def test_stamper_adds_group_icon_without_overwriting_source_on_failure(self) -> None:
        icon = self.root / "guardian.ico"
        generate_icon(icon)
        executable = self.root / "python-copy.exe"
        shutil.copy2(sys.executable, executable)
        stamp_executable_icon(executable, icon)
        self.assertTrue(has_group_icon(executable))


if __name__ == "__main__":
    unittest.main()
