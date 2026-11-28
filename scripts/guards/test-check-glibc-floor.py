#!/usr/bin/env python3
"""Black-box checks for the release binary glibc floor guard."""

import subprocess
import unittest
from pathlib import Path

CHECK = Path(__file__).with_name("check-glibc-floor.py")


class GlibcFloorTest(unittest.TestCase):
    def test_accepts_binaries_within_the_floor(self):
        result = subprocess.run(
            ["python3", str(CHECK), "--floor", "999.0", "/bin/true", "/bin/false"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/bin/true", result.stdout)
        self.assertIn("/bin/false", result.stdout)

    def test_rejects_a_binary_that_requires_a_newer_glibc(self):
        result = subprocess.run(
            ["python3", str(CHECK), "--floor", "0.0", "/bin/true"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds floor", result.stderr)

    def test_rejects_missing_or_non_elf_inputs(self):
        for binary in ("/dev/null", "/this-binary-does-not-exist"):
            with self.subTest(binary=binary):
                result = subprocess.run(
                    ["python3", str(CHECK), "--floor", "2.28", binary],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("readelf failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
