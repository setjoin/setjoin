#!/usr/bin/env python3
"""Black-box CLI checks for the floor-container Rust build entry point."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

class RustCrossBuild(unittest.TestCase):
    def test_architectures_select_their_linux_gnu_target_and_floor(self):
        with tempfile.TemporaryDirectory(prefix='gofree-t12-cross-') as tmp:
            tmp = Path(tmp)
            python = tmp / 'python3'
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALL_LOG"\n')
            python.chmod(0o755)
            env = dict(os.environ, PATH=str(tmp)+os.pathsep+os.environ['PATH'], CALL_LOG=str(tmp/'log'))
            cases = [('x86_64', 'x86_64', '2.28'), ('arm64', 'aarch64', '2.28'),
                     ('loong64', 'loongarch64', '2.36')]
            for arch, target, floor in cases:
                with self.subTest(arch=arch):
                    result = subprocess.run(['bash', str(ROOT/'scripts/cross-build.sh'), '--rust', '--arch', arch], env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = (tmp/'log').read_text().splitlines()
                    self.assertEqual(args[1:], [target+'-unknown-linux-gnu', floor])
                    self.assertTrue(args[0].endswith('/scripts/build-rust-floor.py'))

    def test_unsupported_rust_smoke_fails_closed(self):
        result = subprocess.run(['bash', str(ROOT/'scripts/cross-build.sh'), '--rust', '--arch', 'loong64', '--smoke'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('smoke', result.stderr.lower())

if __name__ == '__main__':
    unittest.main()
