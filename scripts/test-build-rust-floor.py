#!/usr/bin/env python3
"""Exercise the floor build command as an operator would run it."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'build-rust-floor.py'

class FloorBuild(unittest.TestCase):
    def test_checks_each_successfully_built_workspace_binary(self):
        with tempfile.TemporaryDirectory(prefix='gofree-t12-test-') as tmp:
            tmp = Path(tmp)
            cargo = tmp / 'cargo'
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] == 'metadata':
 print(json.dumps({'workspace_members':['p'], 'packages':[{'id':'p','targets':[{'name':'one','kind':['bin']},{'name':'two','kind':['bin']}]}]}))
else:
 for name in ('one', 'two'):
  print(json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':['bin']},'package_id':'p','executable':os.path.join(os.environ['ARTIFACT_DIR'], name)}))
''')
            cargo.chmod(0o755)
            readelf = tmp / 'readelf'
            readelf.write_text('''#!/bin/sh
printf '%s\\n' "$3" >> "$READELF_LOG"
printf 'Version needs section\\n Name: GLIBC_2.28\\n'
''')
            readelf.chmod(0o755)
            env = dict(os.environ, PATH=str(tmp)+os.pathsep+os.environ['PATH'], ARTIFACT_DIR=str(tmp), READELF_LOG=str(tmp/'log'))
            result = subprocess.run(['python3', str(SCRIPT), 'x86_64-unknown-linux-gnu', '2.28'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((tmp/'log').read_text().splitlines(), [str(tmp/'one'), str(tmp/'two')])

    def test_checks_every_reported_binary_and_rejects_missing_output(self):
        with tempfile.TemporaryDirectory(prefix='gofree-t12-test-') as tmp:
            tmp = Path(tmp)
            cargo = tmp / 'cargo'
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] == 'metadata':
 print(json.dumps({'workspace_members':['p'], 'packages':[{'id':'p','targets':[{'name':'one','kind':['bin']},{'name':'two','kind':['bin']}]}]}))
else:
 print(json.dumps({'reason':'compiler-artifact','target':{'name':'one','kind':['bin']},'package_id':'p','executable':os.environ['ARTIFACT']}))
''')
            cargo.chmod(0o755)
            artifact = tmp / 'one'
            artifact.touch()
            env = dict(os.environ, PATH=str(tmp)+os.pathsep+os.environ['PATH'], ARTIFACT=str(artifact))
            result = subprocess.run(['python3', str(SCRIPT), 'x86_64-unknown-linux-gnu', '2.28'], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('two', result.stderr)

if __name__ == '__main__':
    unittest.main()
