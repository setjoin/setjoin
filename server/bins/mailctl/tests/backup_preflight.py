"""Exercise oracle preflight at its subprocess/PostgreSQL-tool boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
DEFAULT_DSN = "postgres://fixture@127.0.0.1:55451/gofree_preflight_test"
ROUNDTRIP_DSN = "postgres://fixture@127.0.0.1:55452/gofree_preflight_test"


class BackupPreflight(unittest.TestCase):
    def invoke(self, settings, override=None, case="roundtrip-rust"):
        with tempfile.TemporaryDirectory(prefix="gofree-mctl4-preflight-") as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            tool = root / "tool"
            tool.write_text(
                "#!" + sys.executable + "\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "with open(os.environ['PREFLIGHT_TRACE'], 'a') as f:\n"
                "    f.write(json.dumps(sys.argv) + '\\n')\n"
                "if Path(sys.argv[0]).name == 'psql':\n"
                "    print(json.loads(os.environ['PREFLIGHT_SETTINGS'])[sys.argv[1]])\n"
                "else:\n"
                "    for arg in sys.argv[1:]:\n"
                "        if arg.startswith('--file='):\n"
                "            Path(arg.removeprefix('--file=')).unlink(missing_ok=True)\n"
                "    sys.exit('fixture stopped at pg_dump')\n"
            )
            tool.chmod(0o700)
            for name in ("psql", "pg_dump"):
                (root / name).symlink_to(tool)
            env = os.environ | {
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "TEST_DB_DSN": DEFAULT_DSN,
                "MAILCTL_BACKUP_CASE": case,
                "PREFLIGHT_TRACE": str(trace),
                "PREFLIGHT_SETTINGS": json.dumps(settings),
            }
            env.pop("MAILCTL_BACKUP_ROUNDTRIP_DB_DSN", None)
            if override is not None:
                env["MAILCTL_BACKUP_ROUNDTRIP_DB_DSN"] = override
            result = subprocess.run(
                [sys.executable, str(HERE / "backup_oracle.py"), "replay", "/unused-mailctl"],
                env=env, capture_output=True, text=True, timeout=30, check=False,
            )
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
            return result, calls

    def test_low_lock_capacity_fails_before_snapshot_or_restore(self):
        result, calls = self.invoke({DEFAULT_DSN: 64})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("max_locks_per_transaction >= 256", result.stderr)
        self.assertIn("got 64", result.stderr)
        self.assertEqual([Path(call[0]).name for call in calls], ["psql"])

    def test_roundtrip_override_checks_and_snapshots_only_dedicated_database(self):
        result, calls = self.invoke(
            {DEFAULT_DSN: 64, ROUNDTRIP_DSN: 512}, override=ROUNDTRIP_DSN
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture stopped at pg_dump", result.stderr)
        self.assertEqual([Path(call[0]).name for call in calls], ["psql", "pg_dump"])
        self.assertEqual(calls[0][1], ROUNDTRIP_DSN)
        self.assertEqual(calls[1][-1], ROUNDTRIP_DSN)

    def test_roundtrip_override_leaves_other_cases_on_default_database(self):
        result, calls = self.invoke(
            {DEFAULT_DSN: 64, ROUNDTRIP_DSN: 512},
            override=ROUNDTRIP_DSN, case="restore-auth",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture stopped at pg_dump", result.stderr)
        self.assertEqual([Path(call[0]).name for call in calls], ["pg_dump"])
        self.assertEqual(calls[0][-1], DEFAULT_DSN)


if __name__ == "__main__":
    unittest.main()
