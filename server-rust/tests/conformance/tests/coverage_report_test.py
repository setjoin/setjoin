#!/usr/bin/env python3
"""Check the coverage reporter using an independently instrumented program."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
REPORT = ROOT / "scripts/report-gofree-oracle-coverage.py"


class CoverageReport(unittest.TestCase):
    def test_reports_only_handler_lines_exercised_by_the_selected_replay(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-coverage-") as directory:
            root = Path(directory)
            source = root / "fixture.rs"
            source.write_text('''
fn handler(flag: bool) -> u32 {
    if flag {
        11
    } else {
        29
    }
}
#[test] fn replay_success() { assert_eq!(handler(true), 11); }
#[test] fn unrelated_test() { assert_eq!(handler(false), 29); }
''')
            binary = root / "gofree-t3-coverage-fixture"
            subprocess.run(["rustc", "--test", "-C", "instrument-coverage", str(source),
                            "-o", str(binary)], check=True, capture_output=True, text=True)
            result = subprocess.run(
                [sys.executable, str(REPORT), "--route", "POST /example", "--binary", str(binary),
                 "--source", str(source), "--test", "replay_success"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["route"], "POST /example")
            lines = report["files"][0]["lines"]
            self.assertGreater(lines["covered"], 0)
            self.assertLess(lines["covered"], lines["count"])

    def test_a_skipped_replay_cannot_produce_coverage_evidence(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-coverage-") as directory:
            root = Path(directory)
            source = root / "fixture.rs"
            source.write_text('#[test] fn replay() { eprintln!("CONFORMANCE-SKIP (reason=no-db)"); }\n')
            binary = root / "gofree-t3-coverage-fixture"
            subprocess.run(["rustc", "--test", "-C", "instrument-coverage", str(source),
                            "-o", str(binary)], check=True, capture_output=True, text=True)
            result = subprocess.run(
                [sys.executable, str(REPORT), "--route", "POST /example", "--binary", str(binary),
                 "--source", str(source), "--test", "replay"],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("skip", result.stderr.lower())

    def test_the_target_runner_wraps_every_replay_like_cargo_test_does(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-coverage-") as directory:
            root = Path(directory)
            source = root / "fixture.rs"
            source.write_text('#[test] fn replay() { assert_eq!(std::env::var("RUNNER_SAW").unwrap(), "yes"); }\n')
            binary = root / "gofree-t3-coverage-fixture"
            subprocess.run(["rustc", "--test", "-C", "instrument-coverage", str(source),
                            "-o", str(binary)], check=True, capture_output=True, text=True)
            runner = root / "runner.sh"
            runner.write_text('#!/usr/bin/env bash\nexport RUNNER_SAW=yes\nexec "$@"\n')
            host = next(line.split(": ", 1)[1] for line in subprocess.run(
                ["rustc", "-vV"], check=True, capture_output=True, text=True).stdout.splitlines()
                if line.startswith("host: "))
            var = "CARGO_TARGET_" + host.upper().replace("-", "_") + "_RUNNER"
            command = [sys.executable, str(REPORT), "--route", "POST /example", "--binary", str(binary),
                       "--source", str(source), "--test", "replay"]
            bare = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(bare.returncode, 0, "the replay must need the runner")
            wrapped = subprocess.run(command, capture_output=True, text=True, check=False,
                                     env=dict(os.environ, **{var: f"bash {runner}"}))
            self.assertEqual(wrapped.returncode, 0, wrapped.stderr)

    def test_one_route_split_over_two_test_binaries_reports_the_union(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-coverage-") as directory:
            root = Path(directory)
            source = root / "shared.rs"
            source.write_text('''
pub fn handler(flag: bool) -> u32 {
    if flag {
        11
    } else {
        29
    }
}
''')
            library = root / "libshared.rlib"
            subprocess.run(["rustc", "--crate-type", "rlib", "--crate-name", "shared", "-C", "instrument-coverage",
                            str(source), "-o", str(library)], check=True, capture_output=True, text=True)
            binaries = []
            for name, body in (("a", "assert_eq!(shared::handler(true), 11);"), ("b", "assert_eq!(shared::handler(false), 29);")):
                crate_root = root / f"{name}.rs"
                crate_root.write_text(f"#[test] fn replay_{name}() {{ {body} }}\n")
                binary = root / f"fixture-{name}"
                subprocess.run(["rustc", "--test", "-C", "instrument-coverage", "--extern", f"shared={library}",
                                str(crate_root), "-o", str(binary)], check=True, capture_output=True, text=True)
                binaries.append(binary)

            def lines(*cases):
                command = [sys.executable, str(REPORT), "--route", "GET /split", "--source", str(source)]
                for binary, test in cases:
                    command += ["--case", str(binary), test]
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)["files"][0]["lines"]["covered"]

            only_a = lines((binaries[0], "replay_a"))
            only_b = lines((binaries[1], "replay_b"))
            both = lines((binaries[0], "replay_a"), (binaries[1], "replay_b"))
            self.assertGreater(both, only_a)
            self.assertGreater(both, only_b)

    def test_a_hung_replay_is_killed_at_the_time_limit(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-coverage-") as directory:
            root = Path(directory)
            source = root / "fixture.rs"
            source.write_text('#[test] fn replay() { std::thread::sleep(std::time::Duration::from_secs(60)); }\n')
            binary = root / "gofree-t3-coverage-fixture"
            subprocess.run(["rustc", "--test", "-C", "instrument-coverage", str(source),
                            "-o", str(binary)], check=True, capture_output=True, text=True)
            result = subprocess.run(
                [sys.executable, str(REPORT), "--route", "POST /example", "--binary", str(binary),
                 "--source", str(source), "--test", "replay"],
                capture_output=True, text=True, check=False, timeout=30,
                env=dict(os.environ, LANE_COVERAGE_REPLAY_TIMEOUT="2"),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exceeded 2s", result.stderr)

    def test_a_replay_that_writes_no_profile_is_not_evidence_even_when_another_replay_does(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-coverage-") as directory:
            root = Path(directory)
            source = root / "fixture.rs"
            source.write_text("#[test] fn replay() {}\n")
            instrumented, plain = root / "instrumented", root / "plain"
            subprocess.run(["rustc", "--test", "-C", "instrument-coverage", str(source), "-o", str(instrumented)],
                           check=True, capture_output=True, text=True)
            subprocess.run(["rustc", "--test", str(source), "-o", str(plain)],
                           check=True, capture_output=True, text=True)
            result = subprocess.run(
                [sys.executable, str(REPORT), "--route", "GET /split", "--source", str(source),
                 "--case", str(instrumented), "replay", "--case", str(plain), "replay"],
                capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no coverage profile", result.stderr)


if __name__ == "__main__":
    unittest.main()
