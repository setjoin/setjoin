#!/usr/bin/env python3
"""Exercise the real cargo-deny policy against independent local packages."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

POLICY = pathlib.Path(__file__).resolve().parents[2] / "deny.toml"
EXCEPTION_GUARD = pathlib.Path(__file__).resolve().parents[3] / "scripts/check-rust-license-exceptions.py"


class LicensePolicy(unittest.TestCase):
    def test_exception_without_a_written_reason_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-exception-") as tmp:
            root = pathlib.Path(tmp)
            (root / "deny.toml").write_text('[licenses]\nexceptions = [{ crate = "demo@1.0.0", allow = ["ISC"] }]\n')
            (root / "license-exception-reasons.toml").write_text('[reasons]\n')
            result = subprocess.run(["python3", str(EXCEPTION_GUARD), str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("demo@1.0.0", result.stderr)
            (root / "license-exception-reasons.toml").write_text(
                '[reasons]\n"demo@1.0.0" = "Reviewed for this version"\n'
            )
            result = subprocess.run(["python3", str(EXCEPTION_GUARD), str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_advisory_ignore_without_a_written_reason_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-fix7-advisory-") as tmp:
            root = pathlib.Path(tmp)
            (root / "license-exception-reasons.toml").write_text("[reasons]\n")
            for ignore, ok in [
                ('"RUSTSEC-2000-0001"', False),
                ('{ id = "RUSTSEC-2000-0001" }', False),
                ('{ id = "RUSTSEC-2000-0001", reason = " " }', False),
                ('{ id = "RUSTSEC-2000-0001", reason = "Verification-only use; no secret input" }', True),
            ]:
                with self.subTest(ignore=ignore):
                    (root / "deny.toml").write_text(f"[advisories]\nignore = [{ignore}]\n")
                    result = subprocess.run(["python3", str(EXCEPTION_GUARD), str(root)], capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, ok, result.stderr)
                    if not ok:
                        self.assertIn("RUSTSEC-2000-0001", result.stderr)

    def test_the_rust_lane_gates_on_every_cargo_deny_check_including_advisories(self):
        import tomllib
        policy = tomllib.loads(POLICY.read_text())
        advisories = policy.get("advisories")
        self.assertIsNotNone(advisories, "deny.toml needs an [advisories] section")
        self.assertEqual(advisories.get("unmaintained"), "all")
        self.assertEqual(advisories.get("unsound"), "all")
        self.assertEqual(advisories.get("yanked"), "deny")
        lane = (POLICY.parents[1] / "scripts/check-server-rust.sh").read_text()
        calls = re.findall(r'"\$CARGO" deny --locked check([^)|]*)\)', lane)
        self.assertTrue(calls, "the Rust lane must run cargo deny check")
        for args in calls:
            self.assertTrue(args.strip() == "" or "advisories" in args.split(), args)

    def test_git_dependency_is_rejected_by_the_source_policy(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-git-source-") as tmp:
            root = pathlib.Path(tmp)
            remote = root / "foreign"
            (remote / "src").mkdir(parents=True)
            (remote / "src/lib.rs").write_text("")
            (remote / "Cargo.toml").write_text('[package]\nname = "foreign"\nversion = "0.1.0"\nlicense = "MIT"\n')
            subprocess.run(["git", "init", "-q", str(remote)], check=True)
            subprocess.run(["git", "-C", str(remote), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(remote), "-c", "user.name=Fixture", "-c",
                 "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                check=True,
            )
            app = root / "app"
            (app / "src").mkdir(parents=True)
            (app / "src/lib.rs").write_text("")
            (app / "Cargo.toml").write_text(
                '[package]\nname = "app"\nversion = "0.1.0"\nlicense = "MIT"\n'
                f'[workspace]\n[dependencies]\nforeign = {{ git = "{remote.as_uri()}" }}\n'
            )
            shutil.copy(POLICY, app / "deny.toml")
            env = dict(os.environ, CARGO_HOME=str(root / "cargo-home"))
            result = subprocess.run(
                ["cargo", "deny", "check", "sources"], cwd=app, env=env, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source not explicitly allowed", result.stderr)

    def test_allowed_and_rejected_licenses(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-license-") as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text("")
            shutil.copy(POLICY, root / "deny.toml")
            cases = [
                ("MIT", True), ("Apache-2.0", True), ("Apache-2.0 WITH LLVM-exception", True),
                ("BSD-2-Clause", True), ("BSD-3-Clause", True), ("ISC", True), ("Zlib", True),
                ("0BSD", True), ("CC0-1.0", True), ("BSL-1.0", True), ("Unicode-3.0", True),
                ("Unicode-DFS-2016", True), ("MPL-2.0", True), ("GPL-3.0-only", False),
                ("LGPL-3.0-only", False), ("AGPL-3.0-only", False), ("SSPL-1.0", False),
                ("BUSL-1.1", False), ("MIT AND GPL-3.0-only", False), (None, False),
            ]
            for license, allowed in cases:
                with self.subTest(license=license):
                    field = f'license = "{license}"\n' if license else ""
                    (root / "Cargo.toml").write_text(
                        f'[package]\nname = "fixture"\nversion = "0.1.0"\n{field}[workspace]\n'
                    )
                    result = subprocess.run(
                        ["cargo", "deny", "check", "licenses"], cwd=root, capture_output=True, text=True
                    )
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)


if __name__ == "__main__":
    unittest.main()
