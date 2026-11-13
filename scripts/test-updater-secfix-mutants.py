#!/usr/bin/env python3
"""Restore each root-updater security gap (#506) in a test-only build; tests must reject it."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1] / "server-rust"
cases = [
    ("adoption", "existing_managed_adoption_refuses_tampered_content", "tampered managed current was adopted"),
    ("adoption", "managed::changed_artifact_is_refused", "tampered release was adopted"),
    ("recovery", "recovery_authorization_and_forced_previous_match_recorded_go", "break-glass recovery is not authorized"),
    ("swap", "fresh_install_places_one_rust_updater_and_compatible_recovery_entrypoint", None),
    ("adoption", "managed::self_consistent_forgery_with_recomputed_evidence_is_refused", "tampered release was adopted"),
    ("adoption", "managed::self_signed_forgery_under_other_keys_is_refused", "tampered release was adopted"),
    ("adoption", "managed::stray_adoption_json_cannot_divert_to_the_self_hashed_path", "tampered release was adopted"),
    ("adoption", "managed::file_or_directory_owned_by_another_user_is_refused", "tampered release was adopted"),
    ("bin", "release_threshold_flag_cannot_lower_the_floor", "left == right"),
    ("hardening", "secure_dir_refuses_a_directory_not_owned_by_root", "non-root-owned directory accepted"),
]
def run(feature, test, name):
    cmd = ["cargo", "test", "--locked", "-p", "setjoin-updater"] + (["--features", "oracle-mutants"] if feature else []) + (["--bin", "setjoin-updater"] if test == "bin" else ["--test", test]) + [name, "--", "--test-threads=1"]
    return subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
for test, name, marker in cases:
    r = run(True, test, name)
    if r.returncode != 101 or "test result: FAILED." not in r.stdout or (marker and marker not in r.stdout):
        print(r.stdout)
        sys.exit(f"mutant not rejected: {test}::{name}")
    print(f"MUTANT-REJECTED: {test}::{name}")
for test, name, _ in cases:
    r = run(False, test, name)
    if r.returncode:
        print(r.stdout)
        sys.exit(f"ordinary build failed: {test}::{name}")
# A release build carries neither test-only verify flag.
r = subprocess.run(["cargo", "build", "--locked", "--release", "-p", "setjoin-updater"], cwd=root)
if r.returncode:
    sys.exit("release build failed")
exe = Path(os.environ.get("CARGO_TARGET_DIR", root / "target")) / "release/setjoin-updater"
for flag in (["--allow-test-roots"], ["--now", "2026-01-01T00:00:00Z"]):
    p = subprocess.run([str(exe), "verify", "--manifest", "/x", "--trust-roots", "/x", *flag], text=True, capture_output=True)
    if "unknown flags" not in p.stderr:
        sys.exit(f"release verify accepted {flag}: {p.stderr}")
print("updater security mutants: PASS (rejected; ordinary green; release verify flags absent)")
