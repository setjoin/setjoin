#!/usr/bin/env python3
"""Restore each recorded LDAP security bug in an explicit test-only build."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1] / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")
selectors = [
    "interleaved_valid_then_failed_binds_leave_connection_anonymous",
    "recorded_people_limits_types_and_rebind",
    "recorded_shared_threat_policy_at_ldap_bind_socket",
    "recorded_abandon_admission_remains_responsive",
]
markers = [
    "failed pipelined Bind left an authenticated principal",
    "assertion `left == right` failed: failed-rebind-retains-principal",
    'assertion `left == right` failed: "policy"',
    "Abandon exhausted connection admission (restored Go bug)",
]
for name, marker in zip(selectors, markers):
    result = subprocess.run(
        ["cargo", "test", "--locked", "-p", "setjoin-ldap", "--features", "oracle-mutants",
         "--test", "listener", name, "--", "--test-threads=1"],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != 101 or "test result: FAILED." not in result.stdout or marker not in result.stdout:
        print(result.stdout)
        sys.exit(f"mutant did not reach the rejecting socket assertion: {name}")
    print(f"MUTANT-REJECTED: {name}")
# Restore the ordinary build, recheck all four secure outcomes and clean fixtures
# left by the deliberately rejected policy bypass.
for name in selectors:
    result = subprocess.run(
        ["cargo", "test", "--locked", "-p", "setjoin-ldap", "--test", "listener", name,
         "--", "--test-threads=1"], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        print(result.stdout)
        sys.exit(f"ordinary secure replay failed: {name}")
print("LDAP security divergence mutants: PASS (4 rejected; ordinary build green)")
