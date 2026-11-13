#!/usr/bin/env python3
"""Restore Strict on the OIDC login flow cookies (and on the callback's clears) in an explicit
test-only build (feature `oracle-mutants`, SETJOIN_OIDCLAX_MUTANT) and require the browser-shaped
test to reject it (#548, owner-approved functional fix 2026-11-09); then require the same build
without a mutant, and the ordinary build, to pass. Needs REQUIRE_DB=1 and the assigned disposable
DSNs. Optional argv: mutant ids to rerun."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1] / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")
TEST = "a_cross_site_idp_redirect_carrying_only_lax_cookies_completes_the_login"
MUTANTS = ["oidc-login-cookies-strict", "oidc-clear-cookies-strict"]


def cargo(env_extra, features):
    cmd = ["cargo", "test", "--locked", "-p", "setjoin-auth"]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += ["--test", "rp_oidclax", TEST, "--", "--test-threads=1"]
    return subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          env={**os.environ, **env_extra})


chosen = [m for m in MUTANTS if not sys.argv[1:] or m in sys.argv[1:]]
for mutant in chosen:
    result = cargo({"SETJOIN_OIDCLAX_MUTANT": mutant}, True)
    if result.returncode != 101 or "test result: FAILED." not in result.stdout:
        print(result.stdout[-3000:])
        sys.exit(f"mutant survived (not rejected): {mutant}")
    why = [l for l in result.stdout.splitlines() if "panicked at" in l or "SameSite" in l]
    print(f"MUTANT-REJECTED: {mutant} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
# A regenerating run must never pass silently: it rewrites the reviewed login expectation, so it
# fails by design (the written files are restored afterwards).
corpus = root / "tests/conformance/identity-rp"
if not sys.argv[1:] or "regeneration" in sys.argv[1:]:
    keep = Path(tempfile.mkdtemp())
    shutil.copytree(corpus / "security", keep / "security")
    shutil.copy(corpus / "divergences.json", keep / "divergences.json")
    try:
        result = subprocess.run(
            ["cargo", "test", "--locked", "-p", "setjoin-auth", "--test", "rp_oracle", "--", "--test-threads=1", "--exact", "login_success"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, "SECFIX8_WRITE_SECURITY": "1", "SECFIX8_WRITE_ONLY": "login-success"},
        )
    finally:
        shutil.rmtree(corpus / "security")
        shutil.copytree(keep / "security", corpus / "security")
        shutil.copy(keep / "divergences.json", corpus / "divergences.json")
        shutil.rmtree(keep)
    if result.returncode == 0 or "test result: FAILED." not in result.stdout:
        print(result.stdout[-2000:])
        sys.exit("a regenerating run passed silently: rp_oracle::login_success")
    print("REGENERATION-FAILS: rp_oracle login_success (mode SECFIX8_WRITE_SECURITY)", flush=True)
for features in (True, False):
    result = cargo({}, features)
    if result.returncode:
        print(result.stdout[-3000:])
        sys.exit(f"secure test failed without a mutant (features={features})")
print(f"OIDCLAX mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
