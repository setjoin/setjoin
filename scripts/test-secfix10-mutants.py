#!/usr/bin/env python3
"""Restore each fixed bug (owner-approved security fixes 2026-11-05, #525 oidc_tokens
credential reducers (FORCE RLS is staged), #539 storage admin org-wide scope) in an explicit test-only
build and require the secure-behaviour test to reject it; then require the same build
without a mutant, and the ordinary build, to pass them.

Rust mutants: feature `oracle-mutants`. OIDC mutants read SETJOIN_SECFIX10_MUTANT (identity);
gateway/platform ones read SETJOIN_SECFIX3_MUTANT (setjoin_contracts). 
Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, DB_APP_DSN, ...)
and psql. Optional argv: mutant ids to rerun.
"""
import os
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[1]
root = repo / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

OIDC = ("setjoin-auth", "setjoin_auth", "SETJOIN_SECFIX10_MUTANT", "oidc_secfix10")
STORAGE = ("setjoin-gateway", "setjoin_gateway", "SETJOIN_SECFIX3_MUTANT", "platform_storage_runtime")
# mutant id -> (spec, test name)
MUTANTS = {
    "oidc-direct-refresh-anchor": (OIDC, "the_refresh_grant_derives_its_user_from_the_presented_hash"),
    "oidc-direct-token-owner": (OIDC, "userinfo_and_introspection_derive_the_owner_from_the_token_row"),
    "oidc-direct-revoke-target": (OIDC, "revocation_derives_the_owner_from_the_presented_credential"),
    "storage-scoped-grant-scan": (STORAGE, "scan_scoped"),
    "storage-scoped-grant-reconcile": (STORAGE, "reconcile_scoped"),
    "storage-scoped-grant-migrate": (STORAGE, "migration_scoped"),
    "storage-scoped-grant-cancel": (STORAGE, "cancel_scoped"),
}


def cargo(spec, name, env_extra, features):
    package, _, _, target = spec
    cmd = ["cargo", "test", "--locked", "-p", package]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += ["--test", target, name, "--", "--test-threads=1"]
    return subprocess.run(
        cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, **env_extra},
    )


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
try:
    for mutant, (spec, name) in chosen.items():
        result = cargo(spec, name, {spec[2]: mutant}, True)
        if result.returncode != 101 or "test result: FAILED." not in result.stdout:
            print(result.stdout[-3000:])
            sys.exit(f"mutant survived (not rejected): {mutant}")
        why = [l for l in result.stdout.splitlines() if "panicked at" in l or l.startswith(("assertion", "left", "right"))]
        print(f"MUTANT-REJECTED: {mutant} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
finally:
    pass
# The same build without a mutant selected, then the ordinary build, must pass.
for spec, name in sorted(set(chosen.values()), key=lambda x: (x[0][3], x[1])):
    for features in (True, False):
        result = cargo(spec, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {spec[3]}::{name}")
print(f"SECFIX10 mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
