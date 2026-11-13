#!/usr/bin/env python3
"""Restore each fixed bug (owner-approved security fixes 2026-11-05, #547: OIDC RP follow-ups
and self-service migration/webhook hardening) in an explicit test-only build and require the
secure-behaviour test to reject it; then require the same build without a mutant, and the
ordinary build, to pass them.

Rust mutants: feature `oracle-mutants`. Identity/auth mutants read SETJOIN_SECFIX13_MUTANT;
gateway ones read SETJOIN_SECFIX3_MUTANT (setjoin_contracts). `sql:` mutants load a
bug-restored reducer into the assigned disposable database and always reload the repository
copy afterwards.

Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, ...) and psql.
Optional argv: mutant ids to rerun.
"""
import os
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile

repo = Path(__file__).resolve().parents[1]
root = repo / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

RP = ("setjoin-auth", "setjoin_auth", "SETJOIN_SECFIX13_MUTANT", "rp_secfix13")
GW = ("setjoin-gateway", "setjoin_gateway", "SETJOIN_SECFIX3_MUTANT", "secfix13")
# mutant id -> (spec, test name)
MUTANTS = {
    "sql:rp-settle-rewrites-email": (RP, "an_idp_asserted_address_never_rewrites_the_linked_account_email"),
    "rp-jit-shadow-orphan": (RP, "a_jit_login_in_shadow_read_mode_creates_its_link_and_can_log_in_again"),
    "rp-jit-blocked-500": (RP, "a_jit_address_collision_is_a_conflict_not_a_server_error"),
    "oidc-link-needs-strict-cookies": (RP, "an_oidc_link_completes_same_site_after_the_cross_site_callback"),
    "oidc-link-cookies-strict": (RP, "an_oidc_link_completes_same_site_after_the_cross_site_callback"),
    "webhook-register-no-dns": (GW, "webhook_registration_resolves_the_host_and_refuses_non_public_answers"),
    "self-service-body-uncapped": (GW, "self_service_json_bodies_are_capped_at_one_mebibyte"),
    "self-service-allows-plaintext-imap": (GW, "self_service_imap_refuses_plaintext_tls_mode"),
    "self-service-allows-empty-tls-mode": (GW, "self_service_imap_refuses_plaintext_tls_mode"),
    "self-service-runs-plaintext-imap": (GW, "self_service_jobs_never_run_plaintext_imap"),
    "self-service-inherits-private-allowlist": (GW, "self_service_migration_never_inherits_the_admin_private_allowlist"),
}
SETTLE = repo / "mailserver/sql/reducers/rust_identity_rp_settle.sql"

FIXED_PROFILE = """    v_stage:='mapping';
"""
GO_PROFILE = """    UPDATE users SET email=p_email,updated_at=statement_timestamp()
     WHERE id=p_user_id AND lower(email)<>lower(p_email);
    v_stage:='mapping';
"""


def swapped(path, fixed, bug):
    text = path.read_text()
    assert text.count(fixed) == 1, f"{path.name} drifted from the mutant recipe"
    return text.replace(fixed, bug)


SQL = {
    "sql:rp-settle-rewrites-email": (SETTLE, lambda: swapped(SETTLE, FIXED_PROFILE, GO_PROFILE)),
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


def load(path):
    subprocess.run(["psql", os.environ["TEST_DB_DSN"], "-v", "ON_ERROR_STOP=1", "-q", "-f", str(path)],
                   check=True, stdout=subprocess.DEVNULL)


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
touched = set()
try:
    for mutant, (spec, name) in chosen.items():
        if mutant in SQL:
            path, body = SQL[mutant]
            touched.add(path)
            with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
                f.write(body())
            load(f.name)
            os.unlink(f.name)
            result = cargo(spec, name, {}, False)
            load(path)
        else:
            result = cargo(spec, name, {spec[2]: mutant}, True)
        if result.returncode != 101 or "test result: FAILED." not in result.stdout:
            print(result.stdout[-3000:])
            sys.exit(f"mutant survived (not rejected): {mutant}")
        why = [l for l in result.stdout.splitlines() if "panicked at" in l or l.startswith(("assertion", "unrelated", "connect", "the "))]
        print(f"MUTANT-REJECTED: {mutant} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
finally:
    for path in touched:
        load(path)
# Regeneration modes must never pass silently: a run that rewrites reviewed expectations fails
# (the written files are restored afterwards, this only proves the run cannot go green).
GW_CORPUS = root / "tests/conformance/identity-self-service"
RP_CORPUS = root / "tests/conformance/identity-rp"
REGEN = [
    ("setjoin-gateway", "identity_self_service", "migration_test_imap_success", {"SECFIX3_WRITE_SECURITY": "1"}, GW_CORPUS),
    ("setjoin-auth", "rp_oracle", "link_success", {"SECFIX8_WRITE_SECURITY": "1", "SECFIX8_WRITE_ONLY": "link-success"}, RP_CORPUS),
]
if not only or "regeneration" in only:
    for package, target, name, extra, corpus in REGEN:
        keep = Path(tempfile.mkdtemp())
        shutil.copytree(corpus / "security", keep / "security")
        shutil.copy(corpus / "divergences.json", keep / "divergences.json")
        try:
            result = subprocess.run(
                ["cargo", "test", "--locked", "-p", package, "--test", target, "--", "--test-threads=1", "--exact", name],
                cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={**os.environ, **extra},
            )
        finally:
            shutil.rmtree(corpus / "security")
            shutil.copytree(keep / "security", corpus / "security")
            shutil.copy(keep / "divergences.json", corpus / "divergences.json")
            shutil.rmtree(keep)
        if result.returncode == 0 or "test result: FAILED." not in result.stdout:
            print(result.stdout[-2000:])
            sys.exit(f"a regenerating run passed silently: {package}::{target}::{name}")
        print(f"REGENERATION-FAILS: {package} {target}::{name} (mode {', '.join(extra)})", flush=True)
# An UNREVIEWED divergence entry fails even with the write flag set, unless that very call
# regenerated it (nothing is regenerated here: the filter matches no baseline).
if not only or "regeneration" in only:
    import json
    divergences = RP_CORPUS / "divergences.json"
    original = divergences.read_text()
    try:
        entries = json.loads(original)
        entry = next(e for e in entries if e["baseline"] == "goldens/link-success.json")
        entry["reason"] += " UNREVIEWED"
        divergences.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
        result = subprocess.run(
            ["cargo", "test", "--locked", "-p", "setjoin-auth", "--test", "rp_oracle", "--", "--test-threads=1", "--exact", "link_success"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, "SECFIX8_WRITE_SECURITY": "1", "SECFIX8_WRITE_ONLY": "matches-no-baseline"},
        )
    finally:
        divergences.write_text(original)
    if result.returncode == 0 or "UNREVIEWED divergence entry" not in result.stdout:
        print(result.stdout[-2000:])
        sys.exit("an UNREVIEWED divergence entry was accepted under the write flag")
    print("UNREVIEWED-REFUSED: write flag set, nothing regenerated", flush=True)
# The same build without a mutant selected, then the ordinary build, must pass.
for spec, name in sorted(set(chosen.values()), key=lambda x: (x[0][3], x[1])):
    for features in (True, False):
        result = cargo(spec, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {spec[3]}::{name}")
print(f"SECFIX13 mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
