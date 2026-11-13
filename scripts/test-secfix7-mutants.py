#!/usr/bin/env python3
"""Restore each fixed OIDC-provider bug (owner-approved security fixes 2026-11-05,
#523) in an explicit test-only build and require the secure-behaviour test to
reject it; then require the same build without a mutant, and the ordinary build,
to pass them.

Rust mutants: feature `oracle-mutants` + env SETJOIN_SECFIX7_MUTANT=<id>. The
refresh-lifetime fix lives in a reducer, so its mutant is applied by loading a
bug-restored copy of the reducer into the assigned disposable database (always
reloaded from the repository afterwards).

Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, ...)
and psql. Optional argv: mutant ids to rerun.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
root = repo / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

SECFIX = "oidc_secfix7"
CONFIG = "oidc_config"
COMPLETE = (SECFIX, "completion_requires_post_with_csrf_and_the_callback_is_bound_to_the_session")
LEGACY = (SECFIX, "legacy_cfb_tokens_are_dead_and_every_token_is_bound_to_its_stored_row")
REUSE = (SECFIX, "reusing_a_rotated_refresh_token_revokes_its_whole_family")
LIFETIME = (SECFIX, "refresh_rotation_cannot_slide_past_the_absolute_family_lifetime")
# mutant id -> (test target, test name); a None id suffix "sql:" marks a reducer mutant
MUTANTS = {
    "oidc-cfb-legacy": LEGACY,
    "oidc-token-unbound": LEGACY,
    "oidc-introspect-any-client": (SECFIX, "introspection_only_answers_the_client_the_token_was_issued_to"),
    "oidc-token-cacheable": (SECFIX, "token_endpoint_responses_are_never_cacheable"),
    "oidc-weak-keys": (CONFIG, "weak_pre_existing_go_keys_fail_closed_at_startup_with_a_rotate_message"),
    "oidc-callback-anonymous": COMPLETE,
    "oidc-complete-get-bind": COMPLETE,
    "oidc-complete-no-csrf": COMPLETE,
    "oidc-refresh-reuse-ignored": REUSE,
    "oidc-confidential-no-pkce": (SECFIX, "confidential_clients_must_use_pkce_too"),
    "oidc-consume-before-client-auth": (SECFIX, "an_unauthenticated_code_holder_cannot_burn_the_code"),
    "oidc-callback-options-bypass": (SECFIX, "a_non_preflight_options_request_cannot_mint_a_callback_code"),
    "oidc-narrow-no-rotate": (SECFIX, "narrowed_scope_refresh_spends_the_token_and_joins_the_family"),
    "oidc-consume-any-client": (SECFIX, "another_client_cannot_burn_a_code"),
    "oidc-confidential-authorize-no-pkce": (SECFIX, "confidential_clients_without_a_challenge_are_refused_at_authorize"),
    "sql:oidc-refresh-sliding": LIFETIME,
    "sql:oidc-rotate-no-family-lock": (SECFIX, "refresh_rotation_waits_for_the_family_lock"),
    "sql:oidc-reuse-no-family-lock": (SECFIX, "refresh_reuse_revocation_waits_for_the_family_lock"),
}
REDUCERS = repo / "mailserver/sql/reducers"
REDUCER = REDUCERS / "rust_identity_oidc_rotate.sql"
REUSE_SQL = REDUCERS / "rust_identity_oidc_reuse.sql"
LOCK = "    PERFORM pg_advisory_xact_lock(hashtextextended('oidc-family:'||v_family,0));\n"


def without_lock(path):
    text = path.read_text()
    assert LOCK in text, "reducer drifted from the mutant recipe"
    return text.replace(LOCK, "")


def cargo(target, name, env_extra, features):
    cmd = ["cargo", "test", "--locked", "-p", "setjoin-auth"]
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


def sliding_reducer():
    text = REDUCER.read_text()
    capped = "LEAST(clock_timestamp()+interval '30 days',v_family_expiry)"
    live = "       AND COALESCE(t.refresh_family_expires_at,t.created_at+interval '90 days')>now()\n"
    inherit = "VALUES(p_id,p_client_id,p_user_id,p_user_id::text,p_scopes,v_expiry,v_family,v_family_expiry);"
    assert capped in text and live in text and inherit in text, "reducer drifted from the mutant recipe"
    text = text.replace(capped, "clock_timestamp()+interval '30 days'").replace(live, "")
    # frozen Go re-extended every rotated token: the successor gets a fresh family window
    return text.replace(inherit, "VALUES(p_id,p_client_id,p_user_id,p_user_id::text,p_scopes,v_expiry,v_family,clock_timestamp()+interval '90 days');")


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
try:
    for mutant, (target, name) in chosen.items():
        if mutant.startswith("sql:"):
            body = {"sql:oidc-refresh-sliding": sliding_reducer,
                    "sql:oidc-rotate-no-family-lock": lambda: without_lock(REDUCER),
                    "sql:oidc-reuse-no-family-lock": lambda: without_lock(REUSE_SQL)}[mutant]()
            with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
                f.write(body)
            load(f.name)
            os.unlink(f.name)
            result = cargo(target, name, {}, False)
        else:
            result = cargo(target, name, {"SETJOIN_SECFIX7_MUTANT": mutant}, True)
        if result.returncode != 101 or "test result: FAILED." not in result.stdout:
            print(result.stdout[-3000:])
            sys.exit(f"mutant survived (not rejected): {mutant}")
        if mutant.startswith("sql:"):
            load(REDUCER)
            load(REUSE_SQL)
        why = [l for l in result.stdout.splitlines() if "panicked at" in l or l.startswith(("assertion", "legacy", "rotation", "refresh", "another", "an "))]
        print(f"MUTANT-REJECTED: {mutant} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
finally:
    load(REDUCER)
    load(REUSE_SQL)
# The same build without a mutant selected, then the ordinary build, must pass.
for target, name in sorted(set(chosen.values())):
    for features in (True, False):
        result = cargo(target, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {target}::{name}")
print(f"OIDC provider security-fix mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
