#!/usr/bin/env python3
"""Restore each fixed identity/token/MFA/authz bug (owner-approved security fixes
2026-11-05: #484 #487 #490 #491 #495 #499 #503 #504) in an explicit test-only build
(feature `oracle-mutants`, SETJOIN_SECFIX3_MUTANT=<id>) and require the secure-behaviour
test to FAIL; then require the ordinary build to pass the same tests.

SQL fixes (#490) are restored by loading the pre-fix function text into the disposable
database for the mutant run and reloading the fixed file afterwards.
Needs REQUIRE_DB=1, the assigned disposable DSNs and psql. Optional argv: mutant-id filter.
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
DSN = os.environ["TEST_DB_DSN"]

AUTH = ("setjoin-auth", "secfix3")
GATE = ("setjoin-gateway", "secfix3_rules")
CA = ("setjoin-conditional-access", "secfix3_policy")
AUTHZ_G = ("setjoin-authz", "runtime_gates")
AUTHZ_D = ("setjoin-authz", "device_credential")
TICKET = ("setjoin-gateway", "ticket_worker")
IDENT = ("setjoin-identity", None)  # lib tests

REFRESH_SQL = (
    "mailserver/sql/reducers/rust_identity_refresh.sql",
    "        IF v_parent.revoked_at IS NOT NULL OR v_parent.expires_at<clock_timestamp() THEN\n            RETURN jsonb_build_object('status','denied');\n        END IF;\n        IF clock_timestamp()",
    "        IF clock_timestamp()",
)
PASSWORD_SQL = (
    "mailserver/sql/reducers/rust_identity_password_write.sql",
    "FROM users WHERE id=p_user_id FOR UPDATE;",
    "FROM users WHERE email=p_email FOR UPDATE;",
)
# (mutant id, (package, test target), test filter, optional sql revert)
MUTANTS = [
    ("login-no-dummy-hash", AUTH, "unknown_email_login_costs_a_password_hash_under_every_profile", None),
    ("revocations-fail-open", AUTH, "revocations_fail_closed_until_the_first_load", None),
    ("unbounded-request-bodies", AUTH, "oversized_password_and_internal_key_bodies_are_refused", None),
    ("password-keyed-on-email", AUTH, "password_change_is_keyed_on_the_signed_uid_not_the_signed_email", PASSWORD_SQL),
    ("refresh-grace-accepts-revoked-parent", AUTH, "refresh_grace_never_accepts_a_revoked_or_expired_rotated_parent", REFRESH_SQL),
    ("impersonate-foreign-domain", AUTH, "scoped_admin_impersonates_only_inside_its_domains", None),
    ("bootstrap-revoked-gets-secret", AUTH, "revoked_token_gets_no_device_secret", None),
    ("bootstrap-bound-no-dpop", AUTH, "bound_token_needs_a_dpop_proof_on_device_register", None),
    ("drive-token-drops-act", AUTH, "drive_native_token_keeps_act_provenance", None),
    ("authority-lookup-keeps-signed-grants", GATE, "failed_authority_lookup_drops_signed_grants", None),
    ("rules-cap-count-then-insert", GATE, "concurrent_personal_creates_cannot_exceed_the_rule_cap", None),
    ("rules-cap-count-then-insert", GATE, "concurrent_sweeps_cannot_exceed_the_active_sweep_cap", None),
    ("dpop-without-ath", AUTHZ_G, "dpop_proof_binds_access_token_uri_and_rejects_replay", None),
    ("device-nonce-before-ownership", AUTHZ_D, "foreign_device_request_does_not_burn_the_owners_nonce", None),
    ("policy-invalidate-keeps-loaded", CA, "invalidated_policy_cache_fails_closed_when_the_reload_fails", None),
    ("step-up-not-enforcing", CA, "legacy_step_up_policy_counts_as_enforcing_on_evaluation_errors", None),
    ("geo-error-is-low-risk", CA, "geo_tier_lookup_error_takes_the_checked_failure_path", None),
    ("ticket-keys-plaintext", TICKET, "persisted_ticket_keys_are_sealed_and_legacy_plaintext_is_replaced", None),
    ("safetynet-accepted", IDENT, "a_fresh_chained_response_is_refused", None),
    ("login-dummy-always-bcrypt", AUTH, "unknown_email_login_costs_a_password_hash_under_every_profile", None),
    ("dpop-replay-evicts-live", AUTHZ_G, "dpop_replay_cache_refuses_new_proofs_instead_of_evicting_live_ones", None),
    ("ticket-legacy-row-kept", TICKET, "without_a_codec_the_legacy_plaintext_row_is_deleted_and_a_sealed_row_kept", None),
    ("csrf-after-over-budget", ("setjoin-gateway", "secfix3_csrf"), "over_budget_cross_site_mutation_is_denied_by_csrf", None),
]


def cargo(pkg, target, name, mutant):
    cmd = ["cargo", "test", "--locked", "-p", pkg]
    if mutant:
        cmd += ["--features", "oracle-mutants"]
    cmd += (["--test", target] if target else ["--lib"]) + [name, "--", "--test-threads=1"]
    env = dict(os.environ)
    if mutant:
        env["SETJOIN_SECFIX3_MUTANT"] = mutant
    return subprocess.run(cmd, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def load(path_or_text, is_text=False):
    if is_text:
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
            f.write(path_or_text)
        path = f.name
    else:
        path = str(path_or_text)
    r = subprocess.run(["psql", DSN, "-v", "ON_ERROR_STOP=1", "-q", "-f", path], text=True, capture_output=True)
    if r.returncode:
        sys.exit(f"psql load failed: {r.stderr}")


only = set(sys.argv[1:])
chosen = [m for m in MUTANTS if not only or m[0] in only]
for mutant, (pkg, target), name, sql in chosen:
    if sql:
        file, fixed, bug = sql
        text = (repo / file).read_text()
        assert fixed in text, f"fixed text not found in {file}"
        load(text.replace(fixed, bug, 1), True)
    try:
        r = cargo(pkg, target, name, mutant)
    finally:
        if sql:
            load(repo / sql[0])
    if r.returncode != 101 or "test result: FAILED." not in r.stdout:
        print(r.stdout[-3000:])
        sys.exit(f"mutant not rejected: {mutant} / {name}")
    print(f"MUTANT-REJECTED: {mutant} / {name}", flush=True)
for mutant, (pkg, target), name, sql in chosen:
    r = cargo(pkg, target, name, None)
    if r.returncode:
        print(r.stdout[-3000:])
        sys.exit(f"ordinary build failed: {name}")
    print(f"ORDINARY-PASS: {name}", flush=True)
print("secfix3 security mutants: PASS (every mutant rejected; ordinary build green)")
