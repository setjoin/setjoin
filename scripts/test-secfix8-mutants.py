#!/usr/bin/env python3
"""Restore each fixed bug (owner-approved security fixes 2026-11-06, #530 OIDC relying
party, #529 admin-scope residuals, #531 follow-ups of #512) in an explicit test-only build
and require the secure-behaviour test to reject it; then require the same build without a
mutant, and the ordinary build, to pass them.

Rust mutants: feature `oracle-mutants`. Identity/auth mutants read
SETJOIN_SECFIX8_MUTANT; gateway ones read SETJOIN_SECFIX3_MUTANT (setjoin_contracts).
`sql:` mutants load a bug-restored reducer into the assigned disposable database and
always reload the repository copy afterwards.

Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, ...) and psql.
Optional argv: mutant ids to rerun.
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

RP = ("setjoin-auth", "setjoin_auth", "SETJOIN_SECFIX8_MUTANT", "rp_secfix8")
GW = ("setjoin-gateway", "setjoin_gateway", "SETJOIN_SECFIX3_MUTANT", "secfix8")
CAREM = ("setjoin-gateway", "setjoin_gateway", "SETJOIN_SECFIX3_MUTANT", "ca_remaining")
# mutant id -> (package, _, env var, test target, test name)
MUTANTS = {
    "rp-http-endpoints": (RP, "discovered_token_and_jwks_endpoints_must_be_https"),
    "rp-body-uncapped": (RP, "idp_response_bodies_are_capped"),
    "rp-alg-unpinned": (RP, "id_token_alg_is_pinned_to_the_discovery_list_asymmetric_only"),
    "rp-email-fallback": (RP, "only_the_verified_email_claim_is_an_email"),
    "rp-empty-nonce": (RP, "an_empty_or_missing_nonce_never_matches"),
    "rp-keeps-flow-cookies": (RP, "a_successful_callback_clears_the_flow_cookies_normalized_or_not"),
    "sql:rp-first-grant-no-provenance": (RP, "the_first_group_grant_records_provider_provenance_so_an_idp_removal_revokes_it"),
    "ca-revoke-any-grant": (GW, "session_revoke_reach_uses_the_route_permission"),
    "fieldpolicy-any-grant": (GW, "field_policy_reach_uses_the_route_permission"),
    "ca-list-reads-any-grant": (CAREM, "loc_list_foreign"),
    "m365-connect-localhost": (GW, "m365_connect_needs_a_real_public_host"),
    "blob-cleanup-no-bypass-check": (GW, "blob_cleanup_refuses_a_credential_without_bypassrls"),
    "sql:meet-ids-unrelated": (GW, "meeting_projection_hides_channel_and_event_ids_from_unrelated_callers"),
}
REDUCERS = repo / "mailserver/sql/reducers"
MAP = REDUCERS / "rust_identity_rp_map.sql"
MEET = REDUCERS / "meeting_read.sql"

FIXED_GRANT = """            INSERT INTO distribution_group_members(group_id,mailbox_id,source)
            VALUES((v_mapping->>'distribution_group_id')::bigint,v_mailbox_id,'sso') ON CONFLICT DO NOTHING;
            INSERT INTO sso_distribution_group_provenance(provider_key,group_id,mailbox_id)
            SELECT p_provider_key,group_id,mailbox_id FROM distribution_group_members
            WHERE group_id=(v_mapping->>'distribution_group_id')::bigint AND mailbox_id=v_mailbox_id ON CONFLICT DO NOTHING;
"""
GO_GRANT = """            WITH effective AS (
                INSERT INTO distribution_group_members(group_id,mailbox_id,source)
                VALUES((v_mapping->>'distribution_group_id')::bigint,v_mailbox_id,'sso') ON CONFLICT DO NOTHING
            ) INSERT INTO sso_distribution_group_provenance(provider_key,group_id,mailbox_id)
              SELECT p_provider_key,group_id,mailbox_id FROM distribution_group_members
              WHERE group_id=(v_mapping->>'distribution_group_id')::bigint AND mailbox_id=v_mailbox_id ON CONFLICT DO NOTHING;
"""
FIXED_IDS = """             'chatChannelId', CASE WHEN v_related THEN m.chat_channel_id END,
             'calendarEventId', CASE WHEN v_related THEN m.calendar_event_id END,
"""
GO_IDS = "             'chatChannelId', m.chat_channel_id, 'calendarEventId', m.calendar_event_id,\n"


def swapped(path, fixed, bug):
    text = path.read_text()
    assert text.count(fixed) == 1, f"{path.name} drifted from the mutant recipe"
    return text.replace(fixed, bug)


SQL = {
    "sql:rp-first-grant-no-provenance": (MAP, lambda: swapped(MAP, FIXED_GRANT, GO_GRANT)),
    "sql:meet-ids-unrelated": (MEET, lambda: swapped(MEET, FIXED_IDS, GO_IDS)),
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
# The same build without a mutant selected, then the ordinary build, must pass.
for spec, name in sorted(set(chosen.values()), key=lambda x: (x[0][3], x[1])):
    for features in (True, False):
        result = cargo(spec, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {spec[3]}::{name}")
print(f"SECFIX8 mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
