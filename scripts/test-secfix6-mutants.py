#!/usr/bin/env python3
"""Restore each fixed cross-tenant data-path security bug (owner-approved security fixes
2026-11-05, #512: #476 #470 #478 #424 #423 #430 #390 #378 #437 #436 #449 #456, the CalDAV TZID
leak, the GAL hidden-manager disclosure and the attachments.zip dot names and caps) in an explicit test-only build and
require the secure-behaviour test, and where a recorded golden was re-baselined the replay of
that golden too, to FAIL; then require the same build without a mutant and the ordinary build
to pass.

Rust mutants: feature `oracle-mutants` + env SETJOIN_SECFIX3_MUTANT=<id> (the shared
`setjoin_contracts::mutants::on`). Reducer mutants (`sql:` prefix) load a bug-restored copy of
the reducer into the assigned disposable database and always reload the repository file
afterwards.

Needs REQUIRE_DB=1, the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, DB_APP_DSN, ...) and
psql. Optional argv: mutant ids to rerun.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
root = repo / "server-rust"
reducers = repo / "mailserver/sql/reducers"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

GW, IMAP = "setjoin-gateway", "setjoin-imap"
# (package, test target, test filter) triples; every one must fail under the mutant.
UNDO = [(GW, "secfix6", "undo_send_never_deletes_another_tenants_queue_row"), (GW, "jmap_submission", "submission_undo_shared_id")]
PURGE = [(GW, "secfix6", "purge_blob_check_ignores_another_tenants_message")]
SYSTAG = [(GW, "secfix6", "mailbox_set_system_tag_precheck_is_mailbox_scoped")]
DOWNLOAD = [(GW, "jmap_other", "jmap_download_cross_tenant")]
EXECUTE = [(GW, "mailboxes", "execute_foreign")]
CAP = [(GW, "secfix6", "subscription_cap_counts_under_the_rls_bound_credential")]
CONSENT = [(GW, "secfix6", "m365_consent_url_is_built_from_trusted_inputs"), (GW, "migration", "m365_connect_escape_client_id")]
SCIM = [(GW, "scim", "groups_create_rls_members"), (GW, "scim", "groups_patch_rls_members")]
ZIP_GOLDEN = [(GW, "jmap_messages", "zip_success")]
MEET = [(GW, "meet_recorded", "get_foreign"), (GW, "meet_recorded", "by_slug_foreign")]
AUDIT = [(GW, "retention_audit_recorded", "audit_set_audit_failure")]
KQL = [(GW, "secfix6", "kql_refuses_a_quoted_nul"), (GW, "retention_audit_recorded", "refuses_a_nul_kql_locally"), (GW, "compliance_recorded", "nul_kql_is_refused_and_worm_requests_forward_untouched")]
IDLE = [(IMAP, "extra", "disconnect_during_idle_frees_the_connection_slot")]
UPDATES = [(GW, "secfix6", "update_devices_are_confined_to_the_callers_reach")]
TZ = [(GW, "caldav", "propfind_timezone_foreign")]
GAL = [(GW, "carddav", "edge_gal_query_hidden_manager")]
ZIP = [(GW, "secfix6", "attachments_zip_neutralises_dot_names_and_bounds_entries")]

# mutant id -> list of (package, target, filter); a "sql:" id reloads a bug-restored reducer.
MUTANTS = {
    "download-existence-oracle": DOWNLOAD,
    "subscription-cap-unscoped": CAP,
    "m365-consent-untrusted": CONSENT,
    "scim-members-request-pool": SCIM,
    "kql-nul-accepted": KQL,
    "imap-idle-spins-on-close": IDLE,
    "updates-devices-unscoped": UPDATES,
    "caldav-tz-global-key": TZ,
    "gal-manager-disclosed": GAL,
    "zip-dot-names": ZIP + ZIP_GOLDEN,
    "zip-unbounded": ZIP,
    "sql:undo-queue-unscoped": UNDO,
    "sql:purge-blob-check-unscoped": PURGE,
    "sql:system-tag-precheck-unscoped": SYSTAG,
    "sql:purge-execute-no-reach": EXECUTE,
    "sql:meeting-read-org-wide": MEET,
    "sql:audit-policy-swallows-failure": AUDIT,
}


def undo_unscoped(text):
    out, n = re.subn(r"          AND mailbox_id = p_mailbox_id  -- #476[^\n]*\n", "", text)
    assert n == 2, "undo_send drifted from the mutant recipe"
    return out


def purge_unscoped(text):
    out, n = re.subn(r"        AND mailbox_id = p_mailbox_id  -- #470[^\n]*\n", "", text)
    assert n == 1, "jmap_email_purge drifted from the mutant recipe"
    return out


def systag_unscoped(text):
    out = text.replace("WHERE id = v_id AND mailbox_id = p_mailbox_id AND tag_type = 'system'  -- #478: own tags only", "WHERE id = v_id AND tag_type = 'system'")
    assert out != text, "jmap_mailbox drifted from the mutant recipe"
    return out


def execute_no_reach(text):
    out, n = re.subn(r"  IF v_found AND NOT \(p_actor=v_p.requested_by.*?    RAISE EXCEPTION 'purge is not independently approved and eligible' USING ERRCODE='BZ311';\n  END IF;\n", "", text, count=1, flags=re.S)
    assert n == 1, "mailbox_purge_execute drifted from the mutant recipe"
    return out


def meeting_org_wide(text):
    out = text.replace("v_related := meeting_guest_read_allowed(p_user_id, p_meeting_id);", "v_related := true;")
    assert out != text, "meeting_read drifted from the mutant recipe"
    return out


def audit_swallows(text):
    out = text.replace(""" PERFORM audit_write(p_actor,'audit_policy_change','',NULL,v_before,
  jsonb_build_object('level',p_level,'reasonRequiredAreas',p_areas),NULLIF(p_ip,'')::inet,p_reason,'core');
""", """ BEGIN
  PERFORM audit_write(p_actor,'audit_policy_change','',NULL,v_before,
   jsonb_build_object('level',p_level,'reasonRequiredAreas',p_areas),NULLIF(p_ip,'')::inet,p_reason,'core');
 EXCEPTION WHEN OTHERS THEN NULL;
 END;
""")
    assert out != text, "audit policy reducer drifted from the mutant recipe"
    return out


SQL = {
    "sql:undo-queue-unscoped": (["message_lifecycle.sql"], undo_unscoped),
    "sql:purge-blob-check-unscoped": (["jmap_email.sql"], purge_unscoped),
    "sql:system-tag-precheck-unscoped": (["jmap_mailbox.sql"], systag_unscoped),
    "sql:purge-execute-no-reach": (["mailbox_purge_execute.sql"], execute_no_reach),
    "sql:meeting-read-org-wide": (["meeting_read.sql"], meeting_org_wide),
    "sql:audit-policy-swallows-failure": (["rust_compliance_audit_policy_set.sql"], audit_swallows),
}
ALL_FILES = sorted({f for files, _ in SQL.values() for f in files})


SCRUB = """BEGIN; SET LOCAL session_replication_role=replica;
DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix6-%');
DELETE FROM admin_role_groups WHERE name LIKE 'secfix6-%';
DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%');
DELETE FROM calendar_subscriptions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%');
DELETE FROM calendars WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%');
DELETE FROM outbound_queue WHERE message_id LIKE 'secfix6-%';
DELETE FROM outbound_queue_hot WHERE message_id LIKE 'secfix6-%';
DELETE FROM orphaned_message_blobs WHERE raw_ref LIKE 'secfix6-%';
CREATE TEMP TABLE secfix6_domains ON COMMIT DROP AS SELECT DISTINCT domain_id FROM users WHERE email LIKE 'secfix6-%';
DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%');
DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%');
DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE email LIKE 'secfix6-%');
DELETE FROM mailboxes WHERE email LIKE 'secfix6-%';
DELETE FROM users WHERE email LIKE 'secfix6-%';
DELETE FROM domains WHERE id IN (SELECT domain_id FROM secfix6_domains);
COMMIT;"""


def scrub():
    """A panicking secure test (the expected result under a mutant) skips its own cleanup."""
    subprocess.run(["psql", os.environ["TEST_DB_DSN"], "-q", "-c", SCRUB], check=True, stdout=subprocess.DEVNULL)


def scrub_imap():
    """The IMAP fixture's cleanup leaves mailbox_lifecycle rows that break its next seed."""
    subprocess.run(["psql", os.environ["TEST_DB_DSN"], "-q", "-c", "DELETE FROM mailbox_address_claims WHERE normalized_address LIKE '%@imap1.test' OR mailbox_id BETWEEN 9343021 AND 9343029; DELETE FROM mailbox_lifecycle WHERE mailbox_id BETWEEN 9343021 AND 9343029"],
                   check=True, stdout=subprocess.DEVNULL)


def cargo(package, target, name, env_extra, features):
    if package == IMAP:
        scrub_imap()
    result = cargo_run(package, target, name, env_extra, features)
    if package == IMAP:
        scrub_imap()
    if target == "secfix6":
        scrub()
    return result


def cargo_run(package, target, name, env_extra, features):
    cmd = ["cargo", "test", "--locked", "-p", package]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += ["--test", target, name, "--", "--test-threads=1"]
    return subprocess.run(
        cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, **env_extra},
    )


def load(path):
    subprocess.run(
        ["psql", os.environ["TEST_DB_DSN"], "-v", "ON_ERROR_STOP=1", "-q", "-f", str(path)],
        check=True, stdout=subprocess.DEVNULL, env={**os.environ, "PGOPTIONS": "-c client_min_messages=warning"},
    )


def reload_all():
    for name in ALL_FILES:
        load(reducers / name)


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
try:
    for mutant, tests in chosen.items():
        env = {}
        if mutant in SQL:
            files, rewrite = SQL[mutant]
            for name in files:
                body = rewrite((reducers / name).read_text())
                with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
                    f.write(body)
                load(f.name)
                os.unlink(f.name)
        else:
            env = {"SETJOIN_SECFIX3_MUTANT": mutant}
        for package, target, name in tests:
            result = cargo(package, target, name, env, True)
            if result.returncode != 101 or "test result: FAILED." not in result.stdout:
                print(result.stdout[-3000:])
                sys.exit(f"mutant survived (not rejected): {mutant} by {target}::{name}")
            why = [l.strip() for l in result.stdout.splitlines() if "panicked at" in l or l.startswith("assertion")][:2]
            print(f"MUTANT-REJECTED: {mutant} by {target}::{name} ({' | '.join(why)[:160]})", flush=True)
        if mutant in SQL:
            reload_all()
finally:
    reload_all()
# The same build without a mutant, then the ordinary build, must pass.
for package, target, name in sorted({t for ts in chosen.values() for t in ts}):
    for features in (True, False):
        result = cargo(package, target, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {target}::{name}")
print("PASS")
