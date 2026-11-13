#!/usr/bin/env python3
"""Restore each fixed domain-scoped-admin bug (owner-approved security fixes
2026-11-05, #510: #373 #376 #384 #393 #402 #467) in an explicit test-only build and
require the secure-behaviour test, and where a recorded golden was re-baselined the
replay of that golden too, to FAIL; then require the same build without a mutant and
the ordinary build to pass.

Rust mutants: feature `oracle-mutants` + env SETJOIN_SECFIX3_MUTANT=<id> (the shared
`setjoin_contracts::mutants::on`). Reducer mutants (`sql:` prefix) load a bug-restored
copy of the reducer into the assigned disposable database and always reload the
repository file afterwards.

Needs REQUIRE_DB=1, the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, DB_APP_DSN, ...)
and psql. Optional argv: mutant ids to rerun.
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

GATEWAY = "setjoin-gateway"
SEC = ("secfix4",)
# (test target, test filter) pairs; every pair must fail under the mutant.
ALIAS = [("secfix4", "alias_must_belong_to_the_mailbox_domain_for_a_scoped_admin")]
FIELD = [
    ("secfix4", "field_policy_is_readable_only_inside_the_callers_reach"),
    ("directory_sync", "policy_get_scoped_foreign"),
]
SETS = [
    ("secfix4", "scope_sets_are_confined_to_the_callers_domain"),
    ("admin_scope_sets", "cross_tenant"),
]
JIT = [
    ("secfix4", "activation_policy_is_confined_to_roles_the_caller_owns"),
    ("admin_sod", "policy_get_foreign"),
]
DEPT = [
    ("secfix4", "departments_are_organization_wide_objects"),
    ("admin_org_policies", "dept_create_foreign"),
]
CONF = [("secfix4", "confined_holders_without_a_domain_get_nothing")]
CAREACH = [("secfix4", "ca_reach_uses_policy_grants_and_logs_follow_it")]
ADC = [("secfix4", "ad_conflicts_and_email_policies_follow_the_grant")]
PRIO = [("secfix4", "scoped_policies_stay_behind_org_wide_policies")]
CAP = [
    ("secfix4", "conditional_access_policies_are_confined_to_the_callers_reach"),
    ("ca_policies", "list_foreign"),
    ("ca_remaining", "export_foreign"),
]

# mutant id -> list of (target, filter); a "sql:" id reloads a bug-restored reducer.
MUTANTS = {
    "alias-foreign-domain": ALIAS,
    "fieldpolicy-get-foreign": FIELD,
    "scopeset-unscoped": SETS,
    "jit-policy-foreign-role": JIT,
    "ca-policy-foreign": CAP + CAREACH,
    "ca-priority-ahead": PRIO,
    "dirsync-conflicts-unscoped": ADC,
    "eap-foreign": ADC,
    "sql:dept-no-org-wide-rule": DEPT,
    "sql:dept-assign-any-grant": ADC,
    "sql:scopeset-reducers-unscoped": SETS,
    "sql:ca-reach-always-true": CAP[:2],
    "sql:restriction-defaults-unrestricted": CONF,
    "sql:reach-ignores-permission": CAREACH + ADC,  # export/import/diff use the org-wide gate, not the reach rule
}

DEPT_FILES = [
    "rust_admin_department_create.sql",
    "rust_admin_department_update.sql",
    "rust_admin_department_delete.sql",
]
SET_FILES = [
    "rust_admin_scope_set_create.sql",
    "rust_admin_scope_set_update.sql",
    "rust_admin_scope_set_delete.sql",
    "rust_admin_scope_set_member_add.sql",
    "rust_admin_scope_set_member_remove.sql",
]
CA_FILE = "rust_ca_policy_reach.sql"
GRANT_FILE = "admin_org_wide_grant.sql"


def no_department_rule(text):
    out, n = re.subn(
        r" IF NOT admin_org_wide_grant\(p_actor,ARRAY\['users.create'\]\)\n.*?\n END IF;\n", "", text, flags=re.S
    )
    assert n == 1, "department reducer drifted from the mutant recipe"
    return out


def unscoped_set(text):
    out = text.replace("v_scope=0 OR domain_id=v_scope", "true").replace(
        "v_scope=0 OR EXISTS(SELECT 1 FROM admin_scope_sets s WHERE s.id=p_set AND s.domain_id=v_scope)", "true"
    ).replace("IF v_scope <> 0 AND p_domain IS DISTINCT FROM v_scope THEN RETURN NULL; END IF;", "")
    assert out != text, "scope-set reducer drifted from the mutant recipe"
    return out


def reach_always_true(text):
    out = text.replace(
        "SELECT admin_org_wide_grant(p_actor, p_perms)\n      OR CASE", "SELECT true OR CASE", 1
    )
    assert out != text, "reach reducer drifted from the mutant recipe"
    return out


def restriction_defaults_unrestricted(text):
    out = text.replace("AND COALESCE(ra.domain_override, rg.domain_scope) IS NOT NULL), -1) END;", "AND COALESCE(ra.domain_override, rg.domain_scope) IS NOT NULL), 0) END;")
    assert out != text, "grant reducer drifted from the mutant recipe"
    return out


def reach_ignores_permission(text):
    needle = "      AND rg.permissions && p_perms\n      AND (ra.expires_at"
    assert needle in text, "grant reducer drifted from the mutant recipe"
    return text.replace(needle, "      AND (ra.expires_at", 1)


def dept_assign_any_grant(text):
    out = text.replace("admin_can_reach_perm(p_actor,p_user,ARRAY['users.create'])", "admin_can_reach(p_actor,p_user)")
    assert out != text, "assign reducer drifted from the mutant recipe"
    return out


SQL = {
    "sql:dept-assign-any-grant": (["rust_admin_department_assign_user.sql"], dept_assign_any_grant),
    "sql:restriction-defaults-unrestricted": ([GRANT_FILE], restriction_defaults_unrestricted),
    "sql:reach-ignores-permission": ([GRANT_FILE], reach_ignores_permission),
    "sql:dept-no-org-wide-rule": (DEPT_FILES, no_department_rule),
    "sql:scopeset-reducers-unscoped": (SET_FILES, unscoped_set),
    "sql:ca-reach-always-true": ([CA_FILE], reach_always_true),
}


def cargo(target, name, env_extra, features):
    cmd = ["cargo", "test", "--locked", "-p", GATEWAY]
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
    for name in sorted(set(DEPT_FILES + SET_FILES + [GRANT_FILE, CA_FILE, "rust_admin_department_assign_user.sql"])):
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
        for target, name in tests:
            result = cargo(target, name, env, True)
            if result.returncode != 101 or "test result: FAILED." not in result.stdout:
                print(result.stdout[-3000:])
                sys.exit(f"mutant survived (not rejected): {mutant} by {target}::{name}")
            why = [l.strip() for l in result.stdout.splitlines() if "panicked at" in l or l.startswith("assertion") or "scoped" in l and "admin" in l][:2]
            print(f"MUTANT-REJECTED: {mutant} by {target}::{name} ({' | '.join(why)[:160]})", flush=True)
        if mutant in SQL:
            reload_all()
finally:
    reload_all()
# The same build without a mutant, then the ordinary build, must pass.
for target, name in sorted({t for ts in chosen.values() for t in ts}):
    for features in (True, False):
        result = cargo(target, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {target}::{name}")
print(f"domain-scope security-fix mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
