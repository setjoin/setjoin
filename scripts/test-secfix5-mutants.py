#!/usr/bin/env python3
"""Restore each fixed device/quarantine/Exchange security bug (owner-approved security fixes
2026-11-05, #511: #434 #435 #440 #448 and #513 item 1) in an explicit test-only build and
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

GW, AZ = "setjoin-gateway", "setjoin-authz"
# (package, test target, test filter) triples; every one must fail under the mutant.
EXCHANGE = [(GW, "secfix5", "exchange_group_domain_scope_confines_a_scoped_admin"), (GW, "exchange", "create_project_group_scope")]
LOCKDOWN = [
    (GW, "secfix5", "lockdown_console_is_confined_to_the_callers_reach"),
    (GW, "devices", "transition_foreign_target"),
]
LOCKDOWN_READ = [
    (GW, "secfix5", "lockdown_console_is_confined_to_the_callers_reach"),
    (GW, "devices", "queue_foreign_target"),
]
OFFLINE = [
    (GW, "secfix5", "offline_devices_are_confined_to_the_callers_reach"),
    (GW, "offline", "q_wipe_foreign"),
]
OFFLINE_PENDING = [
    (GW, "secfix5", "offline_devices_are_confined_to_the_callers_reach"),
    (GW, "offline", "q_pending_foreign"),
]
QUARANTINE = [
    (GW, "secfix5", "quarantine_admin_actions_are_confined_to_the_callers_reach"),
    (GW, "mailsec_quarantine", "admin_preview_scoped"),
]
QUARANTINE_WRITE = [
    (GW, "secfix5", "quarantine_admin_actions_are_confined_to_the_callers_reach"),
    (GW, "mailsec_quarantine", "admin_release_scoped"),
    (GW, "mailsec_quarantine", "admin_reject_scoped"),
]
RESEAL = [
    (AZ, "device_credential", "legacy_plaintext_secret_is_resealed_under_app_rls"),
    (GW, "static_recorded", "telemetry_proof_legacy_valid"),
]

# mutant id -> list of (package, target, filter); a "sql:" id reloads a bug-restored reducer.
MUTANTS = {
    "lockdown-foreign-target": LOCKDOWN + LOCKDOWN_READ[1:],
    "offline-foreign-device": OFFLINE + OFFLINE_PENDING[1:],
    "quarantine-admin-unscoped": QUARANTINE,
    "device-reseal-under-rls": RESEAL,
    "sql:exchange-group-scope-ignored": EXCHANGE,
    "sql:lockdown-transition-ignores-scope": LOCKDOWN,
    "sql:offline-command-ignores-reach": OFFLINE,
    "sql:offline-pending-unscoped": OFFLINE_PENDING,
    "sql:quarantine-release-any-domain": QUARANTINE_WRITE,
}


def exchange_group_scope_ignored(text):
    out = text.replace("COALESCE(a.domain_override,g.domain_scope)", "a.domain_override")
    assert out != text, "exchange reducer drifted from the mutant recipe"
    return out


def lockdown_ignores_scope(text):
    out, n = re.subn(r"    IF p_in_scope IS DISTINCT FROM TRUE THEN\n.*?    END IF;\n", "", text, flags=re.S)
    assert n == 1, "transition reducer drifted from the mutant recipe"
    return out


def offline_ignores_reach(text):
    out, n = re.subn(r"    IF p_action IN \('approve','deny','revoke','wipe'\) AND p_reach IS DISTINCT FROM TRUE THEN\n.*?    END IF;\n", "", text, flags=re.S)
    assert n == 1, "offline command reducer drifted from the mutant recipe"
    return out


def pending_unscoped(text):
    out = text.replace("\n       AND admin_can_reach_perm(p_actor, d.user_id, ARRAY['mam.read'])", "")
    assert out != text, "pending reducer drifted from the mutant recipe"
    return out


def quarantine_any_domain(text):
    out, n = re.subn(
        r"AND \(CASE WHEN p_admin\n\s+THEN admin_can_reach_perm\(.*?\)\n\s+ELSE (mailbox_id IN \(SELECT id FROM mailboxes WHERE user_id = p_actor\)) END\)",
        r"AND (p_admin OR \1)", text, flags=re.S)
    assert n == 2, "quarantine reducers drifted from the mutant recipe"
    return out


SQL = {
    "sql:exchange-group-scope-ignored": (["exchange_assessment_domain_authorized.sql"], exchange_group_scope_ignored),
    "sql:lockdown-transition-ignores-scope": (["rust_device_enroll_transition.sql"], lockdown_ignores_scope),
    "sql:offline-command-ignores-reach": (["rust_offline_command.sql"], offline_ignores_reach),
    "sql:offline-pending-unscoped": (["rust_offline_devices_pending.sql"], pending_unscoped),
    "sql:quarantine-release-any-domain": (["rust_mailsec_quarantine.sql"], quarantine_any_domain),
}
ALL_FILES = sorted({f for files, _ in SQL.values() for f in files} | {"rust_device_secret_reseal.sql"})


def cargo(package, target, name, env_extra, features):
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
