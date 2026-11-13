#!/usr/bin/env python3
"""Restore each fixed bug (owner-approved security fixes 2026-11-07, #536 Microsoft migration:
calendar ownership, Graph bearer origin pinning, worker-only auxiliary-object reducers) in an
explicit test-only build and require the secure-behaviour test to reject it; then require the
same build without a mutant, and the ordinary build, to pass them.

Rust mutants: feature `oracle-mutants`, env SETJOIN_SECFIX3_MUTANT (setjoin_contracts).
`sql:` mutants load a bug-restored reducer (the apply_worker_ownership footer that grants
setjoin_app EXECUTE) into the assigned disposable database and always reload the repository
copy afterwards.

Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, DB_APP_DSN, ...) and
psql. Optional argv: mutant ids to rerun.
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

GW = ("setjoin-gateway", "setjoin_gateway", "SETJOIN_SECFIX3_MUTANT", "secfix9")
# mutant id -> (spec, test name)
MUTANTS = {
    "m365-aux-mailbox-as-calendar": (GW, "legacy_calendar_projection_writes_only_the_target_mailboxs_own_calendar"),
    "m365-aux-mailbox-as-calendar-no-default": (GW, "legacy_calendar_projection_fails_closed_without_a_default_calendar"),
    "m365-restore-any-origin": (GW, "restored_delta_links_must_stay_on_the_graph_origin"),
    "m365-bearer-any-origin": (GW, "a_next_link_to_another_origin_never_receives_the_bearer_token"),
    "m365-cross-cloud": (GW, "the_two_graph_clouds_refuse_each_others_links"),
    "m365-probe-error-ignored": (GW, "a_failed_conflict_probe_fails_the_row_and_inserts_nothing"),
    "sql:aux-apply-app-grant": (GW, "auxiliary_object_reducers_are_worker_only"),
    "sql:aux-begin-app-grant": (GW, "auxiliary_object_reducers_are_worker_only"),
    "sql:aux-complete-app-grant": (GW, "auxiliary_object_reducers_are_worker_only"),
}
# Mutant id -> env value actually read by the code (two ids share one code flag).
RUST_FLAG = {"m365-aux-mailbox-as-calendar-no-default": "m365-aux-mailbox-as-calendar"}
REDUCERS = repo / "mailserver/sql/reducers"
APPLY = ("rust_migration_apply_aux_object.sql", "rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text)")
BEGIN = ("migration_aux_object_begin.sql", "migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text)")
COMPLETE = ("migration_aux_object_complete.sql", "migration_aux_object_complete(bigint,uuid,text,text,bigint)")


def worker_only(signature):
    return f"""-- Worker-only function ACLs (security_event_enqueue.sql:72-78 form, #536). NOT
-- apply_worker_ownership(): that applicator grants setjoin_app EXECUTE, and these definer
-- functions take a caller-chosen job id that alone selects the target mailbox, so only the
-- migration worker credential may run them.
ALTER FUNCTION {signature} OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION {signature} FROM PUBLIC;
REVOKE ALL ON FUNCTION {signature} FROM setjoin_app;
REVOKE ALL ON FUNCTION {signature} FROM setjoin_owner;
GRANT EXECUTE ON FUNCTION {signature} TO setjoin_worker;"""


def go_grant(signature):
    return f"SELECT public.apply_worker_ownership('{signature}'::regprocedure);"


def swapped(spec):
    name, signature = spec
    path = REDUCERS / name
    text = path.read_text()
    assert text.count(worker_only(signature)) == 1, f"{name} drifted from the mutant recipe"
    return path, text.replace(worker_only(signature), go_grant(signature))


SQL = {
    "sql:aux-apply-app-grant": APPLY,
    "sql:aux-begin-app-grant": BEGIN,
    "sql:aux-complete-app-grant": COMPLETE,
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
            path, body = swapped(SQL[mutant])
            touched.add(path)
            with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
                f.write(body)
            load(f.name)
            os.unlink(f.name)
            result = cargo(spec, name, {}, False)
            load(path)
        else:
            result = cargo(spec, name, {spec[2]: RUST_FLAG.get(mutant, mutant)}, True)
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
print(f"SECFIX9 mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
