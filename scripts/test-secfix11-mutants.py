#!/usr/bin/env python3
"""Restore each fixed bug (owner-approved security fixes 2026-11-05, #542: deploy wizard and
airgap upload review of #455, storage read routes review of #537) in an explicit test-only
build and require the secure-behaviour tests to reject it; then require the same build without
a mutant, and the ordinary build, to pass them.

Mutants: feature `oracle-mutants` (setjoin-platform and setjoin-gateway), selected by
SETJOIN_SECFIX3_MUTANT (setjoin_contracts::mutants). Needs REQUIRE_DB=1, the assigned
disposable DSNs (TEST_DB_DSN, DB_DSN, DB_APP_DSN, ...), psql and
GOFREE_AIRGAP_FIXTURE_ROOT=/dev/shm (set here when unset). Optional argv: mutant ids to rerun.
"""
import os
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[1]
root = repo / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")
os.environ.setdefault("GOFREE_AIRGAP_FIXTURE_ROOT", "/dev/shm")

# (package, cargo target args, test name)
LIB = ("setjoin-platform", ["--lib"])
NEW = ("setjoin-gateway", ["--test", "secfix11"])
DEPLOY = ("setjoin-gateway", ["--test", "platform_deploy"])
AIRGAP = ("setjoin-gateway", ["--test", "platform_airgap"])
STORAGE = ("setjoin-gateway", ["--test", "platform_storage_runtime"])
JOBS = ("setjoin-gateway", ["--test", "platform_jobs_storage"])
SCOPE = (NEW, "scoped_system_upgrade_cannot_deploy_or_upload")
MUTANTS = {
    "upgrade-scoped-grant-deploy-start": [SCOPE, (DEPLOY, "start_scoped")],
    "upgrade-scoped-grant-deploy-cancel": [SCOPE, (DEPLOY, "cancel_scoped")],
    "upgrade-scoped-grant-deploy-status": [SCOPE, (DEPLOY, "status_scoped")],
    "upgrade-scoped-grant-airgap-upload": [SCOPE, (AIRGAP, "upload_scoped")],
    "storage-read-scoped-status": [(STORAGE, "status_scoped")],
    "storage-read-scoped-scan-list": [(JOBS, "dr_list_scoped")],
    "storage-read-scoped-scan-get": [(JOBS, "dr_get_scoped")],
    "storage-read-scoped-migrate-list": [(JOBS, "migrate_list_scoped")],
    "storage-read-scoped-migrate-get": [(JOBS, "migrate_get_scoped")],
    "deploy-ssh-output-unbounded": [(LIB, "remote_output_is_capped_while_reading")],
    "deploy-body-uncapped": [(NEW, "deploy_body_is_capped")],
    "deploy-node-unvalidated": [(LIB, "hostile_node_fields_are_refused"), (NEW, "deploy_node_fields_are_validated")],
    "deploy-host-unquoted": [(LIB, "commands_never_carry_an_unquoted_node_host")],
    "deploy-ssh-key-path": [(NEW, "deploy_key_path_is_never_read")],
    "deploy-fence-memory-only": [(NEW, "deploy_fence_survives_restart")],
    "airgap-floor-sidecar-only": [(NEW, "airgap_rollback_floor_survives_pruning_and_restart")],
    "airgap-floor-memory-lags": [(NEW, "airgap_floor_holds_after_a_failed_publish")],
}


def cargo(spec, name, mutant, features):
    package, target = spec
    cmd = ["cargo", "test", "--locked", "-p", package]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += target + [name, "--", "--test-threads=1"]
    env = {**os.environ}
    env.pop("SETJOIN_SECFIX3_MUTANT", None)
    if mutant:
        env["SETJOIN_SECFIX3_MUTANT"] = mutant
    return subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
for mutant, tests in chosen.items():
    for spec, name in tests:
        result = cargo(spec, name, mutant, True)
        if result.returncode != 101 or "test result: FAILED." not in result.stdout:
            print(result.stdout[-3000:])
            sys.exit(f"mutant survived (not rejected): {mutant} by {name}")
        why = [l for l in result.stdout.splitlines() if "panicked at" in l or l.startswith(("assertion", "left", "right"))]
        print(f"MUTANT-REJECTED: {mutant} by {name} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
# The same build without a mutant selected, then the ordinary build, must pass.
seen = sorted({(tuple(spec[0:1]) + tuple(spec[1]), name) for tests in chosen.values() for spec, name in tests})
for (package, *target), name in seen:
    for features in (True, False):
        result = cargo((package, target), name, None, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {package} {target} {name}")
print(f"SECFIX11 mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
