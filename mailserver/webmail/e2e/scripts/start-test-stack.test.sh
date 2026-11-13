#!/usr/bin/env bash
# SEC-TEMP-HYGIENE: start-test-stack.sh proves the predictable INSTANCE_DIR is
# ours before writing or executing anything from it. Negative arms: a
# world-writable or foreign-owned pre-created dir and a symlinked dir fail
# loud with nothing executed or written into them. Positive arm: a fresh run
# passes the gate and creates the dir 0700. Exclusive-creation arms (the
# plant-between-check-and-create race, Astra wave12-14 med-shard2-005): the
# INSTANCE_DIR mkdir must stay atomic-exclusive (no -p), and on EEXIST a
# benign own-owned planted dir is adopted only after the full hostility
# re-check — hostile shapes on that same path are refused by arms 1/2/4. All
# arms run against a sandboxed TMPDIR, unused ports, a skipped webmail build,
# and an unreachable Postgres, so nothing outside the sandbox is touched.
#
# L2-C9 arms (7-14): the e2e DB-target guard (scripts/e2e-test-db-guard.sh).
# Wrong DB names and remote hosts are refused before ANY filesystem effect
# (the guard precedes INSTANCE_DIR derivation); the connected
# cluster-identity + disposable-marker gate is exercised hermetically via a
# PATH-shimmed psql (registry seeded in the sandbox, real loaders never run):
# absent-DB pass, marker pass, empty/foreign-marker refusal, unowned-cluster
# refusal even with an absent DB (r2), replacement-cluster identity-mismatch
# and unreadable-identity refusals (r3), an explicit --bootstrap arm, a
# source pin that the pure guard precedes INSTANCE_DIR creation and the gate
# precedes both destructive mutation sites, and pins on the shipped
# quoted-variable SQL form in the loader and the guard. Arm 14 (r4, Astra
# HOLD): marker CONTENT is not trusted at read time without the bootstrap
# writer's FILE provenance — planted content-valid markers with a hostile
# namespace (loose mode, foreign owner, symlink, non-regular file, hostile
# registry dirs) are refused before any probe, while the same content in
# bootstrap posture still passes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
SCRIPT="$ROOT/mailserver/webmail/e2e/scripts/start-test-stack.sh"
[[ -f "$SCRIPT" ]] || {
  echo 'E_SEC_E2EINSTANCE target script missing' >&2
  exit 1
}

sandbox="$(mktemp -d)"
trap 'rm -rf "$sandbox"' EXIT

run_stack_env() {
  env TMPDIR="$sandbox" \
    E2E_DB_NAME="mailserver_e2e" \
    E2E_GATEWAY_PORT="18808" \
    E2E_AUTH_PORT="18443" \
    E2E_S3_PORT="19000" \
    E2E_SMTP_INBOUND_PORT="11025" \
    E2E_SMTP_SUBMISSION_PORT="11587" \
    E2E_IMAP_PORT="11143" \
    E2E_SKIP_WEBMAIL_BUILD="1" \
    E2E_PGHOST="127.0.0.1" \
    E2E_PGPORT="1" \
    "$@" \
    bash "$SCRIPT" 2>&1
  return "$?"
}

run_stack() { run_stack_env; }

assert_refused() {
  local out="$1" marker="$2"
  grep -q 'refusing' <<<"$out" || {
    echo "E_SEC_E2EINSTANCE hostile INSTANCE_DIR not refused loudly: $out" >&2
    exit 1
  }
  [[ -e "$marker" ]] || {
    echo 'E_SEC_E2EINSTANCE hostile INSTANCE_DIR contents were disturbed' >&2
    exit 1
  }
  [[ ! -e "$sandbox/setjoin-e2e-mailserver_e2e-18808/gateway" ]] || {
    echo 'E_SEC_E2EINSTANCE binary was written into hostile INSTANCE_DIR' >&2
    exit 1
  }
}

# ── Arm 1: pre-created world-writable INSTANCE_DIR fails loud, never used ──
mkdir -m 0777 "$sandbox/setjoin-e2e-mailserver_e2e-18808"
echo planted >"$sandbox/setjoin-e2e-mailserver_e2e-18808/planted"
out="$(run_stack)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo "E_SEC_E2EINSTANCE world-writable INSTANCE_DIR accepted: $out" >&2
  exit 1
}
assert_refused "$out" "$sandbox/setjoin-e2e-mailserver_e2e-18808/planted"
rm -rf "$sandbox/setjoin-e2e-mailserver_e2e-18808"

# ── Arm 2: symlinked INSTANCE_DIR fails loud, never followed ──
mkdir -p "$sandbox/link-target"
ln -s "$sandbox/link-target" "$sandbox/setjoin-e2e-mailserver_e2e-18808"
out="$(run_stack)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo "E_SEC_E2EINSTANCE symlinked INSTANCE_DIR accepted: $out" >&2
  exit 1
}
grep -q 'symlink' <<<"$out" || {
  echo "E_SEC_E2EINSTANCE symlinked INSTANCE_DIR not named: $out" >&2
  exit 1
}
assert_refused "$out" "$sandbox/link-target"
rm -rf "$sandbox/setjoin-e2e-mailserver_e2e-18808" "$sandbox/link-target"

# ── Arm 3: a fresh run passes the gate and creates the dir owner-only ──
out="$(run_stack)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo "E_SEC_E2EINSTANCE sandbox run unexpectedly fully started: $out" >&2
  exit 1
}
grep -q 'refusing' <<<"$out" && {
  echo "E_SEC_E2EINSTANCE fresh INSTANCE_DIR wrongly refused: $out" >&2
  exit 1
}
# shellcheck disable=SC2012
perm="$(ls -ld "$sandbox/setjoin-e2e-mailserver_e2e-18808" | cut -c1-10)"
[[ "$perm" == "drwx------" ]] || {
  echo "E_SEC_E2EINSTANCE fresh INSTANCE_DIR is not 0700 (got $perm)" >&2
  exit 1
}
# C9 positive arm: the pure target guard passed (validation line present, no
# refusal fired) before the run proceeded to its expected unreachable-Postgres
# stop.
grep -q 'e2e-db-guard: validated local disposable database mailserver_e2e' <<<"$out" || {
  echo 'E_SEC_E2EDBGUARD fresh run is missing the C9 target-guard validation line' >&2
  exit 1
}
if grep -q 'E_SEC_E2E_DB_TARGET' <<<"$out"; then
  echo 'E_SEC_E2EDBGUARD fresh run wrongly refused by the C9 target guard' >&2
  exit 1
fi

# ── Arm 5: exclusive-creation primitive (plant-between-check-and-create race) ──
# True interposition between the old separate checks and mkdir is not
# schedulable from a test (the window is a single mkdir(2)), so the primitive
# is tested directly:
#  (a) source: INSTANCE_DIR creation must remain atomic-exclusive `mkdir
#      -m 0700` WITHOUT -p — `mkdir -p` silently adopts a planted path and
#      never enforces the requested mode, which is the exact regression shape;
#  (b) behavior: on EEXIST a benign own-owned planted dir (what a lost race
#      against our own previous run looks like) is ADOPTED — tightened to
#      0700, contents untouched — never refused and never recreated over;
#      hostile shapes on this same EEXIST path are refused by arms 1/2/4.
if grep 'mkdir' "$SCRIPT" | grep 'INSTANCE_DIR' | grep -q -- '-p'; then
  echo 'E_SEC_E2EINSTANCE race arm: INSTANCE_DIR creation lost atomic exclusivity (mkdir -p reintroduced)' >&2
  exit 1
fi
rm -rf "$sandbox/setjoin-e2e-mailserver_e2e-18808" # Arm 3's fresh run leaves its dir behind
mkdir -m 0755 "$sandbox/setjoin-e2e-mailserver_e2e-18808"
echo planted >"$sandbox/setjoin-e2e-mailserver_e2e-18808/planted"
out="$(run_stack)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo "E_SEC_E2EINSTANCE sandbox run unexpectedly fully started: $out" >&2
  exit 1
}
grep -q 'refusing' <<<"$out" && {
  echo "E_SEC_E2EINSTANCE benign own-owned INSTANCE_DIR wrongly refused: $out" >&2
  exit 1
}
# shellcheck disable=SC2012
perm="$(ls -ld "$sandbox/setjoin-e2e-mailserver_e2e-18808" | cut -c1-10)"
[[ "$perm" == "drwx------" ]] || {
  echo "E_SEC_E2EINSTANCE adopted INSTANCE_DIR was not tightened to 0700 (got $perm)" >&2
  exit 1
}
[[ -f "$sandbox/setjoin-e2e-mailserver_e2e-18808/planted" ]] || {
  echo 'E_SEC_E2EINSTANCE adopted INSTANCE_DIR was recreated instead of re-checked (planted marker lost)' >&2
  exit 1
}
rm -rf "$sandbox/setjoin-e2e-mailserver_e2e-18808"

# ── Arm 6 (root only): foreign-owned INSTANCE_DIR fails loud ──
if [[ "$(id -u)" == "0" ]]; then
  mkdir -p "$sandbox/setjoin-e2e-mailserver_e2e-18808"
  chown -R nobody "$sandbox/setjoin-e2e-mailserver_e2e-18808"
  out="$(run_stack)" && rc=0 || rc=$?
  [[ "$rc" -ne 0 ]] || {
    echo "E_SEC_E2EINSTANCE foreign-owned INSTANCE_DIR accepted: $out" >&2
    exit 1
  }
  grep -q "not owned by uid 0" <<<"$out" || {
    echo "E_SEC_E2EINSTANCE foreign-owned INSTANCE_DIR not refused: $out" >&2
    exit 1
  }
fi

# ── C9 arm 7: wrong DB names refused with E_SEC_E2E_DB_TARGET BEFORE any ──
# filesystem effect for that name (the pure guard precedes INSTANCE_DIR
# derivation, which would embed the name in the path).
for c9_bad in postgres mailserver; do
  out="$(run_stack_env "E2E_DB_NAME=$c9_bad")" && rc=0 || rc=$?
  [[ "$rc" -ne 0 ]] || {
    echo "E_SEC_E2EDBGUARD non-disposable DB name accepted: $c9_bad: $out" >&2
    exit 1
  }
  grep -q 'E_SEC_E2E_DB_TARGET problem=invalid_test_database' <<<"$out" || {
    echo "E_SEC_E2EDBGUARD non-disposable DB name not named as such: $c9_bad: $out" >&2
    exit 1
  }
  [[ ! -e "$sandbox/setjoin-e2e-${c9_bad}-18808" ]] || {
    echo "E_SEC_E2EDBGUARD INSTANCE_DIR was created for a refused name: $c9_bad" >&2
    exit 1
  }
done

# ── C9 arm 8: remote PG host refused before any filesystem or network ──────
# effect (the loopback assertion sits in the same pure pre-INSTANCE_DIR call).
out="$(run_stack_env "E2E_PGHOST=db.internal.example.com")" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo "E_SEC_E2EDBGUARD remote database host accepted: $out" >&2
  exit 1
}
grep -q 'E_SEC_E2E_DB_TARGET problem=remote_database_host' <<<"$out" || {
  echo "E_SEC_E2EDBGUARD remote host not refused as such: $out" >&2
  exit 1
}
grep -q 'db.internal.example.com' <<<"$out" || {
  echo 'E_SEC_E2EDBGUARD remote-host refusal does not name the host' >&2
  exit 1
}
[[ ! -e "$sandbox/setjoin-e2e-mailserver_e2e-18808" ]] || {
  echo 'E_SEC_E2EDBGUARD filesystem effects happened despite the remote-host refusal' >&2
  exit 1
}

# ── C9 arms 9-13 harness: hermetic PATH-shimmed psql + sandboxed registry ──
# The shim records every invocation (argv + stdin SQL) and answers the two
# catalog probes the connected guard makes. The real loaders are never run.
c9_shim="$sandbox/c9-shim"
c9_registry="$sandbox/c9-registry"
mkdir -m 0700 "$c9_shim"
cat >"$c9_shim/psql" <<'EOF'
#!/bin/sh
# C9 test shim: never touches a real server. Answers pg_control_system() with
# $C9_SHIM_IDENTITY and the db-state probe with $C9_SHIM_DB_STATE.
c9_query="$(cat)"
{ printf '%s\n' "$*"; printf '%s\n' "$c9_query"; printf '%s\n' '--- end-of-query ---'; } >>"$C9_SHIM_LOG"
case "$c9_query" in
  *pg_control_system*) printf '%s\n' "$C9_SHIM_IDENTITY" ;;
  *) printf '%s\n' "$C9_SHIM_DB_STATE" ;;
esac
exit 0
EOF
chmod +x "$c9_shim/psql"

c9_seed_marker() {
  # $1 = system_identifier recorded for endpoint 127.0.0.1:1 (arm PG port 1).
  # Bootstrap-writer posture: 0700 registry + endpoint dir, 0600 marker
  # (arm 14's read-time namespace validation runs against this).
  mkdir -p "$c9_registry/127.0.0.1_1"
  chmod 0700 "$c9_registry" "$c9_registry/127.0.0.1_1"
  printf 'endpoint=127.0.0.1:1\nsystem_identifier=%s\ncreated=2026-09-12T00:00:00Z\n' "$1" \
    >"$c9_registry/127.0.0.1_1/marker"
  chmod 0600 "$c9_registry/127.0.0.1_1/marker"
}

c9_gate() {
  # Sources the guard and runs the connected gate against the shim. Later
  # env args (e.g. registry/shim overrides) win over the defaults. The
  # positional-$1 bash -c form is an intentional literal (SC2016 pinned).
  # shellcheck disable=SC2016
  env PATH="$c9_shim:$PATH" \
    C9_SHIM_LOG="$c9_shim/calls.log" \
    DB_NAME="mailserver_e2e" \
    E2E_PGHOST="127.0.0.1" \
    E2E_PGPORT="1" \
    E2E_PGUSER="mail" \
    E2E_CLUSTER_REGISTRY="$c9_registry" \
    "$@" \
    bash -c 'source "$1" && e2e_validate_test_db_cluster' guard "$ROOT/scripts/e2e-test-db-guard.sh" 2>&1
  return "$?"
}

# ── C9 arm 9: hermetic marker matrix on an OWNED (identity-matched) cluster.
# Also pins the shipped SQL form: the probe must arrive as quoted psql
# variables (r2-2.3), not concatenated SQL.
: >"$c9_shim/calls.log"
c9_seed_marker '7399960342260465476'
out="$(c9_gate C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -eq 0 ]] || {
  echo "C9 arm 9a: absent DB on an owned disposable cluster wrongly refused: $out" >&2
  exit 1
}
grep -q "shobj_description(oid, 'pg_database')" "$c9_shim/calls.log" || {
  echo 'C9 arm 9a: guard probe did not use shobj_description' >&2
  exit 1
}
grep -q "datname = :'db_name'" "$c9_shim/calls.log" || {
  echo "C9 arm 9a: probe SQL is not the quoted :'db_name' variable form" >&2
  exit 1
}
grep -q -- '-v db_name=mailserver_e2e' "$c9_shim/calls.log" || {
  echo 'C9 arm 9a: probe did not pass db_name as a psql variable' >&2
  exit 1
}
grep -q 'pg_control_system' "$c9_shim/calls.log" || {
  echo 'C9 arm 9a: gate did not read cluster identity' >&2
  exit 1
}
: >"$c9_shim/calls.log"
out="$(c9_gate C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='setjoin-disposable-test-db')" && rc=0 || rc=$?
[[ "$rc" -eq 0 ]] || {
  echo "C9 arm 9b: prior e2e DB with matching marker wrongly refused: $out" >&2
  exit 1
}
: >"$c9_shim/calls.log"
out="$(c9_gate C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 9c: present DB with EMPTY marker accepted' >&2
  exit 1
}
grep -q 'problem=missing_disposable_marker' <<<"$out" || {
  echo "C9 arm 9c: empty marker not refused as such: $out" >&2
  exit 1
}
: >"$c9_shim/calls.log"
out="$(c9_gate C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='operator-data-do-not-drop')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 9d: present DB with FOREIGN marker accepted' >&2
  exit 1
}
grep -q 'problem=missing_disposable_marker' <<<"$out" || {
  echo "C9 arm 9d: foreign marker not refused as such: $out" >&2
  exit 1
}
grep -q 'mailserver_e2e' <<<"$out" || {
  echo 'C9 arm 9d: foreign-marker refusal does not name the DB' >&2
  exit 1
}

# ── C9 arm 10 (r2-1.4): unowned local cluster with an ABSENT target DB is ──
# refused loudly BEFORE any provisioning/destructive statement can run — no
# silent first-run admission, and the refusal names the endpoint/ownership.
c9_registry_empty="$sandbox/c9-registry-empty"
mkdir -p "$c9_registry_empty"
: >"$c9_shim/calls.log"
out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_registry_empty" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo "C9 arm 10: unowned cluster with absent DB silently admitted: $out" >&2
  exit 1
}
grep -q 'problem=unowned_cluster' <<<"$out" || {
  echo "C9 arm 10: refusal does not name cluster ownership: $out" >&2
  exit 1
}
grep -q '127.0.0.1:1' <<<"$out" || {
  echo 'C9 arm 10: refusal does not name the endpoint' >&2
  exit 1
}
grep -q -- '--bootstrap' <<<"$out" || {
  echo 'C9 arm 10: refusal lacks the bootstrap instruction' >&2
  exit 1
}
[[ ! -s "$c9_shim/calls.log" ]] || {
  echo 'C9 arm 10: gate reached the database despite the missing ownership marker' >&2
  exit 1
}

# ── C9 arm 11 (r3-1.3): a VALID OLD marker for the endpoint against a ──────
# REPLACEMENT cluster at the same endpoint must refuse with expected vs
# observed identity; an unreadable identity must refuse too.
: >"$c9_shim/calls.log"
c9_seed_marker '11112222333344445555'
out="$(c9_gate C9_SHIM_IDENTITY='66667777888899990000' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 11a: replacement cluster admitted via stale valid marker' >&2
  exit 1
}
grep -q 'problem=cluster_identity_mismatch' <<<"$out" || {
  echo "C9 arm 11a: identity mismatch not refused as such: $out" >&2
  exit 1
}
grep -q 'expected=11112222333344445555' <<<"$out" || {
  echo 'C9 arm 11a: refusal does not name the expected identifier' >&2
  exit 1
}
grep -q 'observed=66667777888899990000' <<<"$out" || {
  echo 'C9 arm 11a: refusal does not name the observed identifier' >&2
  exit 1
}
grep -q -- '--bootstrap' <<<"$out" || {
  echo 'C9 arm 11a: mismatch refusal lacks the re-bootstrap instruction' >&2
  exit 1
}
: >"$c9_shim/calls.log"
out="$(c9_gate C9_SHIM_IDENTITY='' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 11b: unreadable cluster identity accepted' >&2
  exit 1
}
grep -q 'problem=cluster_identity_unreadable' <<<"$out" || {
  echo "C9 arm 11b: unreadable identity not refused as such: $out" >&2
  exit 1
}

# ── C9 arm 12: source pin (arm-5 style). The pure guard must textually
# precede INSTANCE_DIR creation, and the connected identity gate must
# textually precede BOTH cluster-global mutation sites (the destructive load
# — which also runs provision-roles.sql — and the ALTER ROLE password
# resets), so the gate cannot drift below the destructive ops. Also pins the
# shipped quoted-variable SQL forms in the loader and the guard file.
c9_line_of() { grep -n "$1" "$2" | head -1 | cut -d: -f1; }
c9_guard_src="$(c9_line_of 'scripts/e2e-test-db-guard.sh' "$SCRIPT")"
c9_pure_call="$(c9_line_of 'e2e_validate_test_db || exit' "$SCRIPT")"
c9_instance_dir="$(c9_line_of '^INSTANCE_DIR=' "$SCRIPT")"
c9_gate_call="$(c9_line_of 'e2e_validate_test_db_cluster || exit' "$SCRIPT")"
# Intentional literal: the pin must match the source text verbatim.
# shellcheck disable=SC2016
c9_load_call="$(c9_line_of 'bash "$ROOT/scripts/load-test-schema.sh"' "$SCRIPT")"
c9_role_reset="$(c9_line_of 'ALTER ROLE setjoin_app' "$SCRIPT")"
[[ "$c9_guard_src" -lt "$c9_pure_call" ]] || {
  echo 'C9 arm 12: guard source does not precede the pure validation call' >&2
  exit 1
}
[[ "$c9_pure_call" -lt "$c9_instance_dir" ]] || {
  echo 'C9 arm 12: pure guard call drifted below INSTANCE_DIR creation' >&2
  exit 1
}
[[ "$c9_gate_call" -lt "$c9_load_call" ]] || {
  echo 'C9 arm 12: identity gate drifted below the destructive load call' >&2
  exit 1
}
[[ "$c9_gate_call" -lt "$c9_role_reset" ]] || {
  echo 'C9 arm 12: identity gate drifted below the ALTER ROLE password resets' >&2
  exit 1
}
c9_loader="$ROOT/scripts/load-test-schema.sh"
grep -q 'DROP DATABASE IF EXISTS :"db_name" WITH (FORCE);' "$c9_loader" || {
  echo 'C9 arm 12: loader DROP lost the quoted-variable form (SQL concatenation reintroduced)' >&2
  exit 1
}
grep -q 'CREATE DATABASE :"db_name" OWNER :"db_user" TEMPLATE template0;' "$c9_loader" || {
  echo 'C9 arm 12: loader CREATE lost the quoted-variable form' >&2
  exit 1
}
grep -q "COMMENT ON DATABASE :\"db_name\" IS 'setjoin-disposable-test-db';" "$c9_loader" || {
  echo 'C9 arm 12: loader disposable-marker stamp missing or unquoted' >&2
  exit 1
}
grep -q ":'db_name'" "$ROOT/scripts/e2e-test-db-guard.sh" || {
  echo 'C9 arm 12: guard probe lost the quoted-variable form' >&2
  exit 1
}
grep -q 'ARCH_R2_TEST_MODE' "$ROOT/scripts/e2e-test-db-guard.sh" && {
  echo 'C9 arm 12: the e2e guard must stay kill-switch-free' >&2
  exit 1
}

# ── C9 arm 13: the explicit --bootstrap records endpoint + identity into a ──
# 0600 marker and refuses non-loopback bootstrap targets.
c9_registry_boot="$sandbox/c9-registry-boot"
: >"$c9_shim/calls.log"
out="$(env PATH="$c9_shim:$PATH" \
  C9_SHIM_LOG="$c9_shim/calls.log" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='' \
  E2E_PGHOST='127.0.0.1' E2E_PGPORT='1' E2E_PGUSER='mail' \
  E2E_CLUSTER_REGISTRY="$c9_registry_boot" \
  bash "$ROOT/scripts/e2e-test-db-guard.sh" --bootstrap 2>&1)" && rc=0 || rc=$?
[[ "$rc" -eq 0 ]] || {
  echo "C9 arm 13a: bootstrap of a verified loopback cluster failed: $out" >&2
  exit 1
}
c9_boot_marker="$c9_registry_boot/127.0.0.1_1/marker"
[[ -f "$c9_boot_marker" ]] || {
  echo 'C9 arm 13a: bootstrap wrote no endpoint-keyed marker' >&2
  exit 1
}
grep -q '^system_identifier=7399960342260465476$' "$c9_boot_marker" || {
  echo 'C9 arm 13a: marker does not record the observed system_identifier' >&2
  exit 1
}
grep -q '^endpoint=127.0.0.1:1$' "$c9_boot_marker" || {
  echo 'C9 arm 13a: marker does not record the endpoint' >&2
  exit 1
}
# shellcheck disable=SC2012
perm="$(ls -ld "$c9_boot_marker" | cut -c1-10)"
[[ "$perm" == "-rw-------" ]] || {
  echo "C9 arm 13a: marker is not 0600 (got $perm)" >&2
  exit 1
}
out="$(env PATH="$c9_shim:$PATH" \
  C9_SHIM_LOG="$c9_shim/calls.log" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='' \
  E2E_PGHOST='db.internal.example.com' E2E_PGPORT='1' E2E_PGUSER='mail' \
  E2E_CLUSTER_REGISTRY="$c9_registry_boot" \
  bash "$ROOT/scripts/e2e-test-db-guard.sh" --bootstrap 2>&1)" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 13b: remote bootstrap target accepted' >&2
  exit 1
}
grep -q 'problem=remote_database_host' <<<"$out" || {
  echo "C9 arm 13b: remote bootstrap not refused as such: $out" >&2
  exit 1
}

# ── C9 arm 14 (r4, Astra HOLD): READ-TIME namespace validation. Marker
# CONTENT must not be trusted at verification time without the bootstrap
# writer's FILE provenance. Every shape below carries content that would
# satisfy the endpoint+identity match, so ONLY the read-time namespace
# checks (regular non-symlink 0600 invoking-user-owned marker inside
# regular non-symlink non-group/world-writable invoking-user-owned dirs)
# can refuse it. Refusals must fire before any psql probe.
c9_plant_valid_content() {
  # $1 = registry root. Plants marker content matching the shim identity
  # WITHOUT any posture guarantee beyond what the caller adds.
  mkdir -p "$1/127.0.0.1_1"
  printf 'endpoint=127.0.0.1:1\nsystem_identifier=7399960342260465476\ncreated=2026-09-12T00:00:00Z\n' \
    >"$1/127.0.0.1_1/marker"
}

# 14a: planted mode-0644 marker (content-valid, not bootstrap-written).
c9_ns_a="$sandbox/c9-registry-ns-a"
c9_plant_valid_content "$c9_ns_a"
chmod 0644 "$c9_ns_a/127.0.0.1_1/marker"
: >"$c9_shim/calls.log"
out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_ns_a" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 14a: loose-mode planted marker accepted at read time' >&2
  exit 1
}
grep -q 'problem=marker_hostile' <<<"$out" || {
  echo "C9 arm 14a: loose-mode marker not refused as hostile: $out" >&2
  exit 1
}
grep -q 'cause=marker_not_mode_0600' <<<"$out" || {
  echo "C9 arm 14a: loose-mode marker refusal does not name the mode: $out" >&2
  exit 1
}
[[ ! -s "$c9_shim/calls.log" ]] || {
  echo 'C9 arm 14a: hostile marker contents were read before namespace validation' >&2
  exit 1
}

# 14b: symlinked marker pointing at a valid-content regular file.
c9_ns_b="$sandbox/c9-registry-ns-b"
c9_plant_valid_content "$c9_ns_b"
mv "$c9_ns_b/127.0.0.1_1/marker" "$c9_ns_b/127.0.0.1_1/marker.real"
ln -s "$c9_ns_b/127.0.0.1_1/marker.real" "$c9_ns_b/127.0.0.1_1/marker"
: >"$c9_shim/calls.log"
out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_ns_b" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 14b: symlinked marker accepted at read time' >&2
  exit 1
}
grep -q 'problem=marker_hostile' <<<"$out" || {
  echo "C9 arm 14b: symlinked marker not refused as hostile: $out" >&2
  exit 1
}
grep -q 'cause=marker_path_is_symlink' <<<"$out" || {
  echo "C9 arm 14b: symlinked marker refusal does not name the symlink: $out" >&2
  exit 1
}
[[ ! -s "$c9_shim/calls.log" ]] || {
  echo 'C9 arm 14b: symlinked marker was followed before namespace validation' >&2
  exit 1
}

# 14c: group-writable endpoint directory (planted registry entry posture)
# around an otherwise-valid 0600 marker.
c9_ns_c="$sandbox/c9-registry-ns-c"
c9_plant_valid_content "$c9_ns_c"
chmod 0600 "$c9_ns_c/127.0.0.1_1/marker"
chmod 0770 "$c9_ns_c/127.0.0.1_1"
: >"$c9_shim/calls.log"
out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_ns_c" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 14c: group-writable registry entry accepted at read time' >&2
  exit 1
}
grep -q 'problem=registry_dir_hostile' <<<"$out" || {
  echo "C9 arm 14c: group-writable registry entry not refused as hostile: $out" >&2
  exit 1
}
grep -q 'cause=registry_path_foreign_or_group_writable' <<<"$out" || {
  echo "C9 arm 14c: registry-entry refusal does not name the posture: $out" >&2
  exit 1
}
[[ ! -s "$c9_shim/calls.log" ]] || {
  echo 'C9 arm 14c: probes ran despite the hostile registry entry' >&2
  exit 1
}

# 14d: malformed namespace — the marker path is a DIRECTORY, not a regular
# file.
c9_ns_d="$sandbox/c9-registry-ns-d"
c9_plant_valid_content "$c9_ns_d"
rm -f "$c9_ns_d/127.0.0.1_1/marker"
mkdir "$c9_ns_d/127.0.0.1_1/marker"
: >"$c9_shim/calls.log"
out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_ns_d" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 14d: non-regular marker path accepted at read time' >&2
  exit 1
}
grep -q 'problem=marker_hostile' <<<"$out" || {
  echo "C9 arm 14d: non-regular marker path not refused as hostile: $out" >&2
  exit 1
}
grep -q 'cause=marker_not_a_regular_file' <<<"$out" || {
  echo "C9 arm 14d: non-regular marker refusal does not name the type: $out" >&2
  exit 1
}
[[ ! -s "$c9_shim/calls.log" ]] || {
  echo 'C9 arm 14d: probes ran despite the malformed marker path' >&2
  exit 1
}

# 14e: the registry ROOT itself is a symlink to a valid-content registry.
c9_ns_e_real="$sandbox/c9-registry-ns-e-real"
c9_plant_valid_content "$c9_ns_e_real"
chmod 0600 "$c9_ns_e_real/127.0.0.1_1/marker"
c9_ns_e="$sandbox/c9-registry-ns-e"
ln -s "$c9_ns_e_real" "$c9_ns_e"
: >"$c9_shim/calls.log"
out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_ns_e" \
  C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -ne 0 ]] || {
  echo 'C9 arm 14e: symlinked registry root accepted at read time' >&2
  exit 1
}
grep -q 'problem=registry_dir_hostile' <<<"$out" || {
  echo "C9 arm 14e: symlinked registry root not refused as hostile: $out" >&2
  exit 1
}
grep -q 'cause=registry_path_is_symlink' <<<"$out" || {
  echo "C9 arm 14e: registry-root refusal does not name the symlink: $out" >&2
  exit 1
}
[[ ! -s "$c9_shim/calls.log" ]] || {
  echo 'C9 arm 14e: symlinked registry root was followed before validation' >&2
  exit 1
}

# 14f (root only): foreign-owned 0600 marker with valid content.
if [[ "$(id -u)" == "0" ]]; then
  c9_ns_f="$sandbox/c9-registry-ns-f"
  c9_plant_valid_content "$c9_ns_f"
  chmod 0600 "$c9_ns_f/127.0.0.1_1/marker"
  chown nobody "$c9_ns_f/127.0.0.1_1/marker"
  : >"$c9_shim/calls.log"
  out="$(c9_gate E2E_CLUSTER_REGISTRY="$c9_ns_f" \
    C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
  [[ "$rc" -ne 0 ]] || {
    echo 'C9 arm 14f: foreign-owned marker accepted at read time' >&2
    exit 1
  }
  grep -q 'problem=marker_hostile' <<<"$out" || {
    echo "C9 arm 14f: foreign-owned marker not refused as hostile: $out" >&2
    exit 1
  }
  grep -q 'cause=marker_not_owned_by_invoking_user' <<<"$out" || {
    echo "C9 arm 14f: foreign-owned marker refusal does not name the owner: $out" >&2
    exit 1
  }
fi

# 14g: positive control — the SAME content in bootstrap-writer posture
# (0700 dirs, 0600 own-owned marker) still passes the read-time checks.
c9_registry_pristine="$sandbox/c9-registry-pristine"
mkdir -m 0700 "$c9_registry_pristine"
c9_registry="$c9_registry_pristine"
c9_seed_marker '7399960342260465476'
out="$(c9_gate C9_SHIM_IDENTITY='7399960342260465476' C9_SHIM_DB_STATE='db-absent')" && rc=0 || rc=$?
[[ "$rc" -eq 0 ]] || {
  echo "C9 arm 14g: bootstrap-posture registry wrongly refused by read-time validation: $out" >&2
  exit 1
}

# 15: rehearsal flip seam source pins — the E2E_GATEWAY_FLIP_DIR control must
# stay opt-in (unset means the untouched plain watch loop), and a flip request
# must be refused unless the target is a complete web root (index.html plus
# _app/version.json) with an absolute websiteDir. Only the gateway relaunches;
# the database, SeaweedFS, and authserver children are never killed on flip.
grep -q 'FLIP_DIR="${E2E_GATEWAY_FLIP_DIR:-}"' "$SCRIPT" || {
  echo 'arm 15: flip control is not opt-in via E2E_GATEWAY_FLIP_DIR' >&2
  exit 1
}
grep -q 'while true; do sleep 5; done' "$SCRIPT" || {
  echo 'arm 15: the unchanged plain watch loop for ordinary runs is missing' >&2
  exit 1
}
grep -q '\[ ! -f "$target/index.html" \] \|\[ ! -f "$target/_app/version.json" \]' "$SCRIPT" || {
  echo 'arm 15: flip target completeness check (index.html, _app/version.json) is missing' >&2
  exit 1
}
grep -q 'websiteDir must be a non-empty absolute path' "$SCRIPT" || {
  echo 'arm 15: flip target absoluteness check is missing' >&2
  exit 1
}
flip_block="$(sed -n '/^watch_gateway_flips() {/,/^}/p' "$SCRIPT")"
[[ -n "$flip_block" ]] || {
  echo 'arm 15: watch_gateway_flips function missing' >&2
  exit 1
}
if grep -q 'AUTH_PID\|WEED_PID' <<<"$flip_block"; then
  echo 'arm 15: flip path must never stop the authserver or SeaweedFS children' >&2
  exit 1
fi
grep -q 'launch_gateway' <<<"$flip_block" || {
  echo 'arm 15: flip path must relaunch through the single launch_gateway site' >&2
  exit 1
}

echo 'security start-test-stack: PASS (world-writable/symlink/foreign-owned INSTANCE_DIR refused without use, fresh dir created 0700 atomically, planted benign dir adopted only after EEXIST hostility re-check; C9 DB-target guard: non-disposable names and remote hosts refused pre-filesystem, hermetic marker matrix green, unowned clusters and replacement-cluster identities refused before mutation, read-time namespace validation refuses planted/foreign-owned/symlinked/loose-mode/non-regular markers and hostile registry dirs before any probe, source-pinned ordering and quoted-variable SQL)'
