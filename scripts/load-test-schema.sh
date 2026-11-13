#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# load-test-schema.sh — build the COMPLETE combined schema (authserver +
# mailserver) into a freshly recreated database for pgTAP.
#
# POST-COLLAPSE (ARCH-007): the schema is now ONE baseline, not a replayed
# migration chain. Load order:
#   1. V001__baseline.sql   — the whole combined schema (tables + types +
#                             sequences + indexes + constraints + triggers +
#                             trigger functions + the 123 deferred ADD-FK),
#                             reducers STRIPPED, plus the SEED DATA (system_config,
#                             feature_toggles, admin_permissions, … ) and the
#                             schema_migrations baseline row (version=1).
#   2. reducers (fixed-point) — mailserver then authserver, each loaded to a
#                             fixed point (reload-reducers.sh retries any file
#                             that fails until an iteration adds zero new
#                             successes — resolves forward refs of any depth
#                             in one call). Reducers stay the canonical
#                             CREATE OR REPLACE source in reducers/.
#   3. _fixtures.sql         — pgTAP fixture helpers (test DB only).
#
# The pre-collapse dual-source tree (authserver V000–V009 + schema/, mailserver
# V002..V092 + schema/) is ARCHIVED under {mailserver,authserver}/sql/_archive/
# (non-executed, provenance only) — its end-state structure + seed lives in the
# baseline. See docs/adr/ARCH-007-schema-baseline-collapse.md.
#
# Usage:
#   bash scripts/load-test-schema.sh                 # → mailserver_test
#   DB_NAME=foo bash scripts/load-test-schema.sh     # → custom db
#   bash scripts/load-test-schema.sh --preflight-only  # ARCH-007 input validation
#                          only: refuses archived SQL before ANY database
#                          contact (used by check-archive-exclusion-selftest.sh)
#   bash scripts/load-test-schema.sh && \
#     pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test mailserver/sql/tests/*.pg
#
# Test-only input-root overrides (self-test case C): MIGRATIONS_ROOT relocates
# the dbschema migration inputs, REDUCERS_ROOT the reducer trees (mirrors
# reload-reducers.sh). Unset → the repo ROOT.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-mailserver_test}"

# Destructive-target guard (default ON): refuse a DB_NAME outside the known
# disposable test-database universe — the pgTAP/boundary lane (mailserver_test),
# the determinism double-build (mailserver_determinism_*), the e2e-marker
# family (mailserver_e2e*, *_e2e, *_e2e_* — the same markers
# check-e2e-seed-drift.sh honors) and the post-upgrade smoke's own throwaway.
# ARCH_R2_TEST_MODE=1 opts out for the R2 surrogate.
if [ "${ARCH_R2_TEST_MODE:-0}" != "1" ]; then
  case "$DB_NAME" in
    mailserver_test | mailserver_determinism_* | mailserver_e2e | mailserver_e2e_* | *_e2e | *_e2e_* | setjoin_post_upgrade_smoke) ;;
    *)
      echo "REFUSING: DB_NAME='$DB_NAME' is not a disposable test database (mailserver_test, mailserver_determinism_*, mailserver_e2e*, *_e2e, *_e2e_*, setjoin_post_upgrade_smoke; set ARCH_R2_TEST_MODE=1 to override)" >&2
      exit 2
      ;;
  esac
fi

# Test-only input-root overrides (see Usage above).
MIGRATIONS_ROOT="${MIGRATIONS_ROOT:-$ROOT}"
REDUCERS_ROOT="${REDUCERS_ROOT:-$ROOT}"

# ── ARCHIVE PREFLIGHT (ARCH-007) — pure input validation, zero DB contact ──
# This script's first SQL side effect is the destructive recreate block below
# (DROP DATABASE … WITH (FORCE)). The preflight enumerates EVERY SQL file
# input — the baseline, every forward migration, _fixtures.sql,
# provision-roles.sql, and both reducer trees (re-checked here ahead of
# reload-reducers.sh's own preflight) — and refuses, naming the offending
# file, BEFORE the recreate block, so an accidentally archive-redirected input
# can never reach a database. Both the literal path and its symlink-resolved
# realpath must be free of /_archive/
# (docs/adr/ARCH-007-schema-baseline-collapse.md).
archive_guard_refuse() {
  echo "✗ refusing to execute archived SQL — non-executed provenance: $1" >&2
  echo "  archived trees under */sql/_archive/ are provenance only; every loader" >&2
  echo "  rejects them (ARCH-007: docs/adr/ARCH-007-schema-baseline-collapse.md)." >&2
  exit 1
}

archive_guard_check_one() {
  local rp
  rp="$(realpath "$1" 2>/dev/null)" || rp=""
  [ -n "$rp" ] || rp="$1"
  case "$1" in */_archive/*) archive_guard_refuse "$1" ;; esac
  case "$rp" in */_archive/*) archive_guard_refuse "$rp" ;; esac
}

archive_preflight() {
  local dir f
  # Direct `-f` inputs: provision-roles (pre+post pass), baseline, fixtures.
  for f in \
    "$ROOT/scripts/provision-roles.sql" \
    "$MIGRATIONS_ROOT/mailserver/sql/dbschema/V001__baseline.sql" \
    "$ROOT/mailserver/sql/tests/_fixtures.sql"; do
    [ -e "$f" ] || continue # a missing input fails later at its own step
    archive_guard_check_one "$f"
  done
  # The forward-migration selection (same glob as the apply loop below).
  # shellcheck disable=SC2012
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    archive_guard_check_one "$f"
  done < <(LC_ALL=C ls "$MIGRATIONS_ROOT/mailserver/sql/dbschema"/V[0-9]*__*.sql 2>/dev/null | LC_ALL=C sort)
  # Reducer inputs (the reload-reducers.sh selection).
  for dir in \
    "$REDUCERS_ROOT/mailserver/sql/reducers" \
    "$REDUCERS_ROOT/authserver/sql/reducers"; do
    # Mirrors reload-reducers.sh's load_reducer_set selection.
    # shellcheck disable=SC2012,SC2035
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      archive_guard_check_one "$dir/$f"
    done < <(cd "$dir" 2>/dev/null && LC_ALL=C ls *.sql 2>/dev/null | LC_ALL=C sort)
  done
}

# Self-test entry: run ONLY the preflight (pure; no psql, not even the
# DB-validation helper below) and exit — the full loader is never executed
# against a real cluster by the self-test.
if [ "${1:-}" = "--preflight-only" ]; then
  archive_preflight
  echo "==> archive preflight clean (no database contact made)."
  exit 0
fi

source "$ROOT/scripts/architecture-r2-test-db.sh"
architecture_r2_validate_test_db || exit $?

# ARCH-007 preflight: MUST sit between the (pure) validation above and the
# destructive recreate below — on an archived input the refusal fires before
# DROP/CREATE with zero database side effects.
archive_preflight

PG_OPTS="-h $DB_HOST -p $DB_PORT -U $DB_USER"
PG="psql $PG_OPTS -d $DB_NAME -v ON_ERROR_STOP=1 -q"

fail=0

# provision-roles.sql is idempotent and safe on an empty DB (GRANT ON ALL TABLES
# with zero tables is a no-op). It runs TWICE: once before the baseline so the
# cluster-global roles EXIST when forward migrations reference them (V017+ do —
# a fresh cluster, e.g. a CI service container, has no roles), and once at 4/4
# so the GRANTs cover every table the load created. Retries: see the 4/4 comment.
provision_roles() {
  local prov_log prov_ok attempt
  prov_log="$(mktemp)"
  prov_ok=0
  for attempt in 1 2 3 4 5 6; do
    if (cd "$ROOT/scripts" && $PG -f provision-roles.sql) >"$prov_log" 2>&1; then
      prov_ok=1
      break
    fi
    # jittered backoff: 120ms*attempt + 0–250ms random (seed varies per pid+attempt).
    sleep "$(awk "BEGIN{srand($$*7+$attempt); print 0.12*$attempt + rand()*0.25}")"
  done
  if [ "$prov_ok" -eq 1 ]; then
    [ "$attempt" -gt 1 ] && echo "    OK (after $attempt attempts — lost a cluster-global role race, idempotent retry won)" || echo "    OK"
  else
    echo "    FAIL (provision-roles.sql did not load clean after 6 attempts):"
    sed 's/^/      /' "$prov_log"
    fail=1
  fi
  rm -f "$prov_log"
}

echo "==> Recreating database: $DB_NAME"
# L2-C9 r2-2: values AND identifiers pass as quoted psql variables
# (:"db_name" / :'db_name') — the repository rule forbids concatenating input
# into SQL, and the shell-side name guard (where a lane wires one) is defense
# in depth, not the rule's satisfaction.
psql $PG_OPTS -d postgres -v ON_ERROR_STOP=1 -v db_name="$DB_NAME" -v db_user="$DB_USER" <<'SQL' >/dev/null
DROP DATABASE IF EXISTS :"db_name" WITH (FORCE);
CREATE DATABASE :"db_name" OWNER :"db_user" TEMPLATE template0;
SQL
# L2-C9 WP-2 disposable marker: the e2e DB-target guard
# (scripts/e2e-test-db-guard.sh) refuses to reuse an existing database that
# lacks this comment, so stamp it on every fresh create. Comment metadata
# only — equally harmless for the pgTAP lane (mailserver_test is disposable).
$PG -v db_name="$DB_NAME" <<'SQL' >/dev/null || {
COMMENT ON DATABASE :"db_name" IS 'setjoin-disposable-test-db';
SQL
  echo "    FAIL (disposable-marker stamp)"
  fail=1
}
$PG -c "CREATE EXTENSION IF NOT EXISTS pgtap;" >/dev/null 2>&1 || echo "    (pgtap extension unavailable — pgTAP tests will not run)"

echo "==> 0/4 native-RLS roles (pre-pass — forward migrations reference setjoin_app)"
provision_roles

echo "==> 1/4 baseline (V001__baseline.sql — combined schema + seed) + forward migrations (V002+)"
(cd "$MIGRATIONS_ROOT/mailserver/sql/dbschema" && $PG -f V001__baseline.sql) &&
  echo "    OK V001__baseline.sql" || {
  echo "    FAIL (V001__baseline.sql must load clean)"
  fail=1
}

# ── Forward-migration apply step (RLS-flip Wave 0) ─────────────────────────
# V001 is the FROZEN collapse snapshot; ALL new schema is V002+ forward
# migrations applied ON TOP, in LC_ALL=C sort order (the order the dedup guard
# pins), AFTER V001 (which seeds schema_migrations) and BEFORE the reducer reload
# (every flip artifact is schema-only; reducers are CREATE OR REPLACE re-run after).
# V001 is skipped here (already applied above). Each migration is expected to
# INSERT its own schema_migrations row so MAX(version) advances.
#
# FAIL-LOUD (P1 harness contract): each apply runs under ON_ERROR_STOP=1 (PG), so
# a SQL/parse error makes psql exit non-zero; we set fail=1 and NAME the file (the
# same exit-code → fail propagation as the V001 / reducer / fixtures steps). The
# subshell `( )` keeps the cd local; the && / || carries the verdict back out.
# Only V001 itself FAILing aborts before this loop is meaningful; a later FAIL
# here propagates to the fail=1 verdict (exit 1) at the end.
if [ "$fail" -eq 0 ]; then
  # LC_ALL=C sort over V<NNN>__*.sql, skip V001 (the baseline, already applied).
  while IFS= read -r mig; do
    [ -n "$mig" ] || continue
    base="$(basename "$mig")"
    case "$base" in V001__*) continue ;; esac
    (cd "$MIGRATIONS_ROOT/mailserver/sql/dbschema" && $PG -f "$base") &&
      echo "    OK $base" ||
      {
        echo "    FAIL ($base — forward migration must load clean)"
        fail=1
      }
  done < <(LC_ALL=C ls "$MIGRATIONS_ROOT/mailserver/sql/dbschema"/V[0-9]*__*.sql 2>/dev/null | LC_ALL=C sort)
fi

echo "==> 2/4 reducers (fixed-point load — resolves forward refs internally)"
# reload-reducers.sh loads every reducer to a FIXED POINT in one call: a file
# that fails is retried next iteration (a forward reference resolves once its
# target has loaded); the loop stops when an iteration adds zero new
# successes. Its own first iteration is the old "pass 1" (forward refs
# legitimately error, non-fatal); its own converged iteration is the old
# "pass 2" (the gate — a survivor at fixed point is a real SQL error or a
# real dependency cycle, and IS fatal). One call replaces the old two-pass
# wrapper. (See mailserver/sql/AGENTS.md; do not reintroduce a manual
# multi-pass wrapper here — the fixed point already IS the multi-pass.)
reducer_log="$(mktemp)"
if DB_NAME="$DB_NAME" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
  bash "$ROOT/scripts/reload-reducers.sh" >"$reducer_log" 2>&1; then
  echo "    OK (reducers loaded to a fixed point)"
else
  echo "    FAIL (reducers did not all load clean at fixed point):"
  sed 's/^/      /' "$reducer_log"
  fail=1
fi
rm -f "$reducer_log"

echo "==> 3/4 pgTAP fixture helpers (mk_account / mk_shared_mailbox — test DB only)"
(cd "$ROOT/mailserver/sql/tests" && $PG -f _fixtures.sql) &&
  echo "    OK" || {
  echo "    FAIL (_fixtures.sql must load clean)"
  fail=1
}

# ── Native-RLS role/ownership provisioning (W1, fork 7) ────────────────────
# Roles are CLUSTER-GLOBAL, not per-DB schema, so they live in a dedicated
# idempotent script (NOT a V-migration). Runs AFTER fixtures so GRANT ON ALL
# TABLES sees every table the load created, and BEFORE the verdict. INERT: it
# creates roles + GRANTs runtime privileges; it does NOT enable/force RLS or
# change any table's owner (RLS stays a no-op until the W6 flip). Idempotent —
# CREATE ROLE is IF-NOT-EXISTS guarded so a determinism double-build (DB_A then
# DB_B in the same cluster) re-runs cleanly: the roles already exist on the 2nd
# build and only the per-DB GRANTs re-apply.
echo "==> 4/4 native-RLS role provisioning (scripts/provision-roles.sql — cluster-global, idempotent)"
# provision-roles.sql touches CLUSTER-GLOBAL roles (pg_authid). Parallel builds —
# each loading its OWN database but sharing one cluster (a determinism double-build,
# a CI matrix) — race on them: the IF-NOT-EXISTS create is a TOCTOU and concurrent
# ALTER ROLE throws `tuple concurrently updated` (~3/12 full builds, ~23/30 raw,
# before this). A Postgres advisory lock can't help (per-database; the race is
# cross-database), and macOS lacks flock — so RETRY: the script is idempotent, so
# re-running after a lost race converges. Jittered backoff de-syncs colliding
# builds. A PERSISTENT error (real SQL fault) still fails loud after the attempts.
provision_roles

echo "==> Verifying required objects"
$PG -tA <<'SQL'
SELECT '    ' || rpad(name, 26) || ' : ' || CASE WHEN ok THEN 'present' ELSE 'MISSING' END
FROM (VALUES
  ('dlp_check',            (SELECT count(*) > 0 FROM pg_proc WHERE proname='dlp_check')),
  ('get_system_config',    (SELECT count(*) > 0 FROM pg_proc WHERE proname='get_system_config')),
  ('set_system_config',    (SELECT count(*) > 0 FROM pg_proc WHERE proname='set_system_config')),
  ('saml_sp_registrations',(to_regclass('public.saml_sp_registrations') IS NOT NULL)),
  ('device_registry',      (to_regclass('public.device_registry') IS NOT NULL)),
  ('device_policy',        (to_regclass('public.device_policy') IS NOT NULL)),
  ('device_events',        (to_regclass('public.device_events') IS NOT NULL)),
  ('message_recalls',      (to_regclass('public.message_recalls') IS NOT NULL))
) AS t(name, ok);
SQL

# ── Loaded-reducer manifest assertion (expected-set ⊆ actual) ──────────────
# The SOUND backstop (vs a count-floor, which a partial load above the floor
# would pass green): the EXPECTED set is every function the reducers/*.sql files
# DECLARE (`CREATE [OR REPLACE] FUNCTION <name>`); ACTUAL is pg_proc after load.
# Any expected function missing from pg_proc means a reducer was silently dropped
# — fail loudly and NAME the missing functions. This catches a partial drop even
# if the exit-code propagation from reload-reducers.sh is ever defeated (defense
# in depth — the canary adjust_folder_counters lives in this set automatically).
echo "==> Verifying loaded reducer manifest (expected-set ⊆ actual)"
EXPECTED_FUNCS="$(grep -rhoE '^[[:space:]]*CREATE( OR REPLACE)? FUNCTION [a-zA-Z_][a-zA-Z0-9_]*' \
  "$REDUCERS_ROOT/mailserver/sql/reducers/"*.sql "$REDUCERS_ROOT/authserver/sql/reducers/"*.sql |
  sed -E 's/^[[:space:]]*CREATE( OR REPLACE)? FUNCTION //' | LC_ALL=C sort -u)"
EXPECTED_COUNT="$(printf '%s\n' "$EXPECTED_FUNCS" | grep -c .)"
# ACTUAL = every proc name in the public schema after load. The set-difference is
# done in shell (comm) — no temp table (psql autocommit would ON COMMIT DROP it
# between statements). expected-set ⊆ actual ⟺ MISSING is empty.
ACTUAL_FUNCS="$($PG -tA -c "SELECT DISTINCT proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public';")"
# LC_ALL=C on BOTH sorts AND comm: sort(1) and comm(1) must agree on collation
# or comm emits false "missing" lines (seen on Ubuntu 26 en_US.UTF-8, where the
# locale-collated sort order of underscore names differs from comm's line
# comparison — 5 loaded reducers were reported MISSING). Byte order is the only
# ordering both tools agree on everywhere (macOS + Linux + CI).
MISSING_FUNCS="$(LC_ALL=C comm -23 \
  <(printf '%s\n' "$EXPECTED_FUNCS" | grep . | LC_ALL=C sort -u) \
  <(printf '%s\n' "$ACTUAL_FUNCS" | grep . | LC_ALL=C sort -u))"
MISSING_COUNT="$(printf '%s\n' "$MISSING_FUNCS" | grep -c .)"
LOADED_COUNT=$((EXPECTED_COUNT - MISSING_COUNT))
if [ -n "$MISSING_FUNCS" ]; then
  echo "    reducer manifest: $LOADED_COUNT / $EXPECTED_COUNT expected functions present — MISSING:" >&2
  printf '%s\n' "$MISSING_FUNCS" | sed 's/^/      - /' >&2
  echo "    → one or more reducers were silently dropped during load (see pass logs)." >&2
  fail=1
else
  echo "    reducer manifest: all $EXPECTED_COUNT expected functions present."
fi

if [ "$fail" -eq 0 ]; then
  echo "==> Schema loaded clean. Run pgTAP with:"
  echo "    pg_prove $PG_OPTS -d $DB_NAME mailserver/sql/tests/*.pg"
else
  echo "==> One or more migrations failed to load (see FAIL lines above)."
  exit 1
fi
