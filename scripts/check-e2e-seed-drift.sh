#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-e2e-seed-drift.sh — e2e seed-fixture DRIFT guard (Queue B item 3,
# retired-docs:superpowers/plans/archive/2026-07-04-queue-b-combined.md §3).
#
# WHY. `mailserver/webmail/e2e/fixtures/seed.sql` is hand-maintained SQL that
# targets a schema evolving independently under it. Nothing previously caught
# (a) seed.sql referencing a column/table that's since been renamed/dropped —
# only a human running the full Playwright suite locally hit the wall — or
# (b) a `feature_toggles` key a spec's `setFeature()` call (or seed.sql's own
# `UPDATE feature_toggles ... WHERE key = ...`) needs, that doesn't exist as a
# row — which is NOT a SQL error (an UPDATE matching zero rows silently no-ops),
# so it would never surface as a load failure, only as a bewildering "toggle
# didn't take" flake in whichever spec depends on it.
#
# WHAT IT DOES (two independent checks; either can fail the guard):
#   A. SCHEMA-LOAD  — runs the real seed.sql, wrapped in BEGIN;...ROLLBACK;,
#      against the target DB. A dropped/renamed table or column surfaces as a
#      real Postgres error (named, with the offending statement) BEFORE the
#      rollback discards all effects — so this is side-effect-free against
#      whatever DB you point it at (FK violations are caught the same way:
#      every FK in this schema is NOT DEFERRABLE, so a violation raises
#      immediately, not at COMMIT — the ROLLBACK never gets a chance to hide it).
#   B. TOGGLE-DIFF  — collects every `feature.*`/`sharing.*` key seed.sql's own
#      `feature_toggles` UPDATEs reference, plus every key any `setFeature(...)`
#      call in an e2e spec passes, and asserts each one is an actual row in the
#      live `feature_toggles` table. A key that resolves to zero rows is exactly
#      the silent-no-op gap above.
#
# WHAT IT IS NOT. Not a Playwright-in-CI runner (that's a separate, larger
# item — see the plan). Not a fixture-content auditor (doesn't judge whether
# seed.sql seeds ENOUGH data, only whether what it seeds still lines up with
# the schema/registry).
#
# DB. seed.sql's C9 destructive-DB guard (E2E-SEED-UNGUARDED-GLOBAL-MUTATION,
# inside seed.sql itself) refuses to run against any database that does not
# carry the disposable e2e naming marker (mailserver_e2e, or *_e2e / *_e2e_*),
# so the original default of loading it against a pre-provisioned
# `mailserver_test` can never execute the real seed — by the seed's own
# fail-closed design. By default this guard therefore provisions its OWN
# disposable e2e database (mailserver_e2e_driftguard_<pid>) FRESH each run
# through the sanctioned loader scripts/load-test-schema.sh — the same flow
# the e2e stack (mailserver/webmail/e2e/scripts/start-test-stack.sh) and the
# check-schema-determinism.sh guard use — so the schema under test is the
# CURRENT tree by construction, and drops it on exit. Override
# DB_HOST/DB_PORT/DB_USER/DB_NAME to point at an existing scratch database;
# an explicitly provided DB_NAME is honored ONLY when it carries the
# disposable-e2e marker — the C9 marker outranks the override, so a
# non-marked override is bypassed with a loud note and a disposable e2e
# database is provisioned instead.
#
# Usage: scripts/check-e2e-seed-drift.sh
#   SEED_FILE=<path>  override the seed.sql under test (default: the real one)
#   E2E_DIR=<path>     override the e2e spec tree searched for setFeature() (default: the real one)
# Self-test: scripts/check-e2e-seed-drift-selftest.sh (plants a drifted column +
# a bogus toggle key; doubles as this guard's TDD red-first proof).
#
# guard-requires: db
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"
set +e # _base.sh sets -e; every fallible step below is checked explicitly
# (mirrors check-schema-determinism.sh, the other guard-requires:db script).

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-}" # empty → provision a disposable e2e DB below
# C9 precedence: the disposable-e2e marker OUTRANKS an explicit DB_NAME. An
# override that lacks the marker (e.g. CI exporting DB_NAME=mailserver_test)
# is bypassed with a loud note and the guard provisions its own disposable e2e
# database — drift detection must never silently vanish, and seed.sql's
# destructive-DB refusal must never be stepped around.
if [ -n "$DB_NAME" ]; then
  case "$DB_NAME" in
    mailserver_e2e | *_e2e | *_e2e_*) ;;
    *)
      echo "OVERRIDE-BYPASSED (reason=DB_NAME '$DB_NAME' lacks the disposable-e2e marker; the C9 marker outranks the override — provisioning a disposable e2e database instead)" >&2
      DB_NAME=""
      ;;
  esac
fi
PG_OPTS="-h $DB_HOST -p $DB_PORT -U $DB_USER"

SEED_FILE="${SEED_FILE:-$ROOT/mailserver/webmail/e2e/fixtures/seed.sql}"
E2E_DIR="${E2E_DIR:-$ROOT/mailserver/webmail/e2e}"

# ── Disposable e2e database (default path) ──────────────────────────────────
# No DB_NAME given: build a fresh e2e-marked database so seed.sql's C9 marker
# accepts it AND the schema is the current tree by construction. Fresh-per-run
# (not reused) on purpose: a stale schema would fabricate drift findings —
# exactly what this guard exists to catch. Unique name keeps parallel runs
# safe; drop-on-exit keeps the cluster clean.
PROVISIONED_DB=""
PROVISION_LOG="$(mktemp)"
SCHEMA_LOG="$(mktemp)"
cleanup() {
  rm -f "$SCHEMA_LOG" "$PROVISION_LOG"
  if [ -n "$PROVISIONED_DB" ]; then
    # Quoted psql variable, never string-concatenated SQL (L2-C9 r2-2 shape,
    # mirrors load-test-schema.sh's own DROP/CREATE block).
    psql $PG_OPTS -d postgres -v db_name="$PROVISIONED_DB" >/dev/null 2>&1 <<SQL
DROP DATABASE IF EXISTS :"db_name" WITH (FORCE);
SQL
  fi
}

echo "==> e2e seed-drift guard: $SEED_FILE against ${DB_NAME:-<provisioned disposable e2e DB>}"

if [ ! -f "$SEED_FILE" ]; then
  echo "  [SEED-DRIFT] seed file not found: $SEED_FILE" >&2
  exit 1
fi

trap cleanup EXIT

if [ -z "$DB_NAME" ]; then
  DB_NAME="mailserver_e2e_driftguard_$$"
  echo "    provisioning disposable e2e database $DB_NAME (load-test-schema.sh)..."
  if ! DB_NAME="$DB_NAME" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
    bash "$ROOT/scripts/load-test-schema.sh" >"$PROVISION_LOG" 2>&1; then
    echo "  [SEED-DRIFT] disposable e2e database provisioning FAILED:" >&2
    tail -30 "$PROVISION_LOG" | sed 's/^/      /' >&2
    exit 1
  fi
  PROVISIONED_DB="$DB_NAME"
fi

fail=0

# ── A. SCHEMA-LOAD: run the real seed.sql inside a transaction we roll back.
# `-f -` reads the wrapped script from stdin so we never write a scratch file.
# ON_ERROR_STOP=1 makes psql exit non-zero (and stop) on the FIRST error, which
# is exactly the offending statement — its own message names the missing
# table/column/FK target, no parsing needed on our side.
{
  echo "BEGIN;"
  cat "$SEED_FILE"
  echo "ROLLBACK;"
} | psql $PG_OPTS -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -f - >"$SCHEMA_LOG" 2>&1
if [ $? -ne 0 ]; then
  echo "  [SEED-DRIFT] $SEED_FILE did NOT load cleanly against $DB_NAME — schema drift:" >&2
  sed 's/^/      /' "$SCHEMA_LOG" >&2
  echo "      → a table/column seed.sql references was renamed or dropped (or a live FK target is missing)." >&2
  fail=1
else
  echo "    schema-load: clean (seed.sql applies + rolls back with no error)."
fi

# ── B. TOGGLE-DIFF: every feature_toggles key seed.sql touches, plus every
# key any e2e spec's setFeature() call passes, must be a real registered row.
extract_seed_keys() {
  grep -i 'feature_toggles' "$1" 2>/dev/null |
    grep -oE "'[A-Za-z_]+\.[A-Za-z_]+'" | tr -d "'" | LC_ALL=C sort -u
}
extract_spec_keys() {
  local dir="$1" files
  files="$(find "$dir" -type f -name '*.spec.ts' 2>/dev/null)"
  [ -z "$files" ] && return 0
  printf '%s\n' "$files" | xargs grep -l "setFeature(" 2>/dev/null | while read -r f; do
    grep "setFeature(" "$f" | grep -oE "'[A-Za-z_]+\.[A-Za-z_]+'" | tr -d "'"
  done | LC_ALL=C sort -u
}

SEED_KEYS="$(extract_seed_keys "$SEED_FILE")"
SPEC_KEYS="$(extract_spec_keys "$E2E_DIR")"
ALL_KEYS="$(printf '%s\n%s\n' "$SEED_KEYS" "$SPEC_KEYS" | grep -v '^$' | LC_ALL=C sort -u)"

if [ -n "$ALL_KEYS" ]; then
  values_sql=""
  while IFS= read -r k; do
    [ -z "$k" ] && continue
    if [ -z "$values_sql" ]; then values_sql="('$k')"; else values_sql="$values_sql,('$k')"; fi
  done <<<"$ALL_KEYS"

  MISSING="$(psql $PG_OPTS -d "$DB_NAME" -tAc \
    "WITH want(key) AS (VALUES $values_sql) SELECT want.key FROM want LEFT JOIN feature_toggles ft ON ft.key = want.key WHERE ft.key IS NULL ORDER BY 1;" \
    2>/dev/null)"

  if [ -n "$MISSING" ]; then
    while IFS= read -r mk; do
      [ -z "$mk" ] && continue
      echo "  [SEED-DRIFT] toggle key '$mk' referenced but no such row in feature_toggles (registered where):" >&2
      grep -l "$mk" "$SEED_FILE" >/dev/null 2>&1 && echo "      - seed.sql: $SEED_FILE" >&2
      find "$E2E_DIR" -type f -name '*.spec.ts' -print0 2>/dev/null |
        xargs -0 grep -l "$mk" 2>/dev/null | sed "s|^|      - spec: |" >&2
      echo "      → seed the toggle row (a migration) or fix the stale key name." >&2
    done <<<"$MISSING"
    fail=1
  else
    echo "    toggle-diff: clean ($(printf '%s\n' "$ALL_KEYS" | grep -c .) key(s) checked, all registered)."
  fi
else
  echo "    toggle-diff: no feature_toggles keys referenced by seed.sql or any e2e spec."
fi

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "e2e seed-drift guard FAILED (see above)." >&2
  exit 1
fi
echo "    e2e seed-drift guard: clean."
