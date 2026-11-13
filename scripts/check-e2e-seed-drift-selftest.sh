#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-e2e-seed-drift-selftest.sh — negative+positive self-test for
# check-e2e-seed-drift.sh (Queue B item 3).
#
# A guard that never fires is theater. This plants ONE drifted-column INSERT
# (case A: a nonexistent `mailboxes` column) and ONE bogus toggle key (case B:
# a `setFeature()` call in a synthetic spec referencing a key with no
# `feature_toggles` row), drives the guard at each in isolation, and asserts
# it FAILS both — then drives it at the REAL seed.sql + REAL e2e tree and
# asserts it PASSES. That doubles as this guard's TDD red-first proof.
#
# DB. seed.sql carries the C9 destructive-DB guard (fail-closed refusal on any
# database without the disposable e2e naming marker), so mailserver_test can
# never take a real seed load — a refusal there is the C9 guard working, not a
# verdict about seed.sql. The self-test therefore provisions ONE disposable
# e2e-marked database (mailserver_e2e_selftest_<pid>) up front through the
# sanctioned loader scripts/load-test-schema.sh — the same flow the e2e stack
# uses — and points all three guard invocations at it via DB_NAME (an
# explicitly provided DB_NAME is used by the guard as-is). Case A's assertion
# pins the PLANTED violation specifically: before the disposable DB, the C9
# refusal used to mask the planted column and the case fired for the wrong
# reason. The database is dropped on exit; the self-test never touches
# mailserver_test.
#
# Usage: scripts/check-e2e-seed-drift-selftest.sh   (exit 0 = all cases pass).
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-e2e-seed-drift.sh"
REAL_SEED="$ROOT/mailserver/webmail/e2e/fixtures/seed.sql"
REAL_E2E_DIR="$ROOT/mailserver/webmail/e2e"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
PG_OPTS="-h $DB_HOST -p $DB_PORT -U $DB_USER"

TMP="$(mktemp -d)"
SELFTEST_DB="mailserver_e2e_selftest_$$" # C9 marker: *_e2e_*
cleanup() {
  rm -rf "$TMP"
  psql $PG_OPTS -d postgres -v db_name="$SELFTEST_DB" >/dev/null 2>&1 <<SQL
DROP DATABASE IF EXISTS :"db_name" WITH (FORCE);
SQL
}
trap cleanup EXIT

fail=0

# ── Provision the disposable e2e database (sanctioned loader, current tree) ──
DBLOAD_LOG="$TMP/dbload.log"
if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" >/dev/null 2>&1; then
  echo "SELFTEST FAIL: PostgreSQL not reachable at ${DB_HOST}:${DB_PORT} — the guard is guard-requires: db; start the local cluster first." >&2
  exit 1
fi
echo "  provisioning disposable e2e database $SELFTEST_DB (load-test-schema.sh)..."
if ! DB_NAME="$SELFTEST_DB" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
  bash "$ROOT/scripts/load-test-schema.sh" >"$DBLOAD_LOG" 2>&1; then
  echo "SELFTEST FAIL: disposable e2e database provisioning failed:" >&2
  tail -20 "$DBLOAD_LOG" | sed 's/^/    /' >&2
  exit 1
fi

# ── Case A: schema-load half must FIRE on a drifted (nonexistent) column ──
BAD_SEED="$TMP/seed_bad_column.sql"
cp "$REAL_SEED" "$BAD_SEED"
printf '\n-- selftest-planted violation: nonexistent column\nINSERT INTO mailboxes (bogus_col_xyz) VALUES (1);\n' >>"$BAD_SEED"

out_a="$(DB_NAME="$SELFTEST_DB" SEED_FILE="$BAD_SEED" E2E_DIR="$REAL_E2E_DIR" bash "$GUARD" 2>&1)"
rc_a=$?
if [ $rc_a -eq 0 ] || ! printf '%s' "$out_a" | grep -qi 'bogus_col_xyz'; then
  echo "SELFTEST FAIL: case A (drifted column) did NOT fire on the planted violation (rc=$rc_a)" >&2
  printf '%s\n' "$out_a" | sed 's/^/    /' >&2
  fail=1
else
  echo "  case A (drifted column) fires as expected."
fi

# ── Case B: toggle-diff half must FIRE on a setFeature() key with no row ──
BOGUS_KEY="feature.selftest_bogus_key_zzz"
mkdir -p "$TMP/e2e_bogus"
cat >"$TMP/e2e_bogus/bogus.spec.ts" <<EOF
import { setFeature } from './helpers';
test('bogus', async () => {
  await setFeature(request, adminToken, '$BOGUS_KEY', true);
});
EOF

out_b="$(DB_NAME="$SELFTEST_DB" SEED_FILE="$REAL_SEED" E2E_DIR="$TMP/e2e_bogus" bash "$GUARD" 2>&1)"
rc_b=$?
if [ $rc_b -eq 0 ] || ! printf '%s' "$out_b" | grep -qi "$BOGUS_KEY"; then
  echo "SELFTEST FAIL: case B (bogus toggle key) did NOT fire (rc=$rc_b)" >&2
  printf '%s\n' "$out_b" | sed 's/^/    /' >&2
  fail=1
else
  echo "  case B (bogus toggle key) fires as expected."
fi

# ── Case C: the REAL seed.sql + REAL e2e tree must PASS (no false positives) ──
out_c="$(DB_NAME="$SELFTEST_DB" SEED_FILE="$REAL_SEED" E2E_DIR="$REAL_E2E_DIR" bash "$GUARD" 2>&1)"
rc_c=$?
if [ $rc_c -ne 0 ]; then
  echo "SELFTEST FAIL: case C (real seed.sql + real e2e tree) did NOT pass (rc=$rc_c)" >&2
  printf '%s\n' "$out_c" | sed 's/^/    /' >&2
  fail=1
else
  echo "  case C (real seed.sql + real e2e tree) passes as expected."
fi

# ── Case D: a DB_NAME override WITHOUT the e2e marker is bypassed, not honored ──
# Mirrors CI exporting DB_NAME=mailserver_test: the C9 marker outranks the
# override, so the guard must provision its own disposable DB and PASS with
# the OVERRIDE-BYPASSED note — never load seed.sql into the protected name.
out_d="$(DB_NAME="mailserver_test" SEED_FILE="$REAL_SEED" E2E_DIR="$REAL_E2E_DIR" bash "$GUARD" 2>&1)"
rc_d=$?
if [ $rc_d -ne 0 ]; then
  echo "SELFTEST FAIL: case D (protected DB_NAME override) did NOT pass (rc=$rc_d)" >&2
  printf '%s\n' "$out_d" | sed 's/^/    /' >&2
  fail=1
elif ! printf '%s\n' "$out_d" | grep -q "OVERRIDE-BYPASSED"; then
  echo "SELFTEST FAIL: case D produced no OVERRIDE-BYPASSED note (silent override handling)" >&2
  printf '%s\n' "$out_d" | sed 's/^/    /' >&2
  fail=1
elif printf '%s\n' "$out_d" | grep -q "not a disposable e2e database"; then
  echo "SELFTEST FAIL: case D still attempted the protected database (C9 marker did not outrank the override)" >&2
  printf '%s\n' "$out_d" | sed 's/^/    /' >&2
  fail=1
else
  echo "  case D (protected DB_NAME override bypassed with note) passes as expected."
fi

if [ "$fail" -ne 0 ]; then
  echo "check-e2e-seed-drift SELF-TEST FAILED" >&2
  exit 1
fi
echo "check-e2e-seed-drift self-test: OK (fires on drifted column + bogus toggle key; real seed.sql/e2e tree clean; protected override bypassed)"
