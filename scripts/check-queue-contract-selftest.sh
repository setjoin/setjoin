#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-queue-contract-selftest.sh — negative-case self-test for the queue
# failure-contract guard. A guard that never fires is theater.
#
# Drives check-queue-contract.sh against TEMP dbschema/reducers dirs (via the
# DBSCHEMA_DIR/REDUCERS_DIR overrides, so the real tree is never touched):
#   1. a fake non-waived table missing last_error  → guard exits 1, names the col.
#   2. a fake non-waived table WITH all 4 cols      → guard exits 0.
#   3. a fake table whose only gap is a WAIVED name → guard exits 0.
#   4. settle_job.sql absent                         → guard exits 1.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-queue-contract.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

mk_reducer() { mkdir -p "$1"; printf 'CREATE OR REPLACE FUNCTION settle_job(p TEXT) RETURNS VOID AS $$ BEGIN END; $$ LANGUAGE plpgsql;\n' > "$1/settle_job.sql"; }

run() { DBSCHEMA_DIR="$1" REDUCERS_DIR="$2" bash "$GUARD" > "$TMP/out" 2>&1; return $?; }

echo "==> queue-contract guard self-test (must fire on a missing contract column)"

# Case 1 — missing last_error on a non-waived table.
mkdir -p "$TMP/c1/db"; mk_reducer "$TMP/c1/red"
cat > "$TMP/c1/db/V001__x.sql" <<'SQL'
CREATE TABLE public.widget_queue ( id bigint, status text, attempt_count int, next_attempt_at timestamptz );
SQL
if run "$TMP/c1/db" "$TMP/c1/red"; then
  bad "missing last_error — guard did NOT fail"; sed 's/^/        /' "$TMP/out"
elif grep -q 'last_error' "$TMP/out"; then
  pass "missing last_error — caught (exit 1, names last_error)"
else
  bad "missing last_error — failed but did not name last_error"; sed 's/^/        /' "$TMP/out"
fi

# Case 2 — fully-compliant non-waived table passes.
mkdir -p "$TMP/c2/db"; mk_reducer "$TMP/c2/red"
cat > "$TMP/c2/db/V001__x.sql" <<'SQL'
CREATE TABLE public.widget_queue ( id bigint, status text, attempt_count int, next_attempt_at timestamptz, last_error text );
SQL
if run "$TMP/c2/db" "$TMP/c2/red"; then pass "compliant table passes"
else bad "compliant table should pass"; sed 's/^/        /' "$TMP/out"; fi

# Case 3 — a waived name with no contract still passes.
mkdir -p "$TMP/c3/db"; mk_reducer "$TMP/c3/red"
cat > "$TMP/c3/db/V001__x.sql" <<'SQL'
CREATE TABLE public.blob_cleanup_queue ( id bigint, blob_sha text, delete_after timestamptz );
SQL
if run "$TMP/c3/db" "$TMP/c3/red"; then pass "waived table tolerated"
else bad "waived table should be tolerated"; sed 's/^/        /' "$TMP/out"; fi

# Case 4 — missing settle_job reducer fails.
mkdir -p "$TMP/c4/db" "$TMP/c4/red"
cat > "$TMP/c4/db/V001__x.sql" <<'SQL'
CREATE TABLE public.widget_queue ( id bigint, status text, attempt_count int, next_attempt_at timestamptz, last_error text );
SQL
if run "$TMP/c4/db" "$TMP/c4/red"; then
  bad "missing settle_job — guard did NOT fail"; sed 's/^/        /' "$TMP/out"
else pass "missing settle_job reducer — caught"; fi

if [ "$fail" -ne 0 ]; then
  echo "==> queue-contract guard self-test FAILED"; exit 1
fi
echo "    queue-contract self-test: fires on missing col + missing reducer, passes compliant + waived."
