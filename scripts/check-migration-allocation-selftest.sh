#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-migration-allocation-selftest.sh — negative-case self-test for the
# migration/BZ allocation guard.
#
# A guard that never fires is theater. This drives check-migration-allocation.sh
# against a TEMP fixture dir (via the guard's MIGRATION_DIRS / REDUCER_DIR
# overrides, so the real repo tree is never touched) and asserts:
#   1. a tree seeded with two V025__*.sql files → guard exits 1 (duplicate).
#   2. a clean tree (single V025) → guard exits 0.
#
# Usage: scripts/check-migration-allocation-selftest.sh  (exit 0 = all cases pass).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-migration-allocation.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

run_guard() { # <migration_dir> <reducer_dir>
  MIGRATION_DIRS="$1" REDUCER_DIR="$2" bash "$GUARD" >"$TMP/out" 2>&1
  return $?
}

echo "==> allocation-guard self-test (must fire on a planted duplicate V025)"

# Shared clean reducer dir — no BZ079 collisions in fixture tests.
mkdir -p "$TMP/reducers_clean"

# Case 1 — two files with V025__ prefix → guard must fail and name V025.
mkdir -p "$TMP/dup"
: > "$TMP/dup/V025__a.sql"
: > "$TMP/dup/V025__b.sql"
if run_guard "$TMP/dup" "$TMP/reducers_clean"; then
  bad "planted V025 duplicate — guard did NOT fail"
  sed 's/^/        /' "$TMP/out"
elif grep -q 'V025' "$TMP/out"; then
  pass "planted V025 duplicate — caught (guard exit 1, names V025)"
else
  bad "planted V025 duplicate — failed but without naming V025"
  sed 's/^/        /' "$TMP/out"
fi

# Case 2 — clean tree (single V025) with no BZ079 in reducers → guard must pass.
mkdir -p "$TMP/clean"
: > "$TMP/clean/V025__ca_foundation.sql"
if run_guard "$TMP/clean" "$TMP/reducers_clean"; then
  pass "clean tree (singular V025, no BZ079 collision) passes"
else
  bad "clean tree should pass"
  sed 's/^/        /' "$TMP/out"
fi

if [ "$fail" -ne 0 ]; then
  echo "==> allocation-guard self-test FAILED — the guard stopped catching a duplicate V025."
  exit 1
fi
echo "    allocation-guard self-test: fires on dup V025, passes clean tree."
