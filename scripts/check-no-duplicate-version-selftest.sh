#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-no-duplicate-version-selftest.sh — negative-case self-test for the
# migration version-suffix dedup guard.
#
# A guard that never fires is theater. This drives check-no-duplicate-version.sh
# against TEMP migration trees (via the guard's MIGRATION_DIRS override, so the
# real repo tree is never touched) and asserts:
#   1. a tree seeded with V099__a.sql + V099__b.sql (a NEW, non-allowlisted dup)
#      → guard exits 1 AND names V099.
#   2. a clean tree (no duplicate versions) → guard exits 0.
#   3. a tree whose only duplicate is an ALLOWLISTED version (V051__x + V051__y)
#      → guard exits 0 (the frozen-pair allowlist still suppresses it).
#
# Usage: scripts/check-no-duplicate-version-selftest.sh   (exit 0 = all cases pass).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-no-duplicate-version.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

run_guard() { # <dirs> → writes $TMP/out, returns guard exit code
  MIGRATION_DIRS="$1" bash "$GUARD" > "$TMP/out" 2>&1
  return $?
}

echo "==> dedup-guard self-test (must fire on a planted 5th duplicate)"

# Case 1 — a NEW (non-allowlisted) duplicate version must fail with the version named.
mkdir -p "$TMP/dup"
: > "$TMP/dup/V001__base.sql"
: > "$TMP/dup/V099__a.sql"
: > "$TMP/dup/V099__b.sql"
if run_guard "$TMP/dup"; then
  bad "planted V099 duplicate — guard did NOT fail"; sed 's/^/        /' "$TMP/out"
elif grep -q 'V099' "$TMP/out"; then
  pass "planted V099 duplicate — caught (guard exit 1, names V099)"
else
  bad "planted V099 duplicate — failed but without naming V099"; sed 's/^/        /' "$TMP/out"
fi

# Case 2 — a CLEAN tree (distinct versions) must pass.
mkdir -p "$TMP/clean"
: > "$TMP/clean/V001__a.sql"
: > "$TMP/clean/V002__b.sql"
: > "$TMP/clean/V003__c.sql"
if run_guard "$TMP/clean"; then
  pass "clean tree passes"
else
  bad "clean tree should pass"; sed 's/^/        /' "$TMP/out"
fi

# Case 3 — a duplicate on an ALLOWLISTED version (V051) must still pass.
mkdir -p "$TMP/allow"
: > "$TMP/allow/V051__x.sql"
: > "$TMP/allow/V051__y.sql"
if run_guard "$TMP/allow"; then
  pass "allowlisted V051 duplicate is tolerated (frozen-pair allowlist)"
else
  bad "allowlisted V051 duplicate should be tolerated"; sed 's/^/        /' "$TMP/out"
fi

if [ "$fail" -ne 0 ]; then
  echo "==> dedup-guard self-test FAILED — the guard stopped catching a duplicate version."
  exit 1
fi
echo "    dedup-guard self-test: fires on a new dup, passes clean + allowlisted."
