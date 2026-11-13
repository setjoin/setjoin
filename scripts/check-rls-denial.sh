#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-denial.sh — cross-tenant DENIAL-TEST coverage guard.
#
# WHY THIS EXISTS. check-rls-coverage.sh (W7) proves every app-pool call site
# touching a FORCE'd table is CLASSIFIED (WRAPPED/BYPASS/AUDITED-XTENANT) — it
# is a Go-side coverage guard. It says nothing about whether the DATABASE
# POLICY ITSELF actually denies a foreign tenant's row. A table can ship
# `ENABLE + FORCE ROW LEVEL SECURITY` with a policy that is enabled-but-wrong
# (predicate always true, wrong column, missing WITH CHECK) and every existing
# guard still passes — "RLS is on" is not "RLS denies". The only thing that
# proves a policy actually WORKS is a pgTAP case that runs as the constrained,
# non-owner runtime role (SET LOCAL ROLE setjoin_app / setjoin_worker — the
# test connection `mail` is a SUPERUSER + table owner, so it bypasses RLS even
# under FORCE) with a SECOND tenant's row present, asserting that row is
# inaccessible (0-count SELECT, no-op UPDATE/DELETE, or a 42501).
#
# WHAT IT DOES. Enumerates every `ALTER TABLE ... FORCE ROW LEVEL SECURITY`
# target across mailserver/sql/dbschema/*.sql (baseline + every migration —
# the FORCE'd-table set is derived from the schema itself, not hand-maintained
# here) and requires EVERY one of them to have an entry in
# scripts/rls-denial-allowlist.txt, classified as:
#   · COVERED — names the mailserver/sql/tests/*.pg file + a stable substring
#               of that file's own denial assertion. The guard verifies the
#               file exists, still contains a SET LOCAL ROLE / SET ROLE line,
#               AND still contains the substring — so a deleted or gutted
#               test re-fails the guard instead of the classification
#               silently rotting.
#   · PENDING — no denial test exists yet for this table. Does NOT fail the
#               guard (that is how a fresh gap is seeded green), but is
#               counted and reported every run so the debt stays visible.
# A FORCE'd table with NO entry at all (neither COVERED nor PENDING) FAILS —
# a migration can't silently add FORCE without a human recording a decision.
#
# RELATIONSHIP TO check-rls-coverage.sh: that guard asks "is every raw
# app-pool SQL site touching this table CLASSIFIED for the FORCE flip?"; this
# guard asks the orthogonal "does the FORCE'd policy on this table actually
# DENY a foreign tenant, proven under the real runtime role?" A table can pass
# one and fail the other.
#
# Usage: scripts/check-rls-denial.sh   (exit 0 = every FORCE'd table
#        classified [COVERED verified, or PENDING], 1 = a gap or stale entry).
# Self-test: scripts/check-rls-denial-selftest.sh (run first by run-guards.sh).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export LC_ALL=C

# Overridable for the self-test (points at a synthetic tree); default to the
# real one.
SCHEMA_DIR="${RLS_DENIAL_SCHEMA_DIR:-$ROOT/mailserver/sql/dbschema}"
TESTS_DIR="${RLS_DENIAL_TESTS_DIR:-$ROOT/mailserver/sql/tests}"
ALLOWLIST_FILE="${RLS_DENIAL_ALLOWLIST_FILE:-$(dirname "$0")/rls-denial-allowlist.txt}"

echo "==> RLS cross-tenant DENIAL-TEST coverage guard"

if [ ! -f "$ALLOWLIST_FILE" ]; then
  echo "  [RLS-DENY] allowlist file not found: $ALLOWLIST_FILE" >&2
  exit 1
fi

fail=0
report() { echo "  $1"; fail=1; }

# ── 1. Compute the FORCE'd-table set from the schema itself ─────────────────
# Matches `ALTER TABLE [public.]<table> FORCE  ROW LEVEL SECURITY;` (variable
# whitespace observed in the wild between FORCE and ROW). Table name captured
# word-bounded; schema-qualifier optional and stripped.
FORCE_TABLES="$(grep -hE 'ALTER TABLE[[:space:]]+(public\.)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]+FORCE[[:space:]]+ROW LEVEL SECURITY' \
    "$SCHEMA_DIR"/*.sql 2>/dev/null \
  | sed -E 's/^[[:space:]]*ALTER TABLE[[:space:]]+(public\.)?([A-Za-z_][A-Za-z0-9_]*).*/\2/' \
  | LC_ALL=C sort -u)"

if [ -z "$FORCE_TABLES" ]; then
  echo "  [RLS-DENY] no 'FORCE ROW LEVEL SECURITY' tables found under $SCHEMA_DIR — nothing to check (suspicious; is SCHEMA_DIR right?)." >&2
  exit 1
fi

# ── 2. Load the allowlist (comments/blank lines stripped) ───────────────────
ALLOW_LINES="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST_FILE" || true)"

# find_entry <table> — prints the matching allowlist line (first match) or
# nothing. Field 1 is an exact table-name match (not a substring).
find_entry() {
  local table="$1" line key
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    key="${line%%	*}"
    [ "$key" = "$table" ] || continue
    printf '%s\n' "$line"
    return 0
  done <<< "$ALLOW_LINES"
  return 1
}

total=0
covered=0
pending=0

while IFS= read -r table; do
  [ -z "$table" ] && continue
  total=$((total + 1))

  entry="$(find_entry "$table")" || {
    report "[RLS-DENY] $table: FORCE'd table has NO entry in $ALLOWLIST_FILE."
    report "           → add a line classifying it COVERED (name the .pg file + assertion substring) or PENDING (name the gap)."
    continue
  }

  # Fields: table \t STATUS \t file \t substring \t reason
  status="$(printf '%s' "$entry" | cut -f2)"
  file="$(printf '%s' "$entry" | cut -f3)"
  sub="$(printf '%s' "$entry" | cut -f4)"

  case "$status" in
    PENDING)
      pending=$((pending + 1))
      ;;
    COVERED)
      testpath="$TESTS_DIR/$file"
      if [ -z "$file" ] || [ "$file" = "-" ] || [ ! -f "$testpath" ]; then
        report "[RLS-DENY] $table: COVERED but test file '$file' not found under $TESTS_DIR."
        continue
      fi
      if ! grep -qE 'SET[[:space:]]+(LOCAL[[:space:]]+)?ROLE' "$testpath"; then
        report "[RLS-DENY] $table: COVERED but $file no longer contains a SET [LOCAL] ROLE switch (denial proof must run as a non-owner role)."
        continue
      fi
      if [ -z "$sub" ] || [ "$sub" = "-" ] || ! grep -qF "$sub" "$testpath"; then
        report "[RLS-DENY] $table: COVERED but the recorded assertion substring is no longer present in $file (stale classification — test was renamed/weakened/deleted)."
        report "           → re-verify the denial proof still exists and update the substring in $ALLOWLIST_FILE, or flip to PENDING if it was removed."
        continue
      fi
      covered=$((covered + 1))
      ;;
    *)
      report "[RLS-DENY] $table: unknown STATUS '$status' in $ALLOWLIST_FILE (must be COVERED or PENDING)."
      ;;
  esac
done <<< "$FORCE_TABLES"

echo ""
echo "  FORCE'd tables total:      $total"
echo "  with denial test (COVERED): $covered"
echo "  allowlisted PENDING (gap):  $pending"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "RLS denial-test guard FAILED — see above."
  echo "Every 'FORCE ROW LEVEL SECURITY' table must be classified in scripts/rls-denial-allowlist.txt."
  exit 1
fi

echo ""
echo "    RLS denial-test guard: clean (every FORCE'd table classified; every COVERED entry verified live)."
