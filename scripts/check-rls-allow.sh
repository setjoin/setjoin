#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-allow.sh — ALLOW-side RLS coverage guard (arch review #A4, TOP REC).
#
# WHY THIS EXISTS. check-rls-denial.sh proves a FORCE'd table's policy DENIES
# a foreign tenant's row. It is structurally blind to the mirror bug: a
# missing or wrong ALLOW arm, where the LEGITIMATE write from the table's own
# owner also fails under the constrained setjoin_app role. Both recent
# native-RLS flip-blockers were exactly this shape and escaped the full pgTAP
# suite, caught only on the live VM:
#   · V125 meet: `meetings` shipped a SELECT-only policy — meeting_create
#     500'd live (there was no INSERT arm at all).
#   · V135 drive: `drive_chunks_insert`'s WITH CHECK denied every
#     chat-derived member (the 'g'-scope arm checked drive_space_members
#     directly and never resolved a chat-bound space).
# This is docs/standards/DATABASE_SECURITY.md's own "coverage claims need a
# machine guard" rule, unapplied to the allow side until now.
#
# WHAT IT DOES. For every FORCE'd table (schema-derived, same regex as
# check-rls-denial.sh) that BOTH (a) a reducer actually writes
# (INSERT/UPDATE/DELETE anywhere in mailserver/sql/reducers/*.sql) AND
# (b) carries at least one RLS policy capable of admitting a write (FOR ALL /
# INSERT / UPDATE / DELETE, or no FOR clause at all — default ALL) — this
# guard requires a human-recorded entry in scripts/rls-allow-allowlist.txt
# naming an as-`setjoin_app` FLOW test that proves the LEGITIMATE write path
# actually succeeds under the constrained runtime role.
#
# A table with reducer writers but NO write-capable policy (only FOR SELECT,
# or zero policies at all — e.g. `user_risk`/`session_activity`, worker/
# BYPASSRLS-only writers) is auto-excluded: no app-role write is structurally
# possible, so no ALLOW proof is possible OR required. This is computed live
# from the schema every run — nothing to hand-maintain, and a later migration
# that adds a write-capable policy is automatically pulled into scope on its
# very next run without anyone touching the allowlist.
#
# Classification (mirrors check-rls-denial.sh's convention exactly):
#   · COVERED — names the mailserver/sql/tests/*.pg file + a stable substring
#               of that file's own success assertion. The guard verifies the
#               file exists, still contains a SET [LOCAL] ROLE line, AND
#               still contains the substring — a deleted/gutted/renamed test
#               re-fails the guard instead of the classification rotting.
#   · PENDING — no allow-side flow test exists yet. Does NOT fail the guard
#               (that is how a fresh gap is seeded green), but is counted and
#               reported every run so the debt stays visible.
# A required table with NO entry at all (neither COVERED nor PENDING) FAILS —
# a migration can't silently ship a write-capable FORCE'd table without a
# human recording a decision.
#
# RELATIONSHIP TO check-rls-denial.sh: that guard asks "does the FORCE'd
# policy DENY a foreign tenant?"; this guard asks the mirror question "does
# the FORCE'd policy actually ADMIT the table's own legitimate writer?" A
# table can pass one and fail the other — proving both is what "RLS works"
# actually means.
#
# Usage: scripts/check-rls-allow.sh   (exit 0 = every required table
#        classified [COVERED verified, or PENDING], 1 = a gap or stale entry).
# Self-test: scripts/check-rls-allow-selftest.sh (run first by run-guards.sh).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export LC_ALL=C

SCHEMA_DIR="${RLS_ALLOW_SCHEMA_DIR:-$ROOT/mailserver/sql/dbschema}"
REDUCERS_DIR="${RLS_ALLOW_REDUCERS_DIR:-$ROOT/mailserver/sql/reducers}"
TESTS_DIR="${RLS_ALLOW_TESTS_DIR:-$ROOT/mailserver/sql/tests}"
ALLOWLIST_FILE="${RLS_ALLOW_ALLOWLIST_FILE:-$(dirname "$0")/rls-allow-allowlist.txt}"

echo "==> RLS ALLOW-side coverage guard (#A4)"

if [ ! -f "$ALLOWLIST_FILE" ]; then
  echo "  [RLS-ALLOW] allowlist file not found: $ALLOWLIST_FILE" >&2
  exit 1
fi

fail=0
report() { echo "  $1"; fail=1; }

# ── 1. FORCE'd-table set — identical derivation to check-rls-denial.sh ─────
FORCE_TABLES="$(grep -hE 'ALTER TABLE[[:space:]]+(public\.)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]+FORCE[[:space:]]+ROW LEVEL SECURITY' \
    "$SCHEMA_DIR"/*.sql 2>/dev/null \
  | sed -E 's/^[[:space:]]*ALTER TABLE[[:space:]]+(public\.)?([A-Za-z_][A-Za-z0-9_]*).*/\2/' \
  | LC_ALL=C sort -u)"

if [ -z "$FORCE_TABLES" ]; then
  echo "  [RLS-ALLOW] no 'FORCE ROW LEVEL SECURITY' tables found under $SCHEMA_DIR — nothing to check (suspicious; is SCHEMA_DIR right?)." >&2
  exit 1
fi

# ── 2. WRITER tables: an INSERT/UPDATE/DELETE against the table appears
#    anywhere in the reducer layer (the app-role's only legitimate write
#    surface — raw gateway writes to these tables are out of scope here,
#    covered instead by check-gateway-ownership.sh). ────────────────────────
WRITER_TABLES="$(grep -ohE '(INSERT INTO|UPDATE|DELETE FROM)[[:space:]]+(ONLY[[:space:]]+)?(public\.)?[A-Za-z_][A-Za-z0-9_]*' \
    "$REDUCERS_DIR"/*.sql 2>/dev/null \
  | sed -E 's/^(INSERT INTO|UPDATE|DELETE FROM)[[:space:]]+(ONLY[[:space:]]+)?(public\.)?//' \
  | LC_ALL=C sort -u)"

# ── 3. WRITECAP tables: at least one CREATE POLICY on the table can admit a
#    setjoin_app non-SELECT command (FOR ALL/INSERT/UPDATE/DELETE, or no FOR
#    clause — PostgreSQL defaults an omitted FOR to ALL). Exact owner-only
#    USING+WITH CHECK policies are excluded: those tables are intentionally
#    writable only through BYPASSRLS/SECURITY DEFINER worker reducers and have
#    no legitimate setjoin_app write to prove. Table-name capture handles
#    both `ON public.<table>` and the bare `ON <table>` some migrations use.
#    RS=";" treats each SQL statement (policies never embed a literal ';') as
#    one awk record so a policy's FOR clause on its own line is still seen. ─
WRITECAP_TABLES="$(cat "$SCHEMA_DIR"/*.sql 2>/dev/null | awk '
  BEGIN { RS=";" }
  /CREATE[ \t\n]+POLICY/ {
    stmt = $0
    if (match(stmt, /ON[ \t\n]+(public\.)?[A-Za-z_][A-Za-z0-9_]*/)) {
      tbl = substr(stmt, RSTART, RLENGTH)
      gsub(/ON[ \t\n]+(public\.)?/, "", tbl)
      gsub(/[ \t\n]+$/, "", tbl)
      wc = 0
      if (stmt ~ /FOR[ \t\n]+(ALL|INSERT|UPDATE|DELETE)/) wc = 1
      if (stmt !~ /FOR[ \t\n]+(ALL|SELECT|INSERT|UPDATE|DELETE)/) wc = 1
      normalized = tolower(stmt)
      gsub(/[ \t\n\r]+/, "", normalized)
      if (normalized ~ /using\(current_user=\047setjoin_owner\047\)withcheck\(current_user=\047setjoin_owner\047\)/) wc = 0
      if (wc) print tbl
    }
  }' | LC_ALL=C sort -u)"

# ── 4. Load the allowlist (comments/blank lines stripped) ───────────────────
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

total_force=0
total_required=0
excluded_no_writecap=0
excluded_no_writer=0
covered=0
pending=0

while IFS= read -r table; do
  [ -z "$table" ] && continue
  total_force=$((total_force + 1))

  if ! grep -qxF "$table" <<< "$WRITER_TABLES"; then
    excluded_no_writer=$((excluded_no_writer + 1))
    continue
  fi
  if ! grep -qxF "$table" <<< "$WRITECAP_TABLES"; then
    excluded_no_writecap=$((excluded_no_writecap + 1))
    continue
  fi

  total_required=$((total_required + 1))

  entry="$(find_entry "$table")" || {
    report "[RLS-ALLOW] $table: FORCE'd + has a reducer writer + has a write-capable policy, but NO entry in $ALLOWLIST_FILE."
    report "            → add a line classifying it COVERED (name the .pg file + a success-assertion substring, run as SET [LOCAL] ROLE setjoin_app) or PENDING (name the gap)."
    continue
  }

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
        report "[RLS-ALLOW] $table: COVERED but test file '$file' not found under $TESTS_DIR."
        continue
      fi
      if ! grep -qE 'SET[[:space:]]+(LOCAL[[:space:]]+)?ROLE' "$testpath"; then
        report "[RLS-ALLOW] $table: COVERED but $file no longer contains a SET [LOCAL] ROLE switch (the allow proof must run as a non-owner role)."
        continue
      fi
      if [ -z "$sub" ] || [ "$sub" = "-" ] || ! grep -qF "$sub" "$testpath"; then
        report "[RLS-ALLOW] $table: COVERED but the recorded assertion substring is no longer present in $file (stale classification — test was renamed/weakened/deleted)."
        report "            → re-verify the allow proof still exists and update the substring in $ALLOWLIST_FILE, or flip to PENDING if it was removed."
        continue
      fi
      covered=$((covered + 1))
      ;;
    *)
      report "[RLS-ALLOW] $table: unknown STATUS '$status' in $ALLOWLIST_FILE (must be COVERED or PENDING)."
      ;;
  esac
done <<< "$FORCE_TABLES"

echo ""
echo "  FORCE'd tables total:               $total_force"
echo "  excluded (no reducer writer):       $excluded_no_writer"
echo "  excluded (no write-capable policy — worker/BYPASSRLS-only, auto): $excluded_no_writecap"
echo "  required (writer + write-capable):  $total_required"
echo "  with allow-flow test (COVERED):     $covered"
echo "  allowlisted PENDING (gap):          $pending"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "RLS allow-test guard FAILED — see above."
  echo "Every FORCE'd table with a reducer writer AND a write-capable policy must be classified in scripts/rls-allow-allowlist.txt."
  exit 1
fi

echo ""
echo "    RLS allow-test guard: clean (every required table classified; every COVERED entry verified live)."
