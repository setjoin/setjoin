#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-denial-selftest.sh — proves check-rls-denial.sh actually FIRES.
# Builds a synthetic schema dir + tests dir + allowlist and asserts:
#   (A) a FORCE'd table with NO allowlist entry FAILS (exit 1, names it).
#   (B) the same table, classified PENDING, PASSES (gap allowed, not silent —
#       just not a failure).
#   (C) the same table, classified COVERED pointing at a real SET LOCAL ROLE
#       test containing the recorded substring, PASSES.
#   (D) COVERED but the substring is WRONG/stale → FAILS (stale classification
#       caught, not silently trusted).
#   (E) COVERED but the file has no SET ROLE line (not actually a non-owner
#       proof) → FAILS.
#   (F) COVERED but the named file doesn't exist → FAILS.
# Runs FIRST via run-guards.sh so a broken guard is caught before we trust it.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GUARD="$(dirname "$0")/check-rls-denial.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/schema" "$WORK/tests"

# One FORCE'd table, mirroring the real migration shape (variable whitespace).
cat > "$WORK/schema/V999__selftest.sql" <<'SQL'
CREATE TABLE public.widgets (id bigint PRIMARY KEY, owner_id bigint);
ALTER TABLE public.widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.widgets FORCE  ROW LEVEL SECURITY;
SQL

# A real-shaped denial test: SET LOCAL ROLE + a two-tenant assertion string.
cat > "$WORK/tests/widgets_rls.pg" <<'PG'
BEGIN;
SET LOCAL ROLE setjoin_app;
SELECT is((SELECT count(*) FROM widgets WHERE owner_id = 2)::INT, 0,
  'widgets: B''s row is invisible to A');
RESET ROLE;
ROLLBACK;
PG

pass=0; fail=0
ok()  { echo "  ok: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

run_guard() { # <allowlist-file>
  RLS_DENIAL_SCHEMA_DIR="$WORK/schema" RLS_DENIAL_TESTS_DIR="$WORK/tests" \
    RLS_DENIAL_ALLOWLIST_FILE="$1" bash "$GUARD" 2>&1
}

# (A) empty allowlist → guard FAILS and names the table.
ALLOW_EMPTY="$WORK/allow-empty.txt"; : > "$ALLOW_EMPTY"
rc=0; out="$(run_guard "$ALLOW_EMPTY")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(A) unclassified FORCE'd table fails the guard"; else bad "(A) guard PASSED with an unclassified table (false-negative!)"; fi
if printf '%s' "$out" | grep -qi 'widgets: FORCE'"'"'d table has NO entry'; then ok "(A) names the table"; else bad "(A) did not name the table"; fi

# (B) PENDING classification → guard PASSES.
ALLOW_PENDING="$WORK/allow-pending.txt"
printf 'widgets\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_PENDING"
rc=0; out="$(run_guard "$ALLOW_PENDING")" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(B) PENDING classification passes the guard"; else bad "(B) PENDING classification FAILED the guard:"$'\n'"$out"; fi
if printf '%s' "$out" | grep -qi 'allowlisted PENDING (gap):  *1'; then ok "(B) pending count reported"; else bad "(B) pending count not reported"; fi

# (C) COVERED, real file + real substring → guard PASSES.
ALLOW_COVERED="$WORK/allow-covered.txt"
printf 'widgets\tCOVERED\twidgets_rls.pg\twidgets: B'"''"'s row is invisible to A\tselftest\n' > "$ALLOW_COVERED"
rc=0; out="$(run_guard "$ALLOW_COVERED")" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(C) COVERED with a real denial test passes"; else bad "(C) COVERED with a real denial test FAILED:"$'\n'"$out"; fi
if printf '%s' "$out" | grep -qi 'with denial test (COVERED): 1'; then ok "(C) covered count reported"; else bad "(C) covered count not reported"; fi

# (D) COVERED but substring is stale/wrong → guard FAILS.
ALLOW_STALE_SUB="$WORK/allow-stale-sub.txt"
printf 'widgets\tCOVERED\twidgets_rls.pg\tthis text was never written\tselftest stale\n' > "$ALLOW_STALE_SUB"
rc=0; out="$(run_guard "$ALLOW_STALE_SUB")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(D) stale substring is caught (guard fires)"; else bad "(D) stale substring NOT caught (false-negative!)"; fi

# (E) COVERED but the file has no SET ROLE line → guard FAILS.
cat > "$WORK/tests/no_role.pg" <<'PG'
BEGIN;
SELECT is((SELECT count(*) FROM widgets)::INT, 0, 'widgets: B''s row is invisible to A');
ROLLBACK;
PG
ALLOW_NO_ROLE="$WORK/allow-no-role.txt"
printf 'widgets\tCOVERED\tno_role.pg\twidgets: B'"''"'s row is invisible to A\tselftest no-role\n' > "$ALLOW_NO_ROLE"
rc=0; out="$(run_guard "$ALLOW_NO_ROLE")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(E) missing SET ROLE line is caught (not a real non-owner proof)"; else bad "(E) missing SET ROLE line NOT caught (false-negative!)"; fi

# (F) COVERED but the named file doesn't exist → guard FAILS.
ALLOW_MISSING_FILE="$WORK/allow-missing-file.txt"
printf 'widgets\tCOVERED\tdoes_not_exist.pg\tanything\tselftest missing file\n' > "$ALLOW_MISSING_FILE"
rc=0; out="$(run_guard "$ALLOW_MISSING_FILE")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(F) missing test file is caught"; else bad "(F) missing test file NOT caught (false-negative!)"; fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-rls-denial selftest FAILED ($fail/$((pass+fail)) checks failed) — the guard does not behave as specified."
  exit 1
fi
echo "check-rls-denial selftest: all $pass checks passed (guard fires + is precise)."
