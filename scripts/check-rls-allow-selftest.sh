#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-allow-selftest.sh — proves check-rls-allow.sh actually FIRES.
# Builds a synthetic schema dir + reducers dir + tests dir + allowlist and
# asserts:
#   (A) a FORCE'd table with a writer + a write-capable policy + NO allowlist
#       entry FAILS (exit 1, names it).
#   (B) the same table, classified PENDING, PASSES (gap allowed, not silent).
#   (C) the same table, classified COVERED pointing at a real SET LOCAL ROLE
#       test containing the recorded substring, PASSES.
#   (D) COVERED but the substring is WRONG/stale → FAILS.
#   (E) COVERED but the file has no SET ROLE line → FAILS.
#   (F) COVERED but the named file doesn't exist → FAILS.
#   (G) a FORCE'd table with NO reducer writer at all is excluded — NOT
#       required to have an entry, even with an empty allowlist.
#   (H) a FORCE'd table with a writer but ONLY a FOR SELECT policy (the
#       user_risk/session_activity shape) is excluded too — no entry needed.
#   (I) a FORCE'd table with a writer and a policy with NO explicit FOR
#       clause (defaults to ALL) IS required — the omitted-FOR-clause case
#       must not be mistaken for select-only.
#   (J) a FORCE'd table with an exact setjoin_owner-only write policy is
#       excluded because no setjoin_app write can legitimately succeed.
# Runs FIRST via run-guards.sh so a broken guard is caught before we trust it.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GUARD="$(dirname "$0")/check-rls-allow.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/schema" "$WORK/reducers" "$WORK/tests"

# Five FORCE'd tables, mirroring the real migration shape (variable
# whitespace before ROW LEVEL SECURITY, like the real V114 loop artifacts):
#   widgets      — writer + FOR ALL policy (the normal required case, A-F)
#   untouched    — writer NONE, FOR ALL policy (excluded, G)
#   readonly     — writer + FOR SELECT policy ONLY (excluded, H)
#   defaultall   — writer + a policy with NO FOR clause at all (required, I)
#   workeronly   — writer + owner-only ALL policy (excluded, J)
cat > "$WORK/schema/V999__selftest.sql" <<'SQL'
CREATE TABLE public.widgets (id bigint PRIMARY KEY, owner_id bigint);
ALTER TABLE public.widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.widgets FORCE  ROW LEVEL SECURITY;
CREATE POLICY widgets_self ON public.widgets
  FOR ALL TO public
  USING (owner_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (owner_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));

CREATE TABLE public.untouched (id bigint PRIMARY KEY, owner_id bigint);
ALTER TABLE public.untouched ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.untouched FORCE  ROW LEVEL SECURITY;
CREATE POLICY untouched_self ON public.untouched
  FOR ALL TO public
  USING (owner_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));

CREATE TABLE public.readonly (id bigint PRIMARY KEY, owner_id bigint);
ALTER TABLE public.readonly ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.readonly FORCE  ROW LEVEL SECURITY;
CREATE POLICY readonly_self ON public.readonly
  FOR SELECT
  USING (owner_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));

CREATE TABLE public.defaultall (id bigint PRIMARY KEY, owner_id bigint);
ALTER TABLE public.defaultall ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.defaultall FORCE  ROW LEVEL SECURITY;
CREATE POLICY defaultall_self ON public.defaultall
  USING (owner_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));

CREATE TABLE public.workeronly (id bigint PRIMARY KEY);
ALTER TABLE public.workeronly ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workeronly FORCE ROW LEVEL SECURITY;
CREATE POLICY workeronly_owner ON public.workeronly
  USING (current_user='setjoin_owner') WITH CHECK (current_user='setjoin_owner');
SQL

# Reducer writers: widgets, readonly, defaultall all have one; untouched has none.
cat > "$WORK/reducers/widgets.sql" <<'SQL'
CREATE OR REPLACE FUNCTION widget_create(p_owner_id bigint) RETURNS bigint AS $$
BEGIN
  INSERT INTO widgets (owner_id) VALUES (p_owner_id);
  RETURN 1;
END;
$$ LANGUAGE plpgsql;
SQL
cat > "$WORK/reducers/readonly.sql" <<'SQL'
CREATE OR REPLACE FUNCTION readonly_seed(p_owner_id bigint) RETURNS void AS $$
BEGIN
  INSERT INTO readonly (owner_id) VALUES (p_owner_id);  -- worker/BYPASSRLS-only in practice
END;
$$ LANGUAGE plpgsql;
SQL
cat > "$WORK/reducers/defaultall.sql" <<'SQL'
CREATE OR REPLACE FUNCTION defaultall_create(p_owner_id bigint) RETURNS void AS $$
BEGIN
  INSERT INTO defaultall (owner_id) VALUES (p_owner_id);
END;
$$ LANGUAGE plpgsql;
SQL
cat > "$WORK/reducers/workeronly.sql" <<'SQL'
CREATE OR REPLACE FUNCTION workeronly_create() RETURNS void AS $$
BEGIN
  INSERT INTO workeronly DEFAULT VALUES;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
SQL

# A real-shaped allow test: SET LOCAL ROLE + a success assertion string.
cat > "$WORK/tests/widgets_rls.pg" <<'PG'
BEGIN;
SET LOCAL ROLE setjoin_app;
SELECT lives_ok($$ SELECT widget_create(1) $$, 'widget_create succeeds as setjoin_app');
RESET ROLE;
ROLLBACK;
PG

pass=0; fail=0
ok()  { echo "  ok: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

run_guard() { # <allowlist-file>
  RLS_ALLOW_SCHEMA_DIR="$WORK/schema" RLS_ALLOW_REDUCERS_DIR="$WORK/reducers" \
    RLS_ALLOW_TESTS_DIR="$WORK/tests" RLS_ALLOW_ALLOWLIST_FILE="$1" bash "$GUARD" 2>&1
}

# (A) empty allowlist → guard FAILS and names widgets (the only required table
#     with zero entries at this point).
ALLOW_EMPTY="$WORK/allow-empty.txt"; : > "$ALLOW_EMPTY"
rc=0; out="$(run_guard "$ALLOW_EMPTY")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(A) unclassified required table fails the guard"; else bad "(A) guard PASSED with an unclassified table (false-negative!)"; fi
if printf '%s' "$out" | grep -qi 'widgets: FORCE'"'"'d + has a reducer writer'; then ok "(A) names widgets"; else bad "(A) did not name widgets"; fi
if printf '%s' "$out" | grep -qi 'defaultall: FORCE'"'"'d + has a reducer writer'; then ok "(A) also names defaultall (no-FOR-clause = ALL)"; else bad "(A) did not name defaultall"; fi
if printf '%s' "$out" | grep -qi 'untouched:'; then bad "(A) wrongly flagged untouched (no reducer writer — should be excluded)"; else ok "(A) untouched correctly excluded"; fi
if printf '%s' "$out" | grep -qi 'readonly:'; then bad "(A) wrongly flagged readonly (SELECT-only policy — should be excluded)"; else ok "(A) readonly correctly excluded"; fi
if printf '%s' "$out" | grep -qi 'workeronly:'; then bad "(A) wrongly flagged workeronly (owner-only policy — should be excluded)"; else ok "(A) workeronly correctly excluded"; fi

# (G)/(H) counts reported even with an empty allowlist (still fails overall,
# but the exclusion accounting must be visible).
if printf '%s' "$out" | grep -qi 'excluded (no reducer writer):       1'; then ok "(G) no-writer exclusion counted"; else bad "(G) no-writer exclusion not counted"; fi
if printf '%s' "$out" | grep -qi 'excluded (no write-capable policy'; then ok "(H) select-only exclusion counted"; else bad "(H) select-only exclusion not counted"; fi

# (J) The exclusion above is load-bearing: removing its special handling would
# make workeronly appear as an unclassified app-write table in case A.
if printf '%s' "$out" | grep -qi 'excluded (no write-capable policy — worker/BYPASSRLS-only, auto): 2'; then
  ok "(J) owner-only worker policy is counted with non-app-write exclusions"
else
  bad "(J) owner-only worker policy exclusion not counted"
fi

# (B) PENDING classification for widgets + defaultall → guard PASSES.
ALLOW_PENDING="$WORK/allow-pending.txt"
printf 'widgets\tPENDING\t-\t-\tselftest gap\ndefaultall\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_PENDING"
rc=0; out="$(run_guard "$ALLOW_PENDING")" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(B) PENDING classification passes the guard"; else bad "(B) PENDING classification FAILED the guard:"$'\n'"$out"; fi
if printf '%s' "$out" | grep -qi 'allowlisted PENDING (gap):          2'; then ok "(B) pending count reported"; else bad "(B) pending count not reported"; fi

# (I) defaultall (no explicit FOR clause) is counted as required, not excluded —
# proven by (B) needing an entry for it to pass at all; double-check directly.
ALLOW_ONLY_WIDGETS="$WORK/allow-only-widgets.txt"
printf 'widgets\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_ONLY_WIDGETS"
rc=0; out="$(run_guard "$ALLOW_ONLY_WIDGETS")" || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'defaultall: FORCE'"'"'d + has a reducer writer'; then
  ok "(I) omitted-FOR-clause policy (defaults to ALL) is correctly treated as write-capable/required"
else
  bad "(I) defaultall was NOT required despite its policy having no FOR clause (defaults to ALL) — false-negative!"
fi

# (C) COVERED, real file + real substring → guard PASSES.
ALLOW_COVERED="$WORK/allow-covered.txt"
printf 'widgets\tCOVERED\twidgets_rls.pg\twidget_create succeeds as setjoin_app\tselftest\ndefaultall\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_COVERED"
rc=0; out="$(run_guard "$ALLOW_COVERED")" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(C) COVERED with a real allow test passes"; else bad "(C) COVERED with a real allow test FAILED:"$'\n'"$out"; fi
if printf '%s' "$out" | grep -qi 'with allow-flow test (COVERED):     1'; then ok "(C) covered count reported"; else bad "(C) covered count not reported"; fi

# (D) COVERED but substring is stale/wrong → guard FAILS.
ALLOW_STALE_SUB="$WORK/allow-stale-sub.txt"
printf 'widgets\tCOVERED\twidgets_rls.pg\tthis text was never written\tselftest stale\ndefaultall\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_STALE_SUB"
rc=0; out="$(run_guard "$ALLOW_STALE_SUB")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(D) stale substring is caught (guard fires)"; else bad "(D) stale substring NOT caught (false-negative!)"; fi

# (E) COVERED but the file has no SET ROLE line → guard FAILS.
cat > "$WORK/tests/no_role.pg" <<'PG'
BEGIN;
SELECT lives_ok($$ SELECT widget_create(1) $$, 'widget_create succeeds as setjoin_app');
ROLLBACK;
PG
ALLOW_NO_ROLE="$WORK/allow-no-role.txt"
printf 'widgets\tCOVERED\tno_role.pg\twidget_create succeeds as setjoin_app\tselftest no-role\ndefaultall\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_NO_ROLE"
rc=0; out="$(run_guard "$ALLOW_NO_ROLE")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(E) missing SET ROLE line is caught (not a real non-owner proof)"; else bad "(E) missing SET ROLE line NOT caught (false-negative!)"; fi

# (F) COVERED but the named file doesn't exist → guard FAILS.
ALLOW_MISSING_FILE="$WORK/allow-missing-file.txt"
printf 'widgets\tCOVERED\tdoes_not_exist.pg\tanything\tselftest missing file\ndefaultall\tPENDING\t-\t-\tselftest gap\n' > "$ALLOW_MISSING_FILE"
rc=0; out="$(run_guard "$ALLOW_MISSING_FILE")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(F) missing test file is caught"; else bad "(F) missing test file NOT caught (false-negative!)"; fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-rls-allow selftest FAILED ($fail/$((pass+fail)) checks failed) — the guard does not behave as specified."
  exit 1
fi
echo "check-rls-allow selftest: all $pass checks passed (guard fires + is precise)."
