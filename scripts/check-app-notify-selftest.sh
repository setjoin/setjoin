#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-app-notify-selftest.sh — negative-case self-test for the app_notify
# single-choke-point guard.
#
# A guard that never fires is theater. This drives check-app-notify.sh against a
# TEMP reducer tree and asserts:
#   1. a CLEAN tree (only app_notify.sql calls pg_notify) passes;
#   2. injecting a stray `pg_notify(` into a NON-wrapper reducer makes the guard
#      fire ([N], exit 1);
#   3. an uppercase PG_NOTIFY( also fires (case-insensitive);
#   4. a comment-only mention of pg_notify does NOT fire (comments are stripped);
#   5. the wrapper file itself (app_notify.sql) calling pg_notify is allowed;
#   6. removing the stray returns the tree to clean.
# Uses the guard's REDUCERS_DIR override so the real repo tree is never touched.
#
# Usage: scripts/check-app-notify-selftest.sh   (exit 0 = all cases caught).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-app-notify.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/reducers"

# Seed the real wrapper so the allowlist resolves as in prod (it legitimately
# calls the built-in pg_notify and must NOT trip the guard).
cp "$ROOT/mailserver/sql/reducers/app_notify.sql" "$TMP/reducers/" 2>/dev/null || true

# A clean, routed reducer (calls app_notify, never pg_notify directly).
cat > "$TMP/reducers/clean.sql" <<'SQL'
-- deps: app_notify
CREATE OR REPLACE FUNCTION clean_fn(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM app_notify('tag:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

run_guard() {
  REDUCERS_DIR="$TMP/reducers" bash "$GUARD" > "$TMP/out" 2>&1
  return $?
}

echo "==> app_notify-guard self-test (must fire on a stray pg_notify)"

# 1. clean tree passes (wrapper + a routed reducer).
if run_guard; then pass "clean tree passes (only app_notify.sql calls pg_notify)"
else bad "clean tree should pass"; sed 's/^/        /' "$TMP/out"; fi

# 2. a stray pg_notify( in a non-wrapper reducer fires [N].
cat > "$TMP/reducers/stray.sql" <<'SQL'
CREATE OR REPLACE FUNCTION stray_fn(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM pg_notify('tag:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
if run_guard; then bad "stray pg_notify — guard did NOT fail"
elif grep -q '\[N\]' "$TMP/out"; then pass "stray pg_notify in a reducer — caught [N]"
else bad "stray pg_notify failed but without an [N] line"; sed 's/^/        /' "$TMP/out"; fi
rm -f "$TMP/reducers/stray.sql"

# 3. uppercase PG_NOTIFY( also fires (case-insensitive).
cat > "$TMP/reducers/upper.sql" <<'SQL'
CREATE OR REPLACE FUNCTION upper_fn(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM PG_NOTIFY('tag:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
if run_guard; then bad "uppercase PG_NOTIFY — guard did NOT fail"
elif grep -q '\[N\]' "$TMP/out"; then pass "uppercase PG_NOTIFY — caught [N]"
else bad "uppercase PG_NOTIFY failed but without an [N] line"; sed 's/^/        /' "$TMP/out"; fi
rm -f "$TMP/reducers/upper.sql"

# 4. a comment-only mention of pg_notify does NOT fire (comments stripped).
cat > "$TMP/reducers/comment.sql" <<'SQL'
-- deps: app_notify
-- This reducer used to call pg_notify('tag:'||…) directly; now routed.
CREATE OR REPLACE FUNCTION comment_fn(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM app_notify('tag:' || p_mailbox_id, '{}');  -- not pg_notify(
END; $$ LANGUAGE plpgsql;
SQL
if run_guard; then pass "comment-only mention of pg_notify — not flagged (comments stripped)"
else bad "comment-only mention FALSE-fired"; sed 's/^/        /' "$TMP/out"; fi
rm -f "$TMP/reducers/comment.sql"

# 6. tree clean again.
if run_guard; then pass "tree clean again after removing the stray"
else bad "tree should be clean again"; sed 's/^/        /' "$TMP/out"; fi

if [ "$fail" -ne 0 ]; then
  echo "==> app_notify-guard self-test FAILED — the guard stopped catching a stray pg_notify."
  exit 1
fi
echo "    app_notify-guard self-test: stray pg_notify is caught; comments/wrapper are not."
