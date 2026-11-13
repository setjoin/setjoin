#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-app-notify.sh — lexical guard that keeps app_notify the SINGLE choke
# point for pg_notify in the reducer layer.
#
# app_notify(channel, payload) (reducers/app_notify.sql) wraps pg_notify so the
# reactive push is capturable by the test-only side-channel (tests/_fixtures.sql:
# _test_notify_log, gated by the app.capture_notify GUC). A reducer that calls
# pg_notify DIRECTLY escapes that capture — its push becomes un-assertable, and
# the "did this reducer push?" question stops being answerable in one place. That
# is the exact silent-stop-pushing bug class (stale state token after a mutation)
# the seam exists to make un-maskable.
#
# This guard FAILS CI if `pg_notify(` appears (in a LIVE, comment-stripped line)
# in ANY reducers/*.sql EXCEPT app_notify.sql — the one file that legitimately
# calls the built-in pg_notify, because it IS the wrapper. Comment-only mentions
# of pg_notify (the prose in headers describing the seam) are stripped first and
# never fire.
#
# Mirrors the check-account-scope.sh genre: comment-stripped, low-false-positive,
# self-tested by check-app-notify-selftest.sh ahead of the real run.
#
# Usage: scripts/check-app-notify.sh   (exit 0 = clean, 1 = a stray pg_notify).
# Wired into scripts/test.sh (self-test first).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

# REDUCERS_DIR may be overridden (used by the guard's own self-test); defaults to
# the repo's reducer tree.
REDUCERS="${REDUCERS_DIR:-$ROOT/mailserver/sql/reducers}"

# The ONE file allowed to call the built-in pg_notify — it is the wrapper.
WRAPPER_FILE="app_notify.sql"

fail=0
report() { echo "  $1"; fail=1; }

echo "==> app_notify single-choke-point guard (pg_notify only inside app_notify.sql)"

for f in "$REDUCERS"/*.sql; do
  base="$(basename "$f")"
  [ "$base" = "$WRAPPER_FILE" ] && continue
  # Strip line comments (-- …) then look for a live pg_notify( call.
  # Case-insensitive on the keyword so PG_NOTIFY( cannot defeat the guard.
  out=$(awk '
    { line = $0; sub(/--.*/, "", line)
      if (tolower(line) ~ /pg_notify[ \t]*\(/) print NR "\t" $0 }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r lineno text; do
    [ -z "$lineno" ] && continue
    report "[N] $base:$lineno  raw pg_notify( in a reducer (bypasses the app_notify capture seam):"
    report "      ${text#"${text%%[![:space:]]*}"}"
    report "      → call PERFORM app_notify(channel, payload) instead. Only app_notify.sql may call the built-in pg_notify."
  done <<< "$out"
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "app_notify single-choke-point guard FAILED."
  echo "See reducers/app_notify.sql and retired-docs:superpowers/plans/archive/2026-06-18-reducer-pg-notify-testable.md."
  exit 1
fi

echo "    app_notify guard: clean (pg_notify lives only in app_notify.sql)."
