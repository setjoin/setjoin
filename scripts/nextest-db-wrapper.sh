#!/usr/bin/env bash
# nextest wrapper script (#550): runs ONE test process against its own database.
#
#   $LANE_ADMIN_DSN     superuser DSN of the CI cluster (any database, usually `postgres`)
#   $LANE_TEMPLATE_DB   schema-loaded template database to clone
#   $LANE_BASE_DB       database name the inherited DSNs point at; every env value that
#                       names it (`.../LANE_BASE_DB` before `?` or end) is re-pointed at
#                       the clone, so tests keep reading TEST_DB_DSN / DB_DSN / DB_APP_DSN /
#                       DB_DIRECT_DSN / DB_WORKER_DSN unchanged
#   $LANE_CLONE_STRATEGY file_copy (default; about 0.2 s for the 44 MB template) or wal_log
#   $LANE_DB_PREFIX     clone name prefix (default gofree_e2e_lane_); load-test-schema.sh
#                       and the test fixtures accept `*_e2e_*` names
#
# The clone is dropped (WITH FORCE) when the test ends, pass or fail. Roles are
# cluster-wide in Postgres, so they are provisioned once with the template and a test
# that creates its own role must use a unique name (all of them already do).
# Usage (by nextest): nextest-db-wrapper.sh <test-binary> <args...>
set -u
: "${LANE_ADMIN_DSN:?LANE_ADMIN_DSN is required}" "${LANE_TEMPLATE_DB:?LANE_TEMPLATE_DB is required}" "${LANE_BASE_DB:?LANE_BASE_DB is required}"
prefix="${LANE_DB_PREFIX:-gofree_e2e_lane_}"
key="${NEXTEST_BINARY_ID:-?}|${NEXTEST_TEST_NAME:-?}|${NEXTEST_RUN_ID:-?}|${NEXTEST_ATTEMPT:-1}"
# Run by `cargo test` as a target runner (the adequacy gate): no nextest ids, so one clone per
# invocation.
[ -n "${NEXTEST_RUN_ID:-}" ] || key="$key|$$|$(date +%s%N)"
db="${prefix}$(printf '%s' "$key" | sha256sum | cut -c1-24)"

admin() { psql "$LANE_ADMIN_DSN" -X -q -v ON_ERROR_STOP=1 -c "$1" >/dev/null; }

strategy="${LANE_CLONE_STRATEGY:-file_copy}"
created=0 err=
for attempt in 1 2 3 4 5; do
  if err="$(admin "CREATE DATABASE \"$db\" TEMPLATE \"$LANE_TEMPLATE_DB\" STRATEGY $strategy" 2>&1)"; then
    created=1
    break
  fi
  sleep "0.$attempt"
done
if [ "$created" != 1 ]; then
  echo "LANE-DB-FAIL: could not clone $LANE_TEMPLATE_DB for $key: $err" >&2
  exit 97
fi

cleanup() {
  local try
  for try in 1 2 3 4 5; do
    admin "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" 2>/dev/null && return 0
    sleep "0.$try"
  done
  echo "LANE-DB-LEAK: $db" >&2
  [ -n "${LANE_LEAK_LOG:-}" ] && echo "$db $key" >>"$LANE_LEAK_LOG"
}
trap cleanup EXIT
trap 'exit 143' TERM INT HUP

# Re-point every inherited connection string at the clone.
for name in $(compgen -e); do
  value="${!name}"
  case "$value" in
    *"/$LANE_BASE_DB" | *"/$LANE_BASE_DB?"* | *"/$LANE_BASE_DB#"*)
      export "$name=$(printf '%s' "$value" | sed -e "s#/$LANE_BASE_DB\$#/$db#" -e "s#/$LANE_BASE_DB\\([?\#]\\)#/$db\\1#")"
      ;;
  esac
done
export LANE_TEST_DB="$db" PGDATABASE="$db"

"$@"
