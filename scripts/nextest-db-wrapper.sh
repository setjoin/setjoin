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
#   $LANE_COVERAGE_MAP  optional TSV `<binary_id>\t<test_name>\t<eid1,eid2,...>` from
#                       lane-shard-plan.py for single-pass coverage capture
#   $LANE_COVERAGE_PROF_DIR optional directory for per-entry sparse `.profdata` + `.cases`
#   $LANE_LLVM_PROFDATA optional path to `llvm-profdata` (resolved automatically if unset)
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

prof_tmp=""
lock_dir_held=""
cleanup() {
  if [ -n "$lock_dir_held" ]; then
    rmdir "$lock_dir_held" 2>/dev/null || true
    lock_dir_held=""
  fi
  if [ -n "$prof_tmp" ]; then
    rm -rf "$prof_tmp" 2>/dev/null || true
    prof_tmp=""
  fi
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

if [ -z "${LANE_COVERAGE_MAP:-}" ] || [ -z "${LANE_COVERAGE_PROF_DIR:-}" ]; then
  "$@"
  exit $?
fi

if [ ! -f "$LANE_COVERAGE_MAP" ]; then
  echo "LANE-COVERAGE-FAIL: LANE_COVERAGE_MAP does not exist: $LANE_COVERAGE_MAP" >&2
  exit 98
fi

entry_ids=""
if [ -n "${NEXTEST_BINARY_ID:-}" ] && [ -n "${NEXTEST_TEST_NAME:-}" ]; then
  entry_ids="$(awk -F'\t' -v b="$NEXTEST_BINARY_ID" -v t="$NEXTEST_TEST_NAME" '$1 == b && $2 == t { print $3; exit }' "$LANE_COVERAGE_MAP")"
fi

if [ -z "$entry_ids" ]; then
  rc=0
  LLVM_PROFILE_FILE=/dev/null "$@" || rc=$?
  # Clean any stray default_*.profraw written in $PWD by child processes that called .env_clear().
  rm -f default_*.profraw 2>/dev/null || true
  exit "$rc"
fi

resolve_profdata() {
  if [ -n "${LANE_LLVM_PROFDATA:-}" ] && [ -x "$LANE_LLVM_PROFDATA" ]; then
    printf '%s\n' "$LANE_LLVM_PROFDATA"
    return 0
  fi
  local sysroot host cand
  sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  host="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
  cand="$sysroot/lib/rustlib/$host/bin/llvm-profdata"
  if [ -n "$sysroot" ] && [ -n "$host" ] && [ -x "$cand" ]; then
    printf '%s\n' "$cand"
    return 0
  fi
  command -v llvm-profdata 2>/dev/null || return 1
}

merge_into_entry() {
  local profdata_bin="$1" eid="$2" case_prof="$3"
  local target="$LANE_COVERAGE_PROF_DIR/$eid.profdata"
  local tmp_out="$LANE_COVERAGE_PROF_DIR/$eid.profdata.tmp.$$"
  local cases_file="$LANE_COVERAGE_PROF_DIR/$eid.cases"
  if [ -f "$target" ]; then
    "$profdata_bin" merge -sparse -o "$tmp_out" "$target" "$case_prof" || return 1
  else
    cp "$case_prof" "$tmp_out" || return 1
  fi
  mv -f "$tmp_out" "$target" || return 1
  printf '%s\t%s\n' "$NEXTEST_BINARY_ID" "$NEXTEST_TEST_NAME" >>"$cases_file" || return 1
}

prof_tmp="$(mktemp -d)"
rc=0
LLVM_PROFILE_FILE="$prof_tmp/%p-%m.profraw" "$@" || rc=$?
rm -f default_*.profraw 2>/dev/null || true

if [ "$rc" -eq 0 ]; then
  raws=()
  for f in "$prof_tmp"/*.profraw; do
    [ -s "$f" ] && raws+=("$f")
  done
  if [ "${#raws[@]}" -eq 0 ]; then
    echo "LANE-COVERAGE-FAIL: coverage case ${NEXTEST_BINARY_ID}::${NEXTEST_TEST_NAME} produced no non-empty .profraw" >&2
    rm -rf "$prof_tmp"
    prof_tmp=""
    exit 98
  fi
  profdata_bin="$(resolve_profdata)" || {
    echo "LANE-COVERAGE-FAIL: llvm-profdata not found for ${NEXTEST_BINARY_ID}::${NEXTEST_TEST_NAME}" >&2
    rm -rf "$prof_tmp"
    prof_tmp=""
    exit 98
  }
  if ! "$profdata_bin" merge -sparse -o "$prof_tmp/case.profdata" "${raws[@]}"; then
    echo "LANE-COVERAGE-FAIL: llvm-profdata merge failed for ${NEXTEST_BINARY_ID}::${NEXTEST_TEST_NAME}" >&2
    rm -rf "$prof_tmp"
    prof_tmp=""
    exit 98
  fi
  rm -f "${raws[@]}"

  mkdir -p "$LANE_COVERAGE_PROF_DIR"
  IFS=',' read -r -a eids <<<"$entry_ids"
  for eid in "${eids[@]}"; do
    [ -n "$eid" ] || continue
    if command -v flock >/dev/null 2>&1; then
      (
        flock -x 9 && merge_into_entry "$profdata_bin" "$eid" "$prof_tmp/case.profdata"
      ) 9>"$LANE_COVERAGE_PROF_DIR/$eid.lock" || {
        echo "LANE-COVERAGE-FAIL: failed merging profile into entry $eid for ${NEXTEST_BINARY_ID}::${NEXTEST_TEST_NAME}" >&2
        rm -rf "$prof_tmp"
        prof_tmp=""
        exit 98
      }
    else
      ld="$LANE_COVERAGE_PROF_DIR/$eid.lockdir"
      while ! mkdir "$ld" 2>/dev/null; do
        sleep 0.05
      done
      lock_dir_held="$ld"
      merge_rc=0
      merge_into_entry "$profdata_bin" "$eid" "$prof_tmp/case.profdata" || merge_rc=$?
      rmdir "$ld" 2>/dev/null || true
      lock_dir_held=""
      if [ "$merge_rc" -ne 0 ]; then
        echo "LANE-COVERAGE-FAIL: failed merging profile into entry $eid for ${NEXTEST_BINARY_ID}::${NEXTEST_TEST_NAME}" >&2
        rm -rf "$prof_tmp"
        prof_tmp=""
        exit 98
      fi
    fi
  done
fi

rm -rf "$prof_tmp"
prof_tmp=""
exit "$rc"
