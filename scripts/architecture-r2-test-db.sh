#!/usr/bin/env bash
# Shared fail-closed database target validation for Architecture R2 focused
# lanes. Source this file, then call architecture_r2_validate_test_db before a
# command that can create, drop, or mutate PostgreSQL state.

architecture_r2_validate_test_db() {
  [[ "${ARCH_R2_TEST_MODE:-0}" == "1" ]] || return 0

  local db_name="${DB_NAME:-}"
  local db_host="${DB_HOST:-127.0.0.1}"
  if [[ ! "$db_name" =~ ^mailserver_test_arch_r2_[0-9a-f]{12}$ ]]; then
    echo "E_ARCH_R2_UNSAFE_DB problem=invalid_test_database cause=architecture_r2_requires_worktree_unique_name value=${db_name:-unset} fix='derive DB_NAME with scripts/verify-architecture-r2.sh --doctor'" >&2
    return 2
  fi
  case "$db_host" in
    127.0.0.1|localhost|::1|\[::1\]|/*) ;;
    *)
      echo "E_ARCH_R2_UNSAFE_DB problem=remote_database_host cause=focused_lane_is_local_only value=$db_host fix='set DB_HOST to 127.0.0.1 or a local Unix socket'" >&2
      return 2
      ;;
  esac

  local dsn_name dsn
  for dsn_name in DB_DSN TEST_DB_DSN; do
    dsn="${!dsn_name:-}"
    [[ -n "$dsn" ]] || continue
    ARCH_R2_EXPECTED_DB="$db_name" ARCH_R2_DSN="$dsn" ARCH_R2_DSN_NAME="$dsn_name" node <<'NODE'
const expected = process.env.ARCH_R2_EXPECTED_DB;
const input = process.env.ARCH_R2_DSN;
const name = process.env.ARCH_R2_DSN_NAME;
try {
  const url = new URL(input);
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error('DSN must use postgres:// or postgresql://');
  }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const loopback = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
  if (!loopback.has(url.hostname)) {
    throw new Error(`DSN host must be loopback, got ${url.hostname || 'empty'}`);
  }
  if (database !== expected) {
    throw new Error(`DSN database ${database || 'empty'} does not match DB_NAME ${expected}`);
  }
} catch (error) {
  console.error(`E_ARCH_R2_UNSAFE_DB problem=dsn_mismatch cause=${JSON.stringify(error.message)} value=${name} fix='remove the DSN or point it at the derived Architecture R2 database'`);
  process.exit(2);
}
NODE
    local dsn_status=$?
    [[ "$dsn_status" -eq 0 ]] || return "$dsn_status"
  done

  echo "architecture-r2-db: validated local worktree database $db_name"
}
