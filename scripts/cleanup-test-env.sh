#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# Cleanup test environment — kills all services, drops test DB, removes files
#
# Usage:
#   bash scripts/cleanup-test-env.sh              # full cleanup
#   bash scripts/cleanup-test-env.sh --keep-db    # keep the test database
#   bash scripts/cleanup-test-env.sh --keep-dir   # keep everything on disk, just stop services
#
# TEST_DIR lives on a shared /tmp, so its state is treated as hostile data,
# never code: .pids is parsed with a strict KEY=<digits> grammar after an
# owner/mode/type check instead of being sourced, so a planted file cannot
# execute shell as the invoking account; kills and rm -rf are confined to
# paths this environment owns. SETJOIN_TEST_ENV_DIR overrides TEST_DIR for
# sandboxed runs (tests).
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

TEST_DIR="${SETJOIN_TEST_ENV_DIR:-/tmp/setjoin-test}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="mailserver_test"
PG_OPTS="-h $DB_HOST -p $DB_PORT -U $DB_USER"

KEEP_DB=false
KEEP_DIR=false

for arg in "$@"; do
  case "$arg" in
    --keep-db) KEEP_DB=true ;;
    --keep-dir) KEEP_DIR=true ;;
  esac
done

echo "==> Cleaning up test environment..."

# ── 1. Kill services ──────────────────────────────────────────────────────
PIDS_FILE="$TEST_DIR/.pids"
pids_usable=false
if [ -L "$PIDS_FILE" ]; then
  echo "  WARNING: refusing symlinked $PIDS_FILE (possible /tmp plant); falling back to kill-by-name" >&2
elif [ -f "$PIDS_FILE" ]; then
  # find exits 0 regardless of matches, so test for matched output itself.
  if [ -n "$(find "$PIDS_FILE" -maxdepth 0 -type f -user "$(id -u)" ! -perm -0020 ! -perm -0002 2>/dev/null)" ]; then
    pids_usable=true
  else
    echo "  WARNING: refusing $PIDS_FILE (not owned by uid $(id -u), or group/world-writable); falling back to kill-by-name" >&2
  fi
fi

unset GW_PID AUTH_PID WEED_FILER_PID WEED_MASTER_PID
if $pids_usable; then
  grammar_ok=true
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      GW_PID | AUTH_PID | WEED_FILER_PID | WEED_MASTER_PID) ;;
      *)
        grammar_ok=false
        break
        ;;
    esac
    if [ "$value" = "$line" ] || [ -z "$value" ]; then
      grammar_ok=false
      break
    fi
    case "$value" in
      *[!0-9]*)
        grammar_ok=false
        break
        ;;
    esac
    printf -v "$key" '%s' "$value"
  done <"$PIDS_FILE"
  if ! $grammar_ok; then
    echo "  WARNING: refusing $PIDS_FILE content (expected KEY=<pid> lines only); falling back to kill-by-name" >&2
    pids_usable=false
    unset GW_PID AUTH_PID WEED_FILER_PID WEED_MASTER_PID
  fi
fi

killed_any=false
for pid_var in GW_PID AUTH_PID WEED_FILER_PID WEED_MASTER_PID; do
  pid="${!pid_var:-}"
  [ -n "$pid" ] || continue
  # A stale recorded PID may have been recycled by an unrelated process;
  # only signal processes that still look like this environment's binaries.
  cmd="$(ps -o command= -p "$pid" 2>/dev/null || true)"
  if [ -z "$cmd" ]; then
    continue
  fi
  case "$cmd" in
    *authserverd* | *mailserverd* | *"weed master"* | *"weed filer"*)
      if kill "$pid" 2>/dev/null; then
        echo "  Killed $pid_var ($pid)"
        killed_any=true
      fi
      ;;
    *)
      echo "  Skipped $pid_var ($pid): no longer a test binary ($cmd)" >&2
      ;;
  esac
done
if ! $killed_any && ! $pids_usable; then
  # Fallback: kill by name, confined to this environment's binary paths so
  # unrelated instances on a shared host are never signalled.
  pkill -f "$TEST_DIR/authserverd" 2>/dev/null && echo "  Killed authserverd" || true
  pkill -f "$TEST_DIR/mailserverd" 2>/dev/null && echo "  Killed mailserverd" || true
  pkill -f "$TEST_DIR/seaweedfs/master" 2>/dev/null && echo "  Killed weed master" || true
  pkill -f "$TEST_DIR/seaweedfs/filer" 2>/dev/null && echo "  Killed weed filer" || true
fi

sleep 1

# ── 2. Drop test database ────────────────────────────────────────────────
if ! $KEEP_DB; then
  echo "  Dropping test database: $DB_NAME"
  # Terminate any lingering connections first
  psql $PG_OPTS -d postgres -c "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = '$DB_NAME' AND pid <> pg_backend_pid();" 2>/dev/null || true
  psql $PG_OPTS -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);" 2>/dev/null || true
  echo "  Database dropped."
else
  echo "  Database kept: $DB_NAME"
fi

# ── 3. Remove test directory ─────────────────────────────────────────────
# rm -rf is confined to a real directory owned by the invoking account; a
# symlinked or foreign-owned TEST_DIR is reported and left untouched.
if ! $KEEP_DIR; then
  if [ -L "$TEST_DIR" ]; then
    echo "  WARNING: $TEST_DIR is a symlink — not removing" >&2
  elif [ -d "$TEST_DIR" ] && [ -n "$(find "$TEST_DIR" -maxdepth 0 -type d -user "$(id -u)" 2>/dev/null)" ]; then
    rm -rf "$TEST_DIR"
    echo "  Removed $TEST_DIR"
  elif [ -e "$TEST_DIR" ]; then
    echo "  WARNING: $TEST_DIR is not owned by uid $(id -u) — not removing" >&2
  else
    echo "  Nothing to remove at $TEST_DIR"
  fi
else
  echo "  Directory kept: $TEST_DIR"
fi

echo "==> Cleanup complete."
