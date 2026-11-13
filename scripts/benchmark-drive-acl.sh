#!/usr/bin/env bash
# Deterministic local A9 performance gate for the Drive ACL authority module.
# The fixture and samples run in one transaction and always roll back.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-mailserver_test}"

case "$DB_NAME" in
  *_test|drive_acl_bench*) ;;
  *)
    echo "refusing to benchmark a database without a test-only name: $DB_NAME" >&2
    exit 2
    ;;
esac

if [ "${RESET_DB:-0}" = "1" ]; then
  DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" DB_NAME="$DB_NAME" \
    bash "$ROOT/scripts/load-test-schema.sh"
fi

exec psql -X -v ON_ERROR_STOP=1 \
  -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -f "$ROOT/scripts/benchmark-drive-acl.sql"
