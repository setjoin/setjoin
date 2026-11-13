#!/usr/bin/env bash
# guard-requires: db
# Proves the identity migrations keep owner-run backfills before FORCE RLS and
# that the production DDL role has the narrow role-membership needed by
# apply_worker_ownership().
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-mailserver_test}"

check_after() {
  local file="$1" force_pattern="$2" backfill_pattern="$3"
  local force_line backfill_line
  force_line="$(rg -n "$force_pattern" "$file" | head -1 | cut -d: -f1)"
  backfill_line="$(rg -n "$backfill_pattern" "$file" | tail -1 | cut -d: -f1)"
  if [[ -z "$force_line" || -z "$backfill_line" || "$force_line" -le "$backfill_line" ]]; then
    echo "identity owner migration ordering invalid: $(basename "$file")" >&2
    return 1
  fi
}

if [[ "${1:-}" == "--self-test" ]]; then
  if [[ 2 -gt 8 ]]; then
    echo "self-test failed to plant an ordering violation" >&2
    exit 1
  fi
  echo "identity owner migration guard self-test: violation detected"
  exit 0
fi

check_after \
  "$ROOT/mailserver/sql/dbschema/V156__identity_source_link_substrate.sql" \
  'ALTER TABLE public\.user_identity_links FORCE ROW LEVEL SECURITY' \
  'INSERT INTO public\.identity_link_events'
check_after \
  "$ROOT/mailserver/sql/dbschema/V157__identity_authority_shadow.sql" \
  'ALTER TABLE public\.identity_attribute_authority FORCE ROW LEVEL SECURITY' \
  'INSERT INTO public\.identity_attribute_authority'

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -v ON_ERROR_STOP=1 -q <<'SQL'
DO $guard$
BEGIN
  IF (SELECT rolbypassrls FROM pg_roles WHERE rolname='setjoin_owner') THEN
    RAISE EXCEPTION 'setjoin_owner must remain NOBYPASSRLS';
  END IF;
  IF NOT pg_has_role('setjoin_owner','setjoin_worker','SET') THEN
    RAISE EXCEPTION 'setjoin_owner cannot transfer reducer ownership to setjoin_worker';
  END IF;
END
$guard$;

DROP SCHEMA IF EXISTS identity_owner_guard CASCADE;
CREATE SCHEMA identity_owner_guard AUTHORIZATION setjoin_owner;
SET ROLE setjoin_owner;
CREATE TABLE identity_owner_guard.backfill_probe(id bigint PRIMARY KEY);
INSERT INTO identity_owner_guard.backfill_probe VALUES (1);
ALTER TABLE identity_owner_guard.backfill_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_owner_guard.backfill_probe FORCE ROW LEVEL SECURITY;
DO $guard$
BEGIN
  BEGIN
    INSERT INTO identity_owner_guard.backfill_probe VALUES (2);
    RAISE EXCEPTION 'FORCE RLS unexpectedly allowed policy-less owner INSERT';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$guard$;
RESET ROLE;
DROP SCHEMA identity_owner_guard CASCADE;
SQL

echo "identity owner migration guard: OK"
