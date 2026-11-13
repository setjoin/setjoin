#!/usr/bin/env bash
# Disposable first-success gate for Drive node ACL authority.
#
# Usage:
#   RUN_PREFIX=driveacl-<unique> bash scripts/drive-acl-smoke.sh all
#   RUN_PREFIX=driveacl-<unique> bash scripts/drive-acl-smoke.sh self-test
#   RUN_PREFIX=driveacl-<unique> bash scripts/drive-acl-smoke.sh seed|grant|verify|revoke|cleanup
#
# The script creates one scratch PostgreSQL database containing synthetic data.
# It never starts a service or changes a production database. Feature flags are
# enabled only inside that scratch database and the default `all` flow drops it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMAND="${1:-all}"
RUN_PREFIX="${RUN_PREFIX:-driveacl-$(date -u +%Y%m%d%H%M%S)-$$}"
KEEP_ON_FAIL="${KEEP_ON_FAIL:-0}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"

case "$RUN_PREFIX" in
  (*[!a-z0-9-]*|'') echo "RUN_PREFIX must contain only lowercase a-z, 0-9, or hyphen" >&2; exit 2 ;;
esac
[ "${#RUN_PREFIX}" -le 32 ] || { echo "RUN_PREFIX must be at most 32 characters" >&2; exit 2; }

DB_SUFFIX="${RUN_PREFIX//-/_}"
DB_NAME="drive_acl_smoke_${DB_SUFFIX}"
ARTIFACT_DIR="$ROOT/test-results/drive-acl-smoke/$RUN_PREFIX"
RESULT_FILE="$ARTIFACT_DIR/result.txt"
PSQL=(psql -X -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME")
STARTED_AT="$(date +%s)"
CURRENT_PHASE="preflight"

mkdir -p "$ARTIFACT_DIR"

record() {
  printf '%s\n' "$*" | tee -a "$RESULT_FILE"
}

phase() {
  CURRENT_PHASE="$1"
  PHASE_STARTED="$(date +%s)"
  record "phase=$CURRENT_PHASE state=start"
}

phase_done() {
  record "phase=$CURRENT_PHASE state=pass duration_seconds=$(($(date +%s)-PHASE_STARTED))"
}

database_exists() {
  psql -X -tA -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
    -v db_name="$DB_NAME" -c "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:'db_name')" \
    2>/dev/null | grep -qx t
}

cleanup_database() {
  phase cleanup
  psql -X -q -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
    -v db_name="$DB_NAME" \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=:'db_name' AND pid<>pg_backend_pid()" \
    >/dev/null 2>&1 || true
  dropdb --if-exists -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME"
  phase_done
}

on_exit() {
  status=$?
  if [ "$status" -ne 0 ]; then
    record "phase=$CURRENT_PHASE state=fail exit_code=$status"
    record "retry=RUN_PREFIX=$RUN_PREFIX bash scripts/drive-acl-smoke.sh $COMMAND"
    if [ "$KEEP_ON_FAIL" != "1" ] && database_exists; then
      cleanup_database
    fi
  fi
  record "result=$([ "$status" -eq 0 ] && printf PASS || printf FAIL) duration_seconds=$(($(date +%s)-STARTED_AT))"
}
trap on_exit EXIT

seed() {
  phase seed
  DB_NAME="$DB_NAME" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
    bash "$ROOT/scripts/load-test-schema.sh" >"$ARTIFACT_DIR/schema-load.log" 2>&1
  "${PSQL[@]}" -q -v smoke_prefix="$RUN_PREFIX" <<'SQL'
CREATE TABLE drive_acl_smoke_state(key text PRIMARY KEY,value bigint NOT NULL);
SELECT mk_account(:'smoke_prefix' || '-owner') AS owner_mailbox \gset
SELECT mk_account(:'smoke_prefix' || '-reader') AS reader_mailbox \gset
SELECT user_id AS owner_user FROM mailboxes WHERE id=:owner_mailbox \gset
SELECT user_id AS reader_user FROM mailboxes WHERE id=:reader_mailbox \gset
SELECT drive_space_create(:owner_user,'Drive ACL synthetic smoke','regular') AS space_id \gset
SELECT drive_node_create(:owner_user,:space_id,NULL,'folder','Synthetic root') AS root_id \gset
SELECT drive_node_create(:owner_user,:space_id,:root_id,'file','Synthetic file') AS file_id \gset
UPDATE drive_spaces SET acl_mode='acl' WHERE id=:space_id;
UPDATE feature_toggles SET enabled=true
 WHERE key IN ('feature.drive_node_acl_reads','feature.drive_node_acl_writes');
INSERT INTO drive_acl_smoke_state(key,value) VALUES
  ('owner_user',:owner_user),('reader_user',:reader_user),('space_id',:space_id),
  ('root_id',:root_id),('file_id',:file_id);
SQL
  phase_done
}

grant() {
  phase grant
  "${PSQL[@]}" -q <<'SQL'
DO $do$
DECLARE
  v_owner bigint; v_reader bigint; v_root bigint; v_space bigint;
  v_grant bigint;
BEGIN
  SELECT value INTO v_owner FROM drive_acl_smoke_state WHERE key='owner_user';
  SELECT value INTO v_reader FROM drive_acl_smoke_state WHERE key='reader_user';
  SELECT value INTO v_root FROM drive_acl_smoke_state WHERE key='root_id';
  SELECT value INTO v_space FROM drive_acl_smoke_state WHERE key='space_id';
  v_grant := (drive_acl_grant(
    v_owner,v_root,'user',v_reader,'viewer',NULL,'subtree',NULL,NULL,NULL,
    'synthetic smoke grant',drive_acl_epoch(v_space),'drive-acl-smoke-idempotency'
  )->>'grantId')::bigint;
  INSERT INTO drive_acl_smoke_state(key,value) VALUES('grant_id',v_grant)
    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
END
$do$;
SQL
  phase_done
}

verify_sql() {
  "${PSQL[@]}" -q <<'SQL'
DO $do$
DECLARE
  v_reader bigint; v_file bigint; v_space bigint; v_grant bigint;
  v_state text; v_download boolean; v_manage boolean;
BEGIN
  SELECT value INTO v_reader FROM drive_acl_smoke_state WHERE key='reader_user';
  SELECT value INTO v_file FROM drive_acl_smoke_state WHERE key='file_id';
  SELECT value INTO v_space FROM drive_acl_smoke_state WHERE key='space_id';
  SELECT value INTO v_grant FROM drive_acl_smoke_state WHERE key='grant_id';
  SELECT state INTO v_state FROM drive_acl_grants WHERE id=v_grant;
  v_download := drive_runtime_has_node_capability(v_reader,v_file,'download');
  v_manage := drive_runtime_has_node_capability(v_reader,v_file,'manage_acl');
  IF v_state='active' AND NOT v_download THEN
    RAISE EXCEPTION 'active Viewer grant did not authorize download';
  ELSIF v_state<>'active' AND v_download THEN
    RAISE EXCEPTION 'terminal grant still authorized download';
  END IF;
  IF v_manage THEN
    RAISE EXCEPTION 'Viewer grant escalated to manage_acl';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM drive_access_invalidations WHERE space_id=v_space) THEN
    RAISE EXCEPTION 'ACL mutation emitted no invalidation';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM drive_audit_log
                WHERE space_id=v_space AND action IN ('acl.grant','acl.revoke')) THEN
    RAISE EXCEPTION 'ACL mutation emitted no audit evidence';
  END IF;
END
$do$;
SQL
}

verify() {
  phase verify
  verify_sql
  phase_done
}

revoke() {
  phase revoke
  "${PSQL[@]}" -q <<'SQL'
DO $do$
DECLARE
  v_owner bigint; v_space bigint; v_grant bigint; v_state text;
BEGIN
  SELECT value INTO v_owner FROM drive_acl_smoke_state WHERE key='owner_user';
  SELECT value INTO v_space FROM drive_acl_smoke_state WHERE key='space_id';
  SELECT value INTO v_grant FROM drive_acl_smoke_state WHERE key='grant_id';
  SELECT state INTO v_state FROM drive_acl_grants WHERE id=v_grant;
  IF v_state='active' THEN
    PERFORM drive_acl_revoke(v_owner,v_grant,drive_acl_epoch(v_space),'synthetic smoke revoke');
  ELSIF v_state<>'revoked' THEN
    RAISE EXCEPTION 'unexpected grant state %',v_state;
  END IF;
END
$do$;
SQL
  phase_done
}

self_test() {
  seed
  grant
  phase plant-mismatch
  "${PSQL[@]}" -q -c "UPDATE drive_acl_grants SET preset='custom',capabilities=ARRAY['traverse']::text[] WHERE id=(SELECT value FROM drive_acl_smoke_state WHERE key='grant_id')"
  phase_done
  if verify_sql >/dev/null 2>&1; then
    echo "self-test failed: planted authorization mismatch was accepted" >&2
    return 1
  fi
  record "self_test=PASS planted_authorization_mismatch=rejected"
  cleanup_database
}

case "$COMMAND" in
  seed) seed ;;
  grant) grant ;;
  verify) verify ;;
  revoke) revoke ;;
  cleanup) cleanup_database ;;
  self-test) self_test ;;
  all)
    seed
    grant
    verify
    revoke
    verify
    cleanup_database
    ;;
  *) echo "usage: $0 {all|self-test|seed|grant|verify|revoke|cleanup}" >&2; exit 2 ;;
esac
