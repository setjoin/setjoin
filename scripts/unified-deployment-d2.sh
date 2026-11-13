#!/usr/bin/env bash
# D2: production-shaped Native-RLS + full disaster-recovery rehearsal across
# the retained A/B stacks created by unified-deployment-readiness.sh.
#
# B is an explicitly disposable restore target. This script refuses any
# unprefixed resource and records only sanitized evidence below test-results/.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="${1:-prepare}"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
EVIDENCE_DIR=""
A=""
B=""
A_IP=""
BUCKET="setjoin-dr"
ACCESS_KEY="minioadmin"
SECRET_KEY="minioadmin12345"
FIXTURE_BODY="setjoin-d2-dr-fixture-v1"
FIXTURE_HASH="ec1f04b22a1fa323ffd3697f0be13524fdb959bce3befa016a0340816fabcbf7"

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

validate() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac
  A="${RUN_PREFIX}-a"
  B="${RUN_PREFIX}-b"
  subnet_base="${TEST_SUBNET%.0/24}"
  A_IP="${subnet_base}.11"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d2"
  install -d -m 0700 "$EVIDENCE_DIR"

  for name in "$A" "${A}-minio" "$B" "${B}-minio"; do
    case "$name" in ("${RUN_PREFIX}-"*) ;; (*) die "unscoped resource name: $name" ;; esac
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: $name"
  done
  grep -q '^=== RESULT: PASS ===$' \
    "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/provision-a.log" ||
    die "environment A has no exact provision PASS evidence"
  grep -q '^=== RESULT: PASS ===$' \
    "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/provision-b.log" ||
    die "environment B has no exact provision PASS evidence"
}

mc() {
  local target="$1"
  shift
  docker run --rm --network "container:$target" \
    --entrypoint /bin/sh minio/mc \
    -c 'mc alias set local http://127.0.0.1:9000 "$1" "$2" >/dev/null &&
        shift 2 && exec mc "$@"' sh "$ACCESS_KEY" "$SECRET_KEY" "$@"
}

ensure_bucket() {
  local target="$1" bucket="$2"
  mc "$target" mb --ignore-existing "local/$bucket" >/dev/null
}

configure_a_backup() {
  say "Configure isolated backup store on A"
  ensure_bucket "$A" mailblobs
  ensure_bucket "$A" "$BUCKET"
  printf '%s' "$FIXTURE_BODY" |
    docker run --rm -i --network "container:$A" \
      --entrypoint /bin/sh minio/mc \
      -c 'mc alias set local http://127.0.0.1:9000 "$1" "$2" >/dev/null &&
          mc pipe "local/mailblobs/blobs/$3" >/dev/null' \
      sh "$ACCESS_KEY" "$SECRET_KEY" "$FIXTURE_HASH"

  docker exec -i "$A" bash -s <<INNER
set -Eeuo pipefail
cfg=/etc/setjoin/config.env
[ -e /etc/setjoin/config.env.pre-d2 ] ||
  cp -a "\$cfg" /etc/setjoin/config.env.pre-d2
tmp=\$(mktemp)
grep -Ev '^(BACKUP_(PROVIDER|ENDPOINT|REGION|BUCKET|ACCESS_KEY|SECRET_KEY)|S3_(ACCESS_KEY|SECRET_KEY))=' "\$cfg" >"\$tmp"
cat >>"\$tmp" <<'EOF'
S3_ACCESS_KEY=$ACCESS_KEY
S3_SECRET_KEY=$SECRET_KEY
BACKUP_PROVIDER=s3
BACKUP_ENDPOINT=http://127.0.0.1:9000
BACKUP_REGION=us-east-1
BACKUP_BUCKET=$BUCKET
BACKUP_ACCESS_KEY=$ACCESS_KEY
BACKUP_SECRET_KEY=$SECRET_KEY
EOF
chmod 0600 "\$tmp"
mv "\$tmp" "\$cfg"
systemctl restart setjoin
for _ in \$(seq 1 30); do
  curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null && exit 0
  sleep 1
done
journalctl -u setjoin --no-pager -n 120 >&2
exit 1
INNER
}

seed_a() {
  say "Seed two-mailbox and cross-program DR fixtures on A"
  docker exec -i "$A" bash -s <<INNER
set -Eeuo pipefail
source /etc/setjoin/config.env
psql "\$DB_DIRECT_OWNER_DSN" -v ON_ERROR_STOP=1 <<'SQL'
DO \$\$
DECLARE
  v_fixture_hash text := '$FIXTURE_HASH';
  v_admin_id bigint;
  v_user jsonb;
  v_user_id bigint;
  v_mailbox_id bigint;
  v_message_id bigint;
  v_received_at timestamptz;
BEGIN
  SELECT id INTO v_admin_id FROM users WHERE lower(email)='admin@example.com';
  IF v_admin_id IS NULL THEN
    RAISE EXCEPTION 'D2 fixture requires installer admin';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users WHERE lower(email)='dr-user@example.com') THEN
    v_user := provision_account(
      p_email=>'dr-user@example.com',
      p_display_name=>'DR Fixture User',
      p_password_hash=>crypt('D2-Fixture-Only-Passw0rd!', gen_salt('bf')),
      p_sync_source=>'local',
      p_create_only=>true
    );
  END IF;
  SELECT id INTO v_user_id FROM users WHERE lower(email)='dr-user@example.com';
  SELECT id INTO v_mailbox_id FROM mailboxes
    WHERE user_id=v_user_id AND is_primary;

  IF NOT EXISTS (SELECT 1 FROM messages WHERE message_id='<setjoin-d2-dr-fixture@org-a.test>') THEN
    v_message_id := deliver(
      'inline:setjoin-d2-dr-fixture',
      '<setjoin-d2-dr-fixture@org-a.test>',
      'external@example.net',
      'External Fixture',
      'dr-user@example.com',
      '["dr-user@example.com"]'::jsonb,
      '[]'::jsonb,
      '[]'::jsonb,
      'Setjoin D2 DR fixture',
      NULL,
      NULL,
      'Stable D2 disaster recovery content',
      NULL,
      35,
      TRUE,
      now(),
      'pass',
      'pass',
      'pass',
      0.0,
      '{}'::jsonb
    );
    SELECT received_at INTO v_received_at FROM messages WHERE id=v_message_id;
    INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count)
      VALUES (v_fixture_hash,'blobs/' || v_fixture_hash,24,'text/plain',0)
      ON CONFLICT (sha256) DO NOTHING;
    INSERT INTO message_attachments(
      message_id,received_at,blob_sha256,filename,content_type,disposition,size_bytes
    ) VALUES (
      v_message_id,v_received_at,v_fixture_hash,'d2-fixture.txt','text/plain','attachment',24
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users WHERE lower(email)='dr-guest@external.test') THEN
    PERFORM provision_account(
      p_email=>'dr-guest@external.test',
      p_display_name=>'DR Guest Fixture',
      p_sync_source=>'guest',
      p_guest=>true,
      p_invited_by=>v_admin_id,
      p_guest_expires_at=>now()+interval '30 days',
      p_create_only=>true
    );
  END IF;

  INSERT INTO identity_sources(
    source_key,display_name,kind,capabilities,state,created_by,updated_by
  ) VALUES (
    'd2-dr-fixture','D2 DR Fixture','ldap',
    '{"provision":true,"authenticate":false}'::jsonb,'draft',v_admin_id,v_admin_id
  ) ON CONFLICT (source_key) DO NOTHING;

  INSERT INTO federation_peers(peer_domain,last_seq,last_acked_seq)
    VALUES ('dr-peer.invalid',0,0)
    ON CONFLICT (peer_domain) DO NOTHING;
  INSERT INTO federation_allowlist(peer_domain,peer_anchor,scope,enabled)
    VALUES (
      'dr-peer.invalid',
      '-----BEGIN CERTIFICATE-----\nD2-DISABLED-DR-FIXTURE\n-----END CERTIFICATE-----',
      'dm',
      false
    ) ON CONFLICT (peer_domain) DO NOTHING;

  PERFORM audit_write(
    v_admin_id,'deployment_readiness.d2_fixture','deployment_fixture',NULL,
    NULL,
    jsonb_build_object(
      'memberUserId',v_user_id,
      'mailboxId',v_mailbox_id,
      'blobSha256',v_fixture_hash
    ),
    NULL,'D2 disaster recovery fixture','core'
  );
END
\$\$;
SQL
INNER
}

role_and_rls_proof() {
  say "Native-RLS role, policy, and owner proof"
  docker exec -i "$A" bash -s >"$EVIDENCE_DIR/native-rls.txt" <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
printf 'operator_current_user='
psql "$DB_DIRECT_OWNER_DSN" -Atc 'SELECT current_user'
printf 'app_current_user='
psql "$DB_DSN" -Atc 'SELECT current_user'
psql "$DB_DIRECT_OWNER_DSN" -v ON_ERROR_STOP=1 \
  -f /root/setjoin/mailserver/sql/tests/rls_role_model.pg
read -r admin_mb dr_mb < <(
  psql "$DB_DIRECT_OWNER_DSN" -AtF ' ' -c \
    "SELECT min(id) FILTER (WHERE email='admin@example.com'),
            min(id) FILTER (WHERE email='dr-user@example.com')
       FROM mailboxes")
owner_other="$(psql "$DB_DIRECT_OWNER_DSN" -Atc \
  "SELECT count(*) FROM messages WHERE mailbox_id=$dr_mb")"
app_other="$(psql "$DB_DSN" -Atc \
  "BEGIN;
   SELECT set_config('app.current_mailbox_id','$admin_mb',true);
   SELECT count(*) FROM messages WHERE mailbox_id=$dr_mb;
   ROLLBACK;" | sed -n '3p')"
printf 'owner_other_mailbox_messages=%s\napp_other_mailbox_messages=%s\n' \
  "$owner_other" "$app_other"
[ "$owner_other" -ge 1 ]
[ "$app_other" = "0" ]

psql "$DB_DIRECT_OWNER_DSN" -v ON_ERROR_STOP=1 -c \
  'SELECT create_monthly_partitions(1)' >/dev/null
psql "$DB_DIRECT_OWNER_DSN" -Atc \
  "SELECT parent.relname || ':' || child.relname || ':' || owner.rolname
     FROM pg_inherits i
     JOIN pg_class child ON child.oid=i.inhrelid
     JOIN pg_class parent ON parent.oid=i.inhparent
     JOIN pg_roles owner ON owner.oid=child.relowner
    WHERE parent.relname IN ('messages','message_tags')
    ORDER BY 1"
INNER
}

enqueue_blob_backup() {
  say "Run manifest/config/blob backup worker on A"
  docker exec -i "$A" bash -s >"$EVIDENCE_DIR/blob-backup.txt" <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
run_id="$(psql "$DB_DIRECT_OWNER_DSN" -Atc \
  "INSERT INTO backup_runs(status) VALUES ('pending') RETURNING id" | head -1)"
printf 'backup_run_id=%s\n' "$run_id"
for _ in $(seq 1 120); do
  status="$(psql "$DB_DIRECT_OWNER_DSN" -Atc \
    "SELECT status FROM backup_runs WHERE id=$run_id")"
  case "$status" in
    completed)
      psql "$DB_DIRECT_OWNER_DSN" -AtF '|' -c \
        "SELECT status,blob_count,blobs_copied,blobs_skipped,
                manifest_timestamp
           FROM backup_runs WHERE id=$run_id"
      exit 0
      ;;
    failed)
      psql "$DB_DIRECT_OWNER_DSN" -Atc \
        "SELECT coalesce(error_log::text,'') FROM backup_runs WHERE id=$run_id" >&2
      exit 1
      ;;
  esac
  sleep 1
done
echo "backup worker timed out" >&2
exit 1
INNER
  mc "$A" stat "local/$BUCKET/backup-manifest.json" \
    >"$EVIDENCE_DIR/backup-manifest-stat.txt"
  mc "$A" stat "local/$BUCKET/blobs/$FIXTURE_HASH" \
    >"$EVIDENCE_DIR/backup-blob-stat.txt"
}

backup_database() {
  say "Run owner-first mailctl backup-db on A"
  docker exec -i "$A" bash -s >"$EVIDENCE_DIR/backup-db.txt" 2>&1 <<INNER
set -Eeuo pipefail
cd /root/setjoin
set -a
source /etc/setjoin/config.env
set +a
printf 'resolved_operator_user='
psql "\$DB_DIRECT_OWNER_DSN" -Atc 'SELECT current_user'
/root/setjoin/mailctl/mailctl backup-db \
  --provider s3 \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 \
  --bucket '$BUCKET' \
  --access-key '$ACCESS_KEY' \
  --secret-key '$SECRET_KEY'
INNER
  mc "$A" stat "local/$BUCKET/db-dump.dump" \
    >"$EVIDENCE_DIR/db-dump-stat.txt"

  say "Prove explicit app DSN cannot produce the operator dump"
  set +e
  docker exec -i "$A" bash -s >"$EVIDENCE_DIR/backup-db-app-expected-denial.txt" 2>&1 <<INNER
set -Eeuo pipefail
cd /root/setjoin
set -a
source /etc/setjoin/config.env
set +a
/root/setjoin/mailctl/mailctl backup-db \
  --dsn "\$DB_DSN" \
  --provider s3 \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 \
  --bucket '${BUCKET}-app-denial' \
  --access-key '$ACCESS_KEY' \
  --secret-key '$SECRET_KEY'
INNER
  app_rc=$?
  set -e
  printf 'expected_app_backup_exit=%s\n' "$app_rc" \
    >>"$EVIDENCE_DIR/backup-db-app-expected-denial.txt"
  [ "$app_rc" -ne 0 ] ||
    die "explicit setjoin_app backup unexpectedly succeeded"
}

snapshot() {
  local target="$1" out="$2"
  docker exec -i "$target" bash -s >"$out" <<INNER
set -Eeuo pipefail
source /etc/setjoin/config.env
psql "\$DB_DIRECT_OWNER_DSN" -At -v fixture_hash='$FIXTURE_HASH' <<'SQL'
SELECT jsonb_pretty(jsonb_build_object(
  'schemaVersion',(SELECT max(version) FROM schema_migrations),
  'users',(SELECT count(*) FROM users),
  'mailboxes',(SELECT count(*) FROM mailboxes),
  'messages',(SELECT count(*) FROM messages),
  'messageTags',(SELECT count(*) FROM message_tags),
  'blobs',(SELECT count(*) FROM blobs),
  'guests',(SELECT count(*) FROM guest_accounts),
  'identitySources',(SELECT count(*) FROM identity_sources),
  'federationPeers',(SELECT count(*) FROM federation_peers),
  'fixtureUserId',(SELECT id FROM users WHERE email='dr-user@example.com'),
  'fixtureMailboxId',(SELECT id FROM mailboxes WHERE email='dr-user@example.com'),
  'fixtureMessageId',(SELECT id FROM messages
                        WHERE message_id='<setjoin-d2-dr-fixture@org-a.test>'),
  'fixtureBlob',(SELECT sha256 FROM blobs WHERE sha256=:'fixture_hash'),
  'fixtureAttachment',(SELECT blob_sha256 FROM message_attachments
                        WHERE blob_sha256=:'fixture_hash'),
  'fixtureGuestId',(SELECT id FROM users WHERE email='dr-guest@external.test'),
  'fixtureIdentitySourceId',(SELECT id FROM identity_sources
                              WHERE source_key='d2-dr-fixture'),
  'fixtureFederationPeer',(SELECT peer_domain FROM federation_peers
                            WHERE peer_domain='dr-peer.invalid'),
  'fixtureAuditCount',(SELECT count(*) FROM admin_audit_log
                        WHERE action='deployment_readiness.d2_fixture'),
  'toggles',(SELECT jsonb_object_agg(key,enabled ORDER BY key)
               FROM feature_toggles)
));
SQL
INNER
}

reset_b_to_setup_mode() {
  say "Reset exact disposable B database to setup/no-user mode"
  ensure_bucket "$B" mailblobs
  # Each retry must prove the gateway copied the blob during THIS full restore,
  # not merely observe an object left by an earlier failed pg_restore attempt.
  mc "$B" rm --recursive --force "local/mailblobs" >/dev/null
  docker exec -i "$B" bash -s >"$EVIDENCE_DIR/reset-b.txt" 2>&1 <<'INNER'
set -Eeuo pipefail
cd /root/setjoin
source /etc/setjoin/config.env
systemctl stop setjoin setjoin-auth
su postgres -c 'dropdb --if-exists --force mailserver'
su postgres -c 'createdb -O mail mailserver'

for mig in mailserver/sql/dbschema/V[0-9]*__*.sql; do
  PGPASSWORD='Sm0keDbPassw0rd2026' \
    psql -h 127.0.0.1 -U mail -d mailserver -v ON_ERROR_STOP=1 \
      -f "$mig" >/dev/null
done
DB_NAME=mailserver DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=mail \
  PGPASSWORD='Sm0keDbPassw0rd2026' bash scripts/reload-reducers.sh >/dev/null
PGPASSWORD='Sm0keDbPassw0rd2026' \
  psql -h 127.0.0.1 -U mail -d mailserver -v ON_ERROR_STOP=1 \
    -f scripts/provision-roles.sql >/dev/null

cfg=/etc/setjoin/config.env
tmp="$(mktemp)"
grep -Ev '^S3_(ACCESS_KEY|SECRET_KEY)=' "$cfg" >"$tmp"
cat >>"$tmp" <<'EOF'
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin12345
EOF
chmod 0600 "$tmp"
mv "$tmp" "$cfg"

# Trust only B's disposable local leaf so mailctl can exercise its normal TLS
# client against the exact installer SAN. No production CA is imported.
cp /etc/setjoin/tls/server.pem /usr/local/share/ca-certificates/setjoin-d2-b.crt
update-ca-certificates >/dev/null
grep -qE '(^|[[:space:]])mail[.]example[.]com([[:space:]]|$)' /etc/hosts ||
  printf '127.0.0.1 mail.example.com\n' >>/etc/hosts
systemctl start setjoin-auth setjoin
for _ in $(seq 1 30); do
  curl -sf --max-time 3 https://mail.example.com/ready >/dev/null && break
  sleep 1
done
curl -sf --max-time 3 https://mail.example.com/ready >/dev/null
test "$(psql "$DB_DIRECT_OWNER_DSN" -Atc 'SELECT count(*) FROM users')" = 0
printf 'setup_mode_users=0\nschema_version='
psql "$DB_DIRECT_OWNER_DSN" -Atc 'SELECT max(version) FROM schema_migrations'
INNER
}

restore_a_to_b() {
  say "Dry-run and full restore A into setup-mode B"
  docker exec -i "$B" bash -s >"$EVIDENCE_DIR/restore-b.txt" 2>&1 <<INNER
set -Eeuo pipefail
cd /root/setjoin
set -a
source /etc/setjoin/config.env
set +a
common=(
  --provider s3
  --endpoint http://$A_IP:9000
  --region us-east-1
  --bucket '$BUCKET'
  --access-key '$ACCESS_KEY'
  --secret-key '$SECRET_KEY'
  --type full
)
/root/setjoin/mailctl/mailctl restore "\${common[@]}" --dry-run
/root/setjoin/mailctl/mailctl restore "\${common[@]}" --yes
INNER
}

verify_restore() {
  say "Compare normalized source and restored database state"
  snapshot "$A" "$EVIDENCE_DIR/snapshot-a.json"
  snapshot "$B" "$EVIDENCE_DIR/snapshot-b.json"
  diff -u "$EVIDENCE_DIR/snapshot-a.json" "$EVIDENCE_DIR/snapshot-b.json" \
    >"$EVIDENCE_DIR/snapshot.diff" ||
    die "restored database snapshot differs from A"
  grep -Eq '^  Blobs restored:[[:space:]]+1$' "$EVIDENCE_DIR/restore-b.txt" ||
    die "full restore did not copy the expected blob into clean B storage"

  mc "$B" stat "local/mailblobs/blobs/$FIXTURE_HASH" \
    >"$EVIDENCE_DIR/restored-blob-stat.txt"
  printf '%s  -\n' "$FIXTURE_HASH" >"$EVIDENCE_DIR/restored-blob.sha256"
  mc "$B" cat "local/mailblobs/blobs/$FIXTURE_HASH" |
    sha256sum -c "$EVIDENCE_DIR/restored-blob.sha256" \
    >"$EVIDENCE_DIR/restored-blob-integrity.txt"

  docker exec -i "$B" bash -s >"$EVIDENCE_DIR/restored-ownership.txt" <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -AtF '|' <<'SQL'
SELECT 'app_owned_force_rls_tables',count(*)
  FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
 WHERE r.rolname='setjoin_app' AND c.relrowsecurity AND c.relforcerowsecurity;
SELECT 'app_super_bypass',rolsuper,rolbypassrls
  FROM pg_roles WHERE rolname='setjoin_app';
SELECT 'worker_super_bypass',rolsuper,rolbypassrls
  FROM pg_roles WHERE rolname='setjoin_worker';
SELECT 'app_messages_select',has_table_privilege('setjoin_app','public.messages','SELECT');
SELECT 'worker_messages_select',has_table_privilege('setjoin_worker','public.messages','SELECT');
SELECT 'app_message_tags_insert',has_table_privilege('setjoin_app','public.message_tags','INSERT');
SQL
INNER
  grep -Fxq 'app_owned_force_rls_tables|0' "$EVIDENCE_DIR/restored-ownership.txt"
  grep -Fxq 'app_super_bypass|f|f' "$EVIDENCE_DIR/restored-ownership.txt"
  grep -Fxq 'worker_super_bypass|f|t' "$EVIDENCE_DIR/restored-ownership.txt"
  grep -Fxq 'app_messages_select|t' "$EVIDENCE_DIR/restored-ownership.txt"
  grep -Fxq 'worker_messages_select|t' "$EVIDENCE_DIR/restored-ownership.txt"
  grep -Fxq 'app_message_tags_insert|t' "$EVIDENCE_DIR/restored-ownership.txt"

  # The dump contains encrypted connector/config/signing-key ciphertext, not
  # the offline master secrets. Restore only the required disposable source
  # secrets over stdin; never print them and never copy source TLS/endpoints.
  for secret_name in DB_ENCRYPTION_KEY JWT_SECRET; do
    secret_line="$(docker exec "$A" sed -n "/^${secret_name}=/p" /etc/setjoin/config.env)"
    case "$secret_line" in ("${secret_name}="?*) ;; (*) die "A $secret_name is missing" ;; esac
    printf '%s\n' "$secret_line" |
      docker exec -i "$B" bash -c '
      set -Eeuo pipefail
      IFS= read -r replacement
      key=${replacement%%=*}
      case "$key" in (DB_ENCRYPTION_KEY|JWT_SECRET) ;; (*) exit 1 ;; esac
      cfg=/etc/setjoin/config.env
      tmp=$(mktemp)
      awk -v key="$key" -v replacement="$replacement" \
        '\''index($0,key "=")==1 { print replacement; found=1; next }
           { print }
           END { if (!found) print replacement }'\'' "$cfg" >"$tmp"
      chmod 0600 "$tmp"
      mv "$tmp" "$cfg"
    '
  done

  docker exec -i "$B" bash -s >"$EVIDENCE_DIR/restored-runtime.txt" <<'INNER'
set -Eeuo pipefail
started_at="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
systemctl restart setjoin-auth setjoin
for _ in $(seq 1 30); do
  curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null && break
  sleep 1
done
curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null
login_resp="$(curl -sk --max-time 10 -X POST https://127.0.0.1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"Sm0ke-Test-Passw0rd!1"}')"
printf '%s' "$login_resp" |
  grep -Eq '"access_token":"|"status":"mfa_enrollment_required"|"mfa_required":true'
sleep 6
if journalctl -u setjoin -u setjoin-auth --since "$started_at" --no-pager |
   grep -Eq 'permission denied for (function|materialized view)|decryption failed'; then
  echo "restored runtime emitted a worker-ownership or secret-decryption error" >&2
  exit 1
fi
printf 'restored_services=PASS\nrestored_admin_login=PASS\n'
printf 'restored_worker_ownership_errors=0\nrestored_decryption_errors=0\n'
INNER
}

rehearse_rollback() {
  say "Rehearse permissive DSN rollback and return to constrained shape on A"
  docker exec -i "$A" bash -s >"$EVIDENCE_DIR/rls-rollback.txt" 2>&1 <<'INNER'
set -Eeuo pipefail
cfg=/etc/setjoin/config.env
orig=/etc/setjoin/config.env.pre-d2-rls-rollback
cp -a "$cfg" "$orig"
restore() {
  cp -a "$orig" "$cfg"
  systemctl restart setjoin
  for _ in $(seq 1 30); do
    curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null && return 0
    sleep 1
  done
  return 1
}
trap restore EXIT
source "$cfg"
owner="$DB_DIRECT_OWNER_DSN"
tmp="$(mktemp)"
awk -v owner="$owner" '
  /^DB_DSN=/ { print "DB_DSN=" owner; next }
  /^DB_DIRECT_DSN=/ { print "DB_DIRECT_DSN=" owner; next }
  /^DB_WORKER_DSN=/ { print "DB_WORKER_DSN=" owner; next }
  { print }
' "$cfg" >"$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$cfg"
systemctl restart setjoin
for _ in $(seq 1 30); do
  curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null && break
  sleep 1
done
curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null
printf 'permissive_restart=PASS\n'
restore
trap - EXIT
source "$cfg"
printf 'constrained_app_user='
psql "$DB_DSN" -Atc 'SELECT current_user'
curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null
printf 'constrained_restart=PASS\n'
INNER
}

finalize() {
  {
    printf 'run_prefix=%s\nsource=A\ntarget=B\n' "$RUN_PREFIX"
    printf 'fixture_blob_sha256=%s\n' "$FIXTURE_HASH"
    printf 'native_rls=PASS\nfull_restore=PASS\nrollback=PASS\n'
    printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$EVIDENCE_DIR/result.txt"
  say "D2 PASS"
}

case "$ACTION" in
  prepare)
    validate
    configure_a_backup
    seed_a
    role_and_rls_proof
    enqueue_blob_backup
    backup_database
    snapshot "$A" "$EVIDENCE_DIR/snapshot-a-before-restore.json"
    reset_b_to_setup_mode
    restore_a_to_b
    verify_restore
    rehearse_rollback
    finalize
    ;;
  restore-current)
    # U3 reuses the already-proven D2 restore path after its controller has
    # atomically copied the exact recovery-set database artifact to the
    # legacy restore adapter's fixed db-dump.dump key. No new path is accepted
    # by mailctl, and this action never creates another source backup.
    validate
    snapshot "$A" "$EVIDENCE_DIR/snapshot-a-before-restore.json"
    reset_b_to_setup_mode
    restore_a_to_b
    verify_restore
    ;;
  *) die "usage: $0 [prepare|restore-current]" ;;
esac
