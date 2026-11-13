#!/usr/bin/env bash
# U3/U4: production-shaped recovery-set + transactional-updater rehearsal on
# retained A/B stacks created by unified-deployment-readiness.sh.
#
# This controller enables execution only inside the exact prefix-scoped,
# disposable A stack. It creates and verifies one portable recovery set,
# restores that same set into isolated B, drives the real Admin API intent
# journey with fresh AAL2, proves one successful cohort switch and one fixed
# automatic rollback, and returns all updater feature gates to OFF.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="${1:-prepare}"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="Sm0ke-Test-Passw0rd!1"
PROBE_EMAIL="dr-user@example.com"
PROBE_PASSWORD="D2-Fixture-Only-Passw0rd!"
BUCKET="setjoin-dr"
ACCESS_KEY="minioadmin"
SECRET_KEY="minioadmin12345"
A=""
B=""
A_IP=""
EVIDENCE_DIR=""
TMP_DIR=""
TERMINAL_OFF_DONE=0
SUCCESS_RELEASE_SUFFIX="u4-success-v3"
ROLLBACK_RELEASE_SUFFIX="u4-rollback-v3"

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

cleanup_tmp() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    find "$TMP_DIR" -type f -delete
    rmdir "$TMP_DIR"
  fi
  if [ "$TERMINAL_OFF_DONE" != "1" ] && [ -n "$A" ] &&
     docker container inspect "$A" >/dev/null 2>&1; then
    printf '\nNOTE: execution cleanup was not reached; the disposable stack is preserved for diagnosis.\n' >&2
  fi
}
trap cleanup_tmp EXIT

validate_prefix() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  [ "${#RUN_PREFIX}" -le 32 ] || die "RUN_PREFIX must be at most 32 characters"
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac
  local base="${TEST_SUBNET%.0/24}"
  A="${RUN_PREFIX}-a"
  B="${RUN_PREFIX}-b"
  A_IP="${base}.11"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/updater-u3-u4"
}

validate_runtime() {
  validate_prefix
  command -v docker >/dev/null 2>&1 || die "docker is required"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
  for name in "$A" "${A}-minio" "$B" "${B}-minio"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: $name"
  done
  grep -q '^=== RESULT: PASS ===$' \
    "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/provision-a.log" ||
    die "environment A has no exact provision PASS evidence"
  grep -q '^=== RESULT: PASS ===$' \
    "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/provision-b.log" ||
    die "environment B has no exact provision PASS evidence"
  install -d -m 0700 "$EVIDENCE_DIR"
  TMP_DIR="$(mktemp -d)"
}

psql_a() {
  local sql="$1"
  docker exec -i "$A" bash -s -- "$sql" <<'INNER'
set -Eeuo pipefail
sql="$1"
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAc "$sql"
INNER
}

api_call() {
  local method="$1" path="$2" body="$3" bearer="$4" out="$5"
  local reason="${6:-}" idempotency="${7:-}"
  local args=(
    -ksS --max-time 30 --resolve "mail.example.com:443:$A_IP"
    -o "$out" -w '%{http_code}' -X "$method"
    "https://mail.example.com$path" -H 'Content-Type: application/json'
  )
  [ -n "$bearer" ] && args+=(-H "Authorization: Bearer $bearer")
  [ -n "$reason" ] && args+=(-H "X-Audit-Reason: $reason")
  [ -n "$idempotency" ] && args+=(-H "Idempotency-Key: $idempotency")
  [ -n "$body" ] && args+=(--data-binary "$body")
  curl "${args[@]}"
}

expect_status() {
  local got="$1" want="$2" label="$3" body="${4:-}"
  if [ "$got" != "$want" ]; then
    [ -z "$body" ] || sed -n '1,20p' "$body" >&2
    die "$label returned HTTP $got, want $want"
  fi
}

fresh_aal2_token() {
  local response setup confirm status mfa_token uri secret code token
  response="$(mktemp "$TMP_DIR/login.XXXXXX")"
  setup="$(mktemp "$TMP_DIR/setup.XXXXXX")"
  confirm="$(mktemp "$TMP_DIR/confirm.XXXXXX")"
  psql_a "
    UPDATE users SET totp_enabled=false,totp_enabled_at=NULL,totp_secret_enc=NULL
     WHERE lower(email)=lower('$ADMIN_EMAIL');
    DELETE FROM oauth_tokens
     WHERE user_id=(SELECT id FROM users WHERE lower(email)=lower('$ADMIN_EMAIL'));
  " >/dev/null
  status="$(api_call POST /auth/login \
    "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "" "$response")"
  expect_status "$status" 403 admin_enrollment_required "$response"
  [ "$(jq -r '.status // empty' "$response")" = "mfa_enrollment_required" ] ||
    die "admin password verification did not enter mandatory enrollment"
  mfa_token="$(jq -r '.mfa_token // empty' "$response")"
  [ -n "$mfa_token" ] || die "admin enrollment omitted its pending token"
  status="$(api_call POST /auth/totp/enroll/setup \
    "$(jq -nc --arg token "$mfa_token" '{mfa_token:$token}')" "" "$setup")"
  expect_status "$status" 200 admin_totp_setup "$setup"
  uri="$(jq -r '.provisioning_uri // empty' "$setup")"
  [ -n "$uri" ] || die "TOTP setup omitted provisioning URI"
  secret="$(sh "$ROOT/scripts/rehearsal-totp.sh" secret "$uri")"
  code="$(sh "$ROOT/scripts/rehearsal-totp.sh" code "$secret")"
  status="$(api_call POST /auth/totp/enroll/confirm \
    "$(jq -nc --arg token "$mfa_token" --arg code "$code" '{mfa_token:$token,code:$code}')" "" "$confirm")"
  expect_status "$status" 200 admin_totp_confirm "$confirm"
  token="$(jq -r '.access_token // empty' "$confirm")"
  [ -n "$token" ] || die "TOTP confirmation omitted its access token"
  printf '%s' "$token"
}

ensure_d2() {
  if ! grep -q '^native_rls=PASS$' \
      "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d2/result.txt" 2>/dev/null; then
    say "Run prerequisite D2 backup/restore rehearsal"
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-d2.sh" prepare
  fi
}

configure_recovery_credentials() {
  say "Configure private recovery/probe credentials, backup worker, and local trust"
  docker exec -i "$A" bash -s <<INNER
set -Eeuo pipefail
source /etc/setjoin/config.env
install -d -m 0700 /etc/setjoin-updater
umask 077
printf '%s' '$ACCESS_KEY' >/etc/setjoin-updater/recovery-access-key
printf '%s' '$SECRET_KEY' >/etc/setjoin-updater/recovery-secret-key
printf '%s' "\$DB_ENCRYPTION_KEY" >/etc/setjoin-updater/protected-config.key
printf '%s\n' '{"email":"$PROBE_EMAIL","password":"$PROBE_PASSWORD"}' \
  >/etc/setjoin-updater/probe-credential.json
chmod 0600 /etc/setjoin-updater/recovery-access-key \
  /etc/setjoin-updater/recovery-secret-key \
  /etc/setjoin-updater/recovery-hmac-key \
  /etc/setjoin-updater/protected-config.key \
  /etc/setjoin-updater/probe-credential.json
cp /etc/setjoin/tls/server.pem \
  /usr/local/share/ca-certificates/setjoin-updater-a.crt
update-ca-certificates >/dev/null
grep -qE '(^|[[:space:]])mail[.]example[.]com([[:space:]]|$)' /etc/hosts ||
  printf '127.0.0.1 mail.example.com\n' >>/etc/hosts

# The production installer deliberately does not invent a backup destination.
# This disposable rehearsal owns its prefix-scoped MinIO and therefore must
# configure the gateway backup worker explicitly, even after an idempotent
# installer re-run has restored the normal production config shape.
cfg=/etc/setjoin/config.env
tmp="\$(mktemp)"
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

create_recovery_set() {
  local token="$1" output verify set_id
  output="$(mktemp "$TMP_DIR/recovery-create.XXXXXX")"
  verify="$(mktemp "$TMP_DIR/recovery-verify.XXXXXX")"
  say "Create and independently verify one application recovery set" >&2
  printf '%s' "$token" | docker exec -i "$A" sh -c \
    'umask 077; cat >/run/setjoin-updater-rehearsal.token'
  docker exec -i "$A" bash -s >"$output" <<'INNER'
set -Eeuo pipefail
trap 'rm -f /run/setjoin-updater-rehearsal.token' EXIT
token="$(cat /run/setjoin-updater-rehearsal.token)"
source /etc/setjoin/config.env
MAILCTL_SERVER=https://mail.example.com MAILCTL_TOKEN="$token" \
  /opt/setjoin/current/mailctl backup create --pre-upgrade \
    --dsn "$DB_DIRECT_OWNER_DSN" \
    --provider s3 --endpoint http://127.0.0.1:9000 --region us-east-1 \
    --bucket setjoin-dr \
    --access-key-file /etc/setjoin-updater/recovery-access-key \
    --secret-key-file /etc/setjoin-updater/recovery-secret-key \
    --recovery-key-file /etc/setjoin-updater/recovery-hmac-key \
    --protected-key-file /etc/setjoin-updater/protected-config.key \
    --reason 'create disposable U3 application recovery point' --json
INNER
  set_id="$(jq -r '.recoverySetId // empty' "$output")"
  [[ "$set_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] ||
    die "recovery creation returned no canonical UUID"
  printf '%s' "$token" | docker exec -i "$A" sh -c \
    'umask 077; cat >/run/setjoin-updater-rehearsal.token'
  docker exec -i "$A" bash -s -- "$set_id" >"$verify" <<'INNER'
set -Eeuo pipefail
set_id="$1"
trap 'rm -f /run/setjoin-updater-rehearsal.token' EXIT
token="$(cat /run/setjoin-updater-rehearsal.token)"
MAILCTL_SERVER=https://mail.example.com MAILCTL_TOKEN="$token" \
  /opt/setjoin/current/mailctl backup verify --pre-upgrade \
    --provider s3 --endpoint http://127.0.0.1:9000 --region us-east-1 \
    --bucket setjoin-dr \
    --access-key-file /etc/setjoin-updater/recovery-access-key \
    --secret-key-file /etc/setjoin-updater/recovery-secret-key \
    --recovery-key-file /etc/setjoin-updater/recovery-hmac-key \
    --protected-key-file /etc/setjoin-updater/protected-config.key \
    --reason 'verify disposable U3 application recovery point' --json \
    "$set_id"
INNER
  [ "$(jq -r '.status // empty' "$verify")" = "verified" ] ||
    die "recovery-set verify did not return verified"
  [ "$(jq -r '.recoverySetId // empty' "$verify")" = "$set_id" ] ||
    die "create and verify returned different recovery-set IDs"
  jq '{status,recoverySetId,manifestDigest,fresh,createdAt,expiresAt}' "$verify" \
    >"$EVIDENCE_DIR/recovery-set.json"
  printf '%s' "$set_id"
}

copy_exact_recovery_dump() {
  local set_id="$1" object_key
  object_key="$(docker run --rm --network "container:$A" --entrypoint /bin/sh minio/mc \
    -c 'mc alias set local http://127.0.0.1:9000 "$1" "$2" >/dev/null && mc cat "local/$3/recovery-sets/$4/manifest.json"' \
    sh "$ACCESS_KEY" "$SECRET_KEY" "$BUCKET" "$set_id" | jq -r '.manifest.database.objectKey // empty')"
  case "$object_key" in
    ("recovery-sets/$set_id/database.dump") ;;
    (*) die "recovery envelope selected an unexpected database object" ;;
  esac
  docker run --rm --network "container:$A" --entrypoint /bin/sh minio/mc \
    -c 'mc alias set local http://127.0.0.1:9000 "$1" "$2" >/dev/null && mc cp "local/$3/$4" "local/$3/db-dump.dump" >/dev/null' \
    sh "$ACCESS_KEY" "$SECRET_KEY" "$BUCKET" "$object_key"
  printf 'recovery_set_id=%s\ndatabase_object=%s\nlegacy_adapter_copy=PASS\n' \
    "$set_id" "$object_key" >"$EVIDENCE_DIR/restore-adapter.txt"
}

prove_isolated_restore() {
  local set_id="$1" token="$2" response status proof_id reason
  say "Restore the exact recovery set into isolated B"
  copy_exact_recovery_dump "$set_id"
  RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
    bash "$ROOT/scripts/unified-deployment-d2.sh" restore-current
  response="$(mktemp "$TMP_DIR/restore-proof.XXXXXX")"
  proof_id="$(cat /proc/sys/kernel/random/uuid)"
  reason="record disposable U3 isolated restore proof"
  status="$(api_call POST /api/admin/system/upgrades/restore-proofs \
    "$(jq -nc --arg proof "$proof_id" --arg set "$set_id" --arg target "$B" \
      --arg reason "$reason" '{proofId:$proof,recoverySetId:$set,targetId:$target,checks:{isolated:true,schema:true,login:true,mail:true,blob:true,productionEndpointsAbsent:true},provedAt:(now|todateiso8601),reason:$reason}')" \
    "$token" "$response" "$reason")"
  expect_status "$status" 201 restore_proof_record "$response"
  jq '{proofId,recoverySetId,targetId,provedAt}' "$response" >"$EVIDENCE_DIR/restore-proof.json"
  [ "$(jq -r '.recoverySetId' "$response")" = "$set_id" ] ||
    die "restore proof returned a different recovery-set ID"
}

build_release_fixtures() {
  local schema success rollback
  success="${RUN_PREFIX}-${SUCCESS_RELEASE_SUFFIX}"
  rollback="${RUN_PREFIX}-${ROLLBACK_RELEASE_SUFFIX}"
  schema="$(psql_a 'SELECT max(version) FROM schema_migrations')"
  [[ "$schema" =~ ^[1-9][0-9]*$ ]] || die "invalid current schema version"
  say "Build signed, root-owned disposable release cohorts"
  docker exec -i "$A" bash -s -- "$success" "$rollback" "$schema" <<'INNER'
set -Eeuo pipefail
success="$1"; rollback="$2"; schema="$3"
cd /root/setjoin/mailserver
source_runtime=/run/setjoin-updater-source-runtime
install -d -m 0700 "$source_runtime"
find "$source_runtime" -mindepth 1 -delete
cp -a /opt/setjoin/current/. "$source_runtime/"
chmod -R u+rwX "$source_runtime"
go build -o "$source_runtime/mailserverd" ./cmd/mailserverd
if [ ! -e "/var/lib/setjoin-updater/releases/$success" ] &&
   [ ! -e "/var/lib/setjoin-updater/releases/$rollback" ] &&
   [ ! -e "/run/setjoin-updater-fixture-$success.json" ] &&
   [ ! -e "/run/setjoin-updater-fixture-$rollback.json" ]; then
  go run ./internal/updater/testutil/cmd/release-fixture \
    --source-runtime "$source_runtime" \
    --output-store /var/lib/setjoin-updater/releases \
    --release-id "$success" --version 9.4.0 --schema "$schema" \
    --recovery-guide /root/setjoin/docs/guides/UPGRADE_RECOVERY.md \
    >"/run/setjoin-updater-fixture-$success.json"
  go run ./internal/updater/testutil/cmd/release-fixture \
    --source-runtime "$source_runtime" \
    --output-store /var/lib/setjoin-updater/releases \
    --release-id "$rollback" --version 9.4.1 --schema "$schema" \
    --recovery-guide /root/setjoin/docs/guides/UPGRADE_RECOVERY.md \
    --broken-mailserver >"/run/setjoin-updater-fixture-$rollback.json"
  chmod 0600 "/run/setjoin-updater-fixture-$success.json" "/run/setjoin-updater-fixture-$rollback.json"
else
  for release_id in "$success" "$rollback"; do
    test -d "/var/lib/setjoin-updater/releases/$release_id"
    test -s "/var/lib/setjoin-updater/releases/$release_id/manifest.json"
    test -s "/run/setjoin-updater-fixture-$release_id.json"
    test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("releaseId", ""))' \
      "/run/setjoin-updater-fixture-$release_id.json")" = "$release_id"
  done
fi
chown -R root:root "/var/lib/setjoin-updater/releases/$success" "/var/lib/setjoin-updater/releases/$rollback"
find "/var/lib/setjoin-updater/releases/$success" "/var/lib/setjoin-updater/releases/$rollback" \
  -type d -exec chmod 0755 {} +
find "/var/lib/setjoin-updater/releases/$success" "/var/lib/setjoin-updater/releases/$rollback" \
  -type f -exec chmod go-w {} +
INNER
  for release_id in "$success" "$rollback"; do
    docker exec "$A" cat "/run/setjoin-updater-fixture-$release_id.json"
  done >"$EVIDENCE_DIR/release-fixtures.jsonl"
}

seed_release() {
  local release_id="$1" source_version="$2"
  docker exec -i "$A" bash -s -- "$release_id" "$source_version" <<'INNER'
set -Eeuo pipefail
release_id="$1"; source_version="$2"
source /etc/setjoin/config.env
manifest_path="/var/lib/setjoin-updater/releases/$release_id/manifest.json"
fixture_path="/run/setjoin-updater-fixture-$release_id.json"
mapfile -t fixture_fields < <(python3 - "$fixture_path" "$manifest_path" "$release_id" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    fixture = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    manifest = json.load(source)
if fixture.get("releaseId") != sys.argv[3]:
    raise SystemExit("fixture release identity does not match")
print(fixture.get("manifestDigest", ""))
print(manifest.get("version", ""))
print(manifest.get("schema_to", ""))
print(json.dumps(manifest, separators=(",", ":"), ensure_ascii=False))
PY
)
digest="${fixture_fields[0]:-}"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo 'fixture digest evidence is invalid' >&2; exit 1; }
version="${fixture_fields[1]:-}"
schema="${fixture_fields[2]:-}"
manifest="${fixture_fields[3]:-}"
[[ "$schema" =~ ^[1-9][0-9]*$ ]] || { echo 'fixture schema evidence is invalid' >&2; exit 1; }
test -n "$version" && test -n "$manifest"
actor="$(psql "$DB_DIRECT_OWNER_DSN" -X -Atc "SELECT id FROM users WHERE lower(email)='admin@example.com'")"
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 \
  -v actor="$actor" -v release_id="$release_id" -v version="$version" \
  -v digest="$digest" -v manifest="$manifest" -v source_version="$source_version" \
  -v schema="$schema" <<'SQL'
SELECT upgrade_catalog_record(
  :'actor'::bigint,:'release_id',:'version','community','linux','amd64',
  :'digest',:'manifest'::jsonb,1,ARRAY['setjoin-updater-fixture-v1'],
  statement_timestamp(),statement_timestamp()+interval '1 day',NULL,NULL
);
SELECT upgrade_readiness_record(
  :'actor'::bigint,:'release_id',:'digest','ready',:'source_version',
  :'schema'::bigint,:'schema'::bigint,
  '{"checks":{"manifest":true,"cohort":true,"recovery":true}}'::jsonb,
  0,statement_timestamp()+interval '1 hour'
);
SQL
INNER
}

configure_execution() {
  say "Enable only the disposable updater execution rail"
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
cat >/etc/setjoin-updater/execution.json <<'JSON'
{"version":1,"enabled":true,"installRoot":"/opt/setjoin","recoveryProvider":"s3","recoveryEndpoint":"http://127.0.0.1:9000","recoveryRegion":"us-east-1","recoveryBucket":"setjoin-dr"}
JSON
chmod 0600 /etc/setjoin-updater/execution.json
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -c \
  "UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.transactional_upgrades_catalog','feature.transactional_upgrades_execution')" >/dev/null
systemctl restart setjoin-updater
systemctl is-active --quiet setjoin-updater
INNER
}

request_intent() {
  local release_id="$1" reason="$2" token preview challenge complete request
  local status challenge_key request_key challenge_id elevation_id intent_id
  token="$(fresh_aal2_token)"
  preview="$(mktemp "$TMP_DIR/preview.XXXXXX")"
  challenge="$(mktemp "$TMP_DIR/challenge.XXXXXX")"
  complete="$(mktemp "$TMP_DIR/complete.XXXXXX")"
  request="$(mktemp "$TMP_DIR/request.XXXXXX")"
  status="$(api_call POST /api/admin/system/upgrades/preview \
    "$(jq -nc --arg release "$release_id" --arg reason "$reason" '{releaseId:$release,reason:$reason,scheduleAt:null}')" \
    "$token" "$preview" "$reason")"
  expect_status "$status" 200 upgrade_preview "$preview"
  challenge_key="$(cat /proc/sys/kernel/random/uuid)"
  status="$(api_call POST /api/admin/system/upgrades/challenges \
    "$(jq -nc --arg release "$release_id" --arg reason "$reason" \
      --arg digest "$(jq -r '.previewDigest' "$preview")" --arg key "$challenge_key" \
      '{releaseId:$release,reason:$reason,scheduleAt:null,previewDigest:$digest,idempotencyKey:$key}')" \
    "$token" "$challenge" "$reason" "$challenge_key")"
  expect_status "$status" 200 upgrade_challenge_issue "$challenge"
  challenge_id="$(jq -r '.challengeId // empty' "$challenge")"
  status="$(api_call POST /api/admin/system/upgrades/challenges/complete \
    "$(jq -nc --arg id "$challenge_id" '{challengeId:$id}')" "$token" "$complete")"
  expect_status "$status" 200 upgrade_challenge_complete "$complete"
  elevation_id="$(jq -r '.elevationId // empty' "$complete")"
  request_key="$(cat /proc/sys/kernel/random/uuid)"
  status="$(api_call POST /api/admin/system/upgrades/intents \
    "$(jq -nc --arg release "$release_id" --arg reason "$reason" \
      --arg digest "$(jq -r '.previewDigest' "$preview")" --arg elevation "$elevation_id" \
      --arg key "$request_key" '{releaseId:$release,reason:$reason,scheduleAt:null,previewDigest:$digest,elevationId:$elevation,idempotencyKey:$key}')" \
    "$token" "$request" "$reason" "$request_key")"
  expect_status "$status" 202 upgrade_intent_request "$request"
  intent_id="$(jq -r '.intentId // empty' "$request")"
  [[ "$intent_id" =~ ^[1-9][0-9]*$ ]] || die "upgrade request returned an invalid intent ID"
  jq -s '{preview:.[0],challenge:.[1],completion:.[2],intent:.[3]}' \
    "$preview" "$challenge" "$complete" "$request" \
    >"$EVIDENCE_DIR/intent-$intent_id-api.json"
  printf '%s' "$intent_id"
}

wait_for_state() {
  local intent_id="$1" expected="$2" state=""
  for _ in $(seq 1 180); do
    state="$(psql_a "SELECT state FROM upgrade_intents WHERE id=$intent_id")"
    [ "$state" = "$expected" ] && break
    case "$state" in
      (failed|recovery_required|cancelled|expired)
        docker exec "$A" journalctl -u setjoin-updater --no-pager -n 160 >&2 || true
        die "intent $intent_id reached $state, want $expected"
        ;;
    esac
    sleep 1
  done
  [ "$state" = "$expected" ] || {
    docker exec "$A" journalctl -u setjoin-updater --no-pager -n 160 >&2 || true
    die "intent $intent_id timed out in state $state"
  }
  docker exec -i "$A" bash -s -- "$intent_id" >"$EVIDENCE_DIR/intent-$intent_id-db.json" <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -Atc "SELECT upgrade_intent_read($1::bigint)"
INNER
}

terminal_off() {
  say "Return every transactional-upgrade execution gate to OFF"
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -c \
  "UPDATE feature_toggles SET enabled=false WHERE key IN ('feature.transactional_upgrades_catalog','feature.transactional_upgrades_execution')" >/dev/null
printf '%s\n' '{"version":1,"enabled":false}' >/etc/setjoin-updater/execution.json
chmod 0600 /etc/setjoin-updater/execution.json
systemctl restart setjoin-updater
systemctl is-active --quiet setjoin-updater
test "$(psql "$DB_DIRECT_OWNER_DSN" -X -Atc \
  "SELECT string_agg(key || '=' || enabled::text,',' ORDER BY key) FROM feature_toggles WHERE key IN ('feature.transactional_upgrades_catalog','feature.transactional_upgrades_execution')")" = \
  'feature.transactional_upgrades_catalog=false,feature.transactional_upgrades_execution=false'
INNER
  TERMINAL_OFF_DONE=1
}

run_rehearsal() {
  local token set_id success rollback success_id rollback_id current
  ensure_d2
  configure_recovery_credentials
  token="$(fresh_aal2_token)"
  set_id="$(create_recovery_set "$token")"
  prove_isolated_restore "$set_id" "$token"
  build_release_fixtures
  configure_execution

  success="${RUN_PREFIX}-${SUCCESS_RELEASE_SUFFIX}"
  rollback="${RUN_PREFIX}-${ROLLBACK_RELEASE_SUFFIX}"
  seed_release "$success" "0.0.1"
  success_id="$(request_intent "$success" 'install disposable U4 success fixture')"
  wait_for_state "$success_id" verified
  current="$(docker exec "$A" basename "$(docker exec "$A" readlink /opt/setjoin/current)")"
  [ "$current" = "$success" ] || die "successful intent did not activate $success"

  seed_release "$rollback" "9.4.0"
  rollback_id="$(request_intent "$rollback" 'exercise disposable U4 automatic rollback')"
  wait_for_state "$rollback_id" rolled_back
  current="$(docker exec "$A" basename "$(docker exec "$A" readlink /opt/setjoin/current)")"
  [ "$current" = "$success" ] || die "automatic rollback did not restore $success"
  docker exec "$A" curl -skf --max-time 5 https://127.0.0.1/ready >/dev/null
  terminal_off
  {
    printf 'run_prefix=%s\nrecovery_set_id=%s\n' "$RUN_PREFIX" "$set_id"
    printf 'isolated_restore=PASS\nsuccess_intent=%s:verified\n' "$success_id"
    printf 'rollback_intent=%s:rolled_back\nterminal_execution_flags=OFF\n' "$rollback_id"
    printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$EVIDENCE_DIR/result.txt"
  say "U3/U4 updater rehearsal PASS"
}

self_test() {
  RUN_PREFIX="updater-self-test"
  TEST_SUBNET="172.30.240.0/24"
  validate_prefix
  [ "$A:$B:$A_IP" = "updater-self-test-a:updater-self-test-b:172.30.240.11" ] ||
    die "prefix derivation self-test failed"
  bash -n "$0"
  printf 'SELF_TEST_PASS prefix=%s\n' "$RUN_PREFIX"
  TERMINAL_OFF_DONE=1
}

case "$ACTION" in
  (prepare) validate_runtime; run_rehearsal ;;
  (status)
    validate_runtime
    docker exec "$A" systemctl --no-pager --full status setjoin-updater || true
    psql_a "SELECT id || ':' || state FROM upgrade_intents ORDER BY id"
    TERMINAL_OFF_DONE=1
    ;;
  (cleanup)
    validate_runtime
    terminal_off
    ;;
  (self-test) self_test ;;
  (*) die "usage: $0 prepare|status|cleanup|self-test" ;;
esac
