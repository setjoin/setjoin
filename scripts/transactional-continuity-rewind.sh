#!/usr/bin/env bash
# U8 portable complete-machine rewind rehearsal. The disposable A stack is
# snapshotted at one coherent boundary, advanced through the real continuity
# and receipt APIs, restored as a unit, and then driven through the real
# incident/upload/quarantine/ingest path.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="${1:-prepare}"
RUN_PREFIX="${RUN_PREFIX:-}"
REWIND_ATTEMPT="${REWIND_ATTEMPT:-base}"
REWIND_BASE_IMAGE="${REWIND_BASE_IMAGE:-setjoin-ga-smoke-base:v6}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
ACCESS_KEY="minioadmin"
SECRET_KEY="minioadmin12345"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="Sm0ke-Test-Passw0rd!1"
PROBE_EMAIL="dr-user@example.com"
PROBE_PASSWORD="D2-Fixture-Only-Passw0rd!"

A=""
A_IP=""
DNS_IP=""
NETWORK=""
MINIO=""
SNAPSHOT_IMAGE=""
SNAPSHOT_VOLUME=""
SNAPSHOT_BUILDER=""
EVIDENCE_DIR=""
SNAPSHOT_DIR=""
TMP_DIR=""

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

cleanup_tmp() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    find "$TMP_DIR" -type f -delete
    rmdir "$TMP_DIR"
  fi
}
trap cleanup_tmp EXIT

validate_prefix() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  [ "${#RUN_PREFIX}" -le 32 ] || die "RUN_PREFIX must be at most 32 characters"
  case "$REWIND_ATTEMPT" in
    (*[!a-z0-9-]*|'') die "REWIND_ATTEMPT must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  [ "${#REWIND_ATTEMPT}" -le 16 ] || die "REWIND_ATTEMPT must be at most 16 characters"
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac
  local base="${TEST_SUBNET%.0/24}"
  A="${RUN_PREFIX}-a"
  MINIO="${A}-minio"
  A_IP="${base}.11"
  DNS_IP="${base}.53"
  NETWORK="${RUN_PREFIX}-net"
  SNAPSHOT_IMAGE="setjoin-rewind-${RUN_PREFIX}-${REWIND_ATTEMPT}-a:baseline"
  SNAPSHOT_VOLUME="${RUN_PREFIX}-${REWIND_ATTEMPT}-rewind-minio-data"
  SNAPSHOT_BUILDER="${RUN_PREFIX}-${REWIND_ATTEMPT}-rewind-builder"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/u5-u8/ubuntu-rewind/$REWIND_ATTEMPT"
  SNAPSHOT_DIR="$EVIDENCE_DIR/private-snapshot"
}

validate_runtime() {
  validate_prefix
  command -v docker >/dev/null 2>&1 || die "docker is required"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
  for name in "$A" "$MINIO"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: $name"
  done
  grep -q '^=== RESULT: PASS ===$' \
    "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/provision-a.log" ||
    die "environment A has no exact provision PASS evidence"
  grep -q '^terminal_execution_flags=OFF$' \
    "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/updater-u3-u4/result.txt" ||
    die "U3/U4 terminal-OFF PASS evidence is required before rewind"
  [ ! -e "$SNAPSHOT_DIR/minio-data" ] ||
    die "private rewind snapshot already exists; inspect or run cleanup before retry"
  docker image inspect "$SNAPSHOT_IMAGE" >/dev/null 2>&1 &&
    die "snapshot image already exists: $SNAPSHOT_IMAGE"
  docker volume inspect "$SNAPSHOT_VOLUME" >/dev/null 2>&1 &&
    die "snapshot volume already exists: $SNAPSHOT_VOLUME"
  docker container inspect "$SNAPSHOT_BUILDER" >/dev/null 2>&1 &&
    die "snapshot builder already exists: $SNAPSHOT_BUILDER"
  docker image inspect "$REWIND_BASE_IMAGE" >/dev/null 2>&1 ||
    die "clean rewind base image is missing: $REWIND_BASE_IMAGE"
  install -d -m 0700 "$SNAPSHOT_DIR"
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
    [ -z "$body" ] || sed -n '1,30p' "$body" >&2
    die "$label returned HTTP $got, want $want"
  fi
}

new_uuid() {
  python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

fresh_token() {
  local email="$1" password="$2" label="$3"
  local response setup confirm status mfa_token uri secret code token
  response="$(mktemp "$TMP_DIR/${label}-login.XXXXXX")"
  setup="$(mktemp "$TMP_DIR/${label}-setup.XXXXXX")"
  confirm="$(mktemp "$TMP_DIR/${label}-confirm.XXXXXX")"
  psql_a "
    UPDATE users SET totp_enabled=false,totp_enabled_at=NULL,totp_secret_enc=NULL
     WHERE lower(email)=lower('$email');
    DELETE FROM oauth_tokens
     WHERE user_id=(SELECT id FROM users WHERE lower(email)=lower('$email'));
  " >/dev/null
  status="$(api_call POST /auth/login \
    "$(jq -nc --arg email "$email" --arg password "$password" '{email:$email,password:$password}')" \
    "" "$response")"
  if [ "$status" = "200" ]; then
    token="$(jq -r '.access_token // empty' "$response")"
    [ -n "$token" ] || die "$label login omitted its access token"
    printf '%s' "$token"
    return
  fi
  expect_status "$status" 403 "${label}_enrollment_required" "$response"
  [ "$(jq -r '.status // empty' "$response")" = "mfa_enrollment_required" ] ||
    die "$label password verification did not enter mandatory enrollment"
  mfa_token="$(jq -r '.mfa_token // empty' "$response")"
  [ -n "$mfa_token" ] || die "$label enrollment omitted its pending token"
  status="$(api_call POST /auth/totp/enroll/setup \
    "$(jq -nc --arg token "$mfa_token" '{mfa_token:$token}')" "" "$setup")"
  expect_status "$status" 200 "${label}_totp_setup" "$setup"
  uri="$(jq -r '.provisioning_uri // empty' "$setup")"
  [ -n "$uri" ] || die "$label TOTP setup omitted provisioning URI"
  secret="$(sh "$ROOT/scripts/rehearsal-totp.sh" secret "$uri")"
  code="$(sh "$ROOT/scripts/rehearsal-totp.sh" code "$secret")"
  status="$(api_call POST /auth/totp/enroll/confirm \
    "$(jq -nc --arg token "$mfa_token" --arg code "$code" '{mfa_token:$token,code:$code}')" \
    "" "$confirm")"
  expect_status "$status" 200 "${label}_totp_confirm" "$confirm"
  token="$(jq -r '.access_token // empty' "$confirm")"
  [ -n "$token" ] || die "$label TOTP confirmation omitted its access token"
  printf '%s' "$token"
}

wait_stack() {
  local ready=0
  for _ in $(seq 1 90); do
    if docker exec "$A" systemctl is-active --quiet postgresql setjoin-auth setjoin &&
       docker exec "$A" curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null 2>&1 &&
       docker run --rm --network "container:$A" --entrypoint /bin/sh minio/mc \
         -c 'mc alias set local http://127.0.0.1:9000 "$1" "$2" >/dev/null && mc ready local >/dev/null' \
         sh "$ACCESS_KEY" "$SECRET_KEY" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  [ "$ready" = "1" ] || {
    docker logs "$MINIO" >&2 || true
    docker exec "$A" systemctl --no-pager --full status postgresql setjoin-auth setjoin >&2 || true
    die "restored A stack did not become ready"
  }
}

set_recovery_flags() {
  local enabled="$1"
  psql_a "
    UPDATE feature_toggles SET enabled=$enabled
     WHERE key IN ('feature.client_recovery_receipts','feature.client_recovery_cache','feature.client_recovery_ingest');
  " >/dev/null
  local want
  if [ "$enabled" = "true" ]; then want="true,true,true"; else want="false,false,false"; fi
  [ "$(psql_a "SELECT string_agg(enabled::text,',' ORDER BY key) FROM feature_toggles WHERE key IN ('feature.client_recovery_receipts','feature.client_recovery_cache','feature.client_recovery_ingest')")" = "$want" ] ||
    die "client recovery flags failed to reach $enabled"
  docker exec "$A" systemctl restart setjoin
  for _ in $(seq 1 30); do
    if docker exec "$A" curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "gateway did not reload client recovery flags"
}

prepare_scanner() {
  say "Prepare real fail-closed ClamAV scanner before the snapshot"
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! dpkg-query -W -f='${Status}' clamav-daemon 2>/dev/null |
    grep -Fq 'install ok installed' || ! command -v clamdscan >/dev/null 2>&1; then
  apt-get update >/dev/null
  apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam clamdscan >/dev/null
fi
systemctl stop clamav-freshclam >/dev/null 2>&1 || true
if ! find /var/lib/clamav -maxdepth 1 -type f \( -name '*.cvd' -o -name '*.cld' \) | grep -q .; then
  timeout 300 freshclam --stdout >/dev/null
fi
sed -i -E '/^(Example|LocalSocket|TCPSocket|TCPAddr)[[:space:]]/d' /etc/clamav/clamd.conf
cat >>/etc/clamav/clamd.conf <<'EOF'
TCPSocket 3310
TCPAddr 127.0.0.1
EOF
install -d -m 0755 /etc/systemd/system/clamav-daemon.socket.d
cat >/etc/systemd/system/clamav-daemon.socket.d/setjoin-loopback.conf <<'EOF'
[Socket]
ListenStream=
ListenStream=127.0.0.1:3310
EOF
systemctl daemon-reload
systemctl enable clamav-daemon >/dev/null
systemctl restart clamav-daemon.socket
systemctl restart clamav-daemon
for _ in $(seq 1 60); do
  if clamdscan --config-file=/etc/clamav/clamd.conf --no-summary /etc/hosts >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
clamdscan --config-file=/etc/clamav/clamd.conf --no-summary /etc/hosts >/dev/null
cfg=/etc/setjoin/config.env
tmp="$(mktemp)"
grep -Ev '^CLAMAV_ADDR=' "$cfg" >"$tmp"
printf 'CLAMAV_ADDR=127.0.0.1:3310\n' >>"$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$cfg"
systemctl restart setjoin
for _ in $(seq 1 30); do
  curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null && exit 0
  sleep 1
done
journalctl -u setjoin --no-pager -n 120 >&2
exit 1
INNER
  set_recovery_flags false
}

db_digest() {
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
exclude_args=()
while IFS= read -r relation; do
  [ -n "$relation" ] && exclude_args+=(--exclude-table-data="$relation")
done < <(psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAqc \
  "SELECT format('%I.%I', n.nspname, c.relname)
     FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relpersistence='u' AND c.relkind IN ('r','p')
    ORDER BY 1")
exclude_args+=(--exclude-table-data=public.health_history)
exclude_args+=(--exclude-table-data=public.threat_feed_blocks)
LC_ALL=C pg_dump "$DB_DIRECT_OWNER_DSN" --no-owner --no-privileges --format=p \
  "${exclude_args[@]}" |
  awk '
    /^\\restrict / || /^\\unrestrict / { next }
    index($0, "SELECT pg_catalog.setval('\''public.health_history_id_seq'\''") == 1 { next }
    { print }
  ' | sha256sum | awk '{print $1}'
INNER
}

threat_feed_digest() {
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAqc \
  "COPY (SELECT cidr::text, source FROM threat_feed_blocks ORDER BY cidr::text, source) TO STDOUT" |
  sha256sum | awk '{print $1}'
INNER
}

container_tree_digest() {
  local path="$1"
  docker exec -i "$A" bash -s -- "$path" <<'INNER'
set -Eeuo pipefail
path="$1"
test -d "$path"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$path" -cf - . | sha256sum | awk '{print $1}'
INNER
}

host_tree_digest() {
  local path="$1"
  (
    cd "$path"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
  ) | sha256sum | awk '{print $1}'
}

state_snapshot() {
  psql_a "SELECT jsonb_build_object(
    'schemaVersion',(SELECT max(version) FROM schema_migrations),
    'installationId',(SELECT installation_id FROM upgrade_control_state WHERE singleton),
    'timelineId',(SELECT timeline_id FROM upgrade_control_state WHERE singleton),
    'timelineGeneration',(SELECT timeline_generation FROM upgrade_control_state WHERE singleton),
    'messageCount',(SELECT count(*) FROM messages),
    'probeMailboxId',(SELECT id FROM mailboxes WHERE email='$PROBE_EMAIL'),
    'probeWatermark',(SELECT GREATEST(jmap_email_state,jmap_mailbox_state,jmap_thread_state,jmap_tag_state) FROM mailboxes WHERE email='$PROBE_EMAIL'),
    'upgradeIntents',(SELECT count(*) FROM upgrade_intents),
    'verifiedIntents',(SELECT count(*) FROM upgrade_intents WHERE state='verified'),
    'rolledBackIntents',(SELECT count(*) FROM upgrade_intents WHERE state='rolled_back'),
    'recoverySets',(SELECT count(*) FROM upgrade_recovery_sets),
    'laterMessageCount',(SELECT count(*) FROM messages WHERE message_id='<setjoin-u8-rewind@$RUN_PREFIX.test>'),
    'flags',(SELECT jsonb_object_agg(key,enabled ORDER BY key) FROM feature_toggles WHERE key IN ('feature.client_recovery_receipts','feature.client_recovery_cache','feature.client_recovery_ingest'))
  )::text"
}

release_links() {
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
for link in /opt/setjoin/current /opt/setjoin/previous /var/lib/setjoin-updater/current /var/lib/setjoin-updater/previous; do
  if [ -L "$link" ]; then printf '%s=%s\n' "$link" "$(readlink "$link")"; fi
done
INNER
}

capture_baseline() {
  state_snapshot >"$EVIDENCE_DIR/baseline-state.json"
  db_digest >"$EVIDENCE_DIR/baseline-db.sha256"
  threat_feed_digest >"$EVIDENCE_DIR/baseline-threat-feed.sha256"
  container_tree_digest /etc/setjoin >"$EVIDENCE_DIR/baseline-config.sha256"
  container_tree_digest /var/lib/setjoin-updater >"$EVIDENCE_DIR/baseline-updater.sha256"
  container_tree_digest /opt/setjoin >"$EVIDENCE_DIR/baseline-release-tree.sha256"
  release_links >"$EVIDENCE_DIR/baseline-release-links.txt"
}

snapshot_egress_cache() {
  say "Separate the reconstructible nested-Podman Egress cache from the machine layer"
  local archive="$SNAPSHOT_DIR/egress-podman-storage.tar" ref image_id
  ref="$(docker exec "$A" systemctl show setjoin-egress -p ExecStart --value |
    grep -Eo 'docker\.io/livekit/egress:[^[:space:];}]+@sha256:[0-9a-f]{64}' | head -n 1)"
  [ -n "$ref" ] || die "could not resolve the pinned Egress image reference"
  image_id="$(docker exec "$A" /usr/bin/podman image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
  if [ -z "$image_id" ]; then
    image_id="$(docker exec "$A" /usr/bin/podman images --no-trunc --format '{{.Id}}' |
      LC_ALL=C sort -u)"
    [ "$(printf '%s\n' "$image_id" | sed '/^$/d' | wc -l | tr -d ' ')" = "1" ] ||
      die "digest-less Egress cache does not contain exactly one image identity"
  fi
  [ -n "$image_id" ] || die "pinned Egress image is not present before snapshot"
  printf '%s\n' "$ref" >"$EVIDENCE_DIR/egress-image-ref.txt"
  printf '%s\n' "$image_id" >"$EVIDENCE_DIR/egress-image-id.txt"
  docker exec "$A" systemctl disable --now setjoin-egress >/dev/null
  docker exec "$A" /usr/bin/podman unmount --all --force >/dev/null 2>&1 || true
  docker exec "$A" tar --xattrs --acls --numeric-owner \
    -C /var/lib/containers -cf - storage >"$archive"
  sha256sum "$archive" | awk '{print $1}' >"$EVIDENCE_DIR/egress-cache.sha256"
  docker exec "$A" /usr/bin/podman system reset --force >/dev/null
  if [ -n "$(docker exec "$A" find /var/lib/containers/storage/overlay \
      -mindepth 1 ! -name .has-mount-program -print -quit 2>/dev/null)" ]; then
    die "nested Podman overlay payload remained after the bounded reset"
  fi
}

restore_egress_cache() {
  local archive="$SNAPSHOT_DIR/egress-podman-storage.tar" ref want_id got_id
  ref="$(sed -n '1p' "$EVIDENCE_DIR/egress-image-ref.txt")"
  want_id="$(sed -n '1p' "$EVIDENCE_DIR/egress-image-id.txt")"
  [ "$(sha256sum "$archive" | awk '{print $1}')" = \
    "$(sed -n '1p' "$EVIDENCE_DIR/egress-cache.sha256")" ] ||
    die "Egress cache archive digest changed"
  docker exec -i "$A" tar --xattrs --acls --numeric-owner \
    -C /var/lib/containers -xf - <"$archive"
  got_id="$(docker exec "$A" /usr/bin/podman image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
  if [ -z "$got_id" ]; then
    got_id="$(docker exec "$A" /usr/bin/podman image inspect --format '{{.Id}}' "$want_id")"
  fi
  [ "$got_id" = "$want_id" ] || die "restored Egress image identity differs from baseline"
  docker exec "$A" systemctl enable --now setjoin-egress >/dev/null
  for _ in $(seq 1 90); do
    if docker exec "$A" systemctl is-active --quiet setjoin-egress &&
       docker exec "$A" /usr/bin/podman ps --format '{{.Names}}' | grep -Fxq setjoin-egress; then
      return
    fi
    sleep 2
  done
  docker exec "$A" systemctl --no-pager --full status setjoin-egress >&2 || true
  die "restored pinned Egress cache did not become active"
}

snapshot_machine() {
  say "Capture coherent A database/config/updater/release and MinIO state"
  snapshot_egress_cache
  capture_baseline
  local minio_image rootfs="$SNAPSHOT_DIR/machine-rootfs.tar"
  minio_image="$(docker inspect -f '{{.Image}}' "$MINIO")"
  printf '%s\n' "$minio_image" >"$EVIDENCE_DIR/minio-image-id.txt"
  docker exec "$A" systemctl stop \
    setjoin setjoin-auth setjoin-updater setjoin-sfu setjoin-valkey clamav-daemon postgresql
  docker stop --time 30 "$MINIO" >/dev/null
  docker exec "$A" tar --one-file-system --xattrs --acls --numeric-owner \
    --exclude=./dev --exclude=./mnt --exclude=./proc --exclude=./run \
    --exclude=./sys --exclude=./tmp --exclude=./var/lib/containers/storage \
    --exclude=./etc/hostname --exclude=./etc/hosts --exclude=./etc/resolv.conf \
    -C / -cf - . >"$rootfs"
  sha256sum "$rootfs" | awk '{print $1}' >"$EVIDENCE_DIR/machine-rootfs.sha256"
  install -d -m 0700 "$SNAPSHOT_DIR/minio-data"
  docker cp "$MINIO:/data/." "$SNAPSHOT_DIR/minio-data"
  host_tree_digest "$SNAPSHOT_DIR/minio-data" >"$EVIDENCE_DIR/baseline-minio.sha256"

  docker create --name "$SNAPSHOT_BUILDER" --entrypoint /bin/bash \
    "$REWIND_BASE_IMAGE" -lc 'sleep infinity' >/dev/null
  docker start "$SNAPSHOT_BUILDER" >/dev/null
  docker cp "$rootfs" "$SNAPSHOT_BUILDER:/tmp/setjoin-machine-rootfs.tar"
  docker exec "$SNAPSHOT_BUILDER" tar --xattrs --acls --numeric-owner \
    -C / -xf /tmp/setjoin-machine-rootfs.tar
  docker exec "$SNAPSHOT_BUILDER" find /tmp/setjoin-machine-rootfs.tar \
    -maxdepth 0 -type f -delete
  docker stop --time 30 "$SNAPSHOT_BUILDER" >/dev/null
  docker commit --change 'ENTRYPOINT ["/sbin/init"]' --change 'CMD []' \
    "$SNAPSHOT_BUILDER" "$SNAPSHOT_IMAGE" >"$EVIDENCE_DIR/snapshot-image-id.txt"
  docker rm -f -v "$SNAPSHOT_BUILDER" >/dev/null

  docker restart --time 60 "$A" >/dev/null
  docker start "$MINIO" >/dev/null
  restore_egress_cache
  wait_stack
}

jmap_call() {
  local body="$1" token="$2" out="$3" label="$4" status
  status="$(api_call POST /jmap "$body" "$token" "$out")"
  expect_status "$status" 200 "$label" "$out"
  [ "$(jq -r '.methodResponses[0][0] // empty' "$out")" != "error" ] || {
    sed -n '1,30p' "$out" >&2
    die "$label returned a JMAP method error"
  }
}

capture_later_client_evidence() {
  say "Observe one later message through real continuity and receipt APIs"
  set_recovery_flags true
  local token mailbox_id message_id raw_literal body response receipt_response status raw_url
  token="$(fresh_token "$PROBE_EMAIL" "$PROBE_PASSWORD" probe)"
  mailbox_id="$(psql_a "SELECT id FROM mailboxes WHERE email='$PROBE_EMAIL'")"
  [ -n "$mailbox_id" ] || die "D2 probe mailbox is missing"
  raw_literal="$(printf 'From: External Sender <external@example.net>\r\nTo: DR Fixture User <dr-user@example.com>\r\nDate: %s\r\nMessage-ID: <setjoin-u8-rewind@%s.test>\r\nSubject: Setjoin U8 portable rewind fixture\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis message exists only after the portable snapshot.\r\n' "$(date -Ru)" "$RUN_PREFIX")"
  message_id="$(docker exec -i "$A" bash -s -- "$raw_literal" "$RUN_PREFIX" <<'INNER'
set -Eeuo pipefail
raw="$1"
prefix="$2"
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tA \
  -v raw="$raw" -v header="<setjoin-u8-rewind@${prefix}.test>" <<'SQL'
SELECT deliver(
  :'raw', :'header', 'external@example.net', 'External Sender',
  'dr-user@example.com', '["dr-user@example.com"]'::jsonb, '[]'::jsonb, '[]'::jsonb,
  'Setjoin U8 portable rewind fixture', NULL, NULL,
  'This message exists only after the portable snapshot.', NULL,
  octet_length(:'raw'), false, now(), 'pass', 'pass', 'pass', 0.0, '{}'::jsonb
);
SQL
INNER
)"
  case "$message_id" in (*[!0-9]*|'') die "later fixture did not return a message id" ;; esac
  printf '%s\n' "$mailbox_id" >"$EVIDENCE_DIR/mailbox-id.txt"
  printf '%s\n' "$message_id" >"$EVIDENCE_DIR/later-message-id.txt"

  response="$EVIDENCE_DIR/later-continuity.json"
  body="$(jq -nc --arg account "$mailbox_id" '{using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],methodCalls:[["Continuity/get",{accountId:$account},"c1"]]}')"
  jmap_call "$body" "$token" "$response" continuity_get
  jq -er '.methodResponses[0][1].token' "$response" >"$SNAPSHOT_DIR/continuity-token.txt"

  receipt_response="$EVIDENCE_DIR/later-receipt.json"
  body="$(jq -nc --arg account "$mailbox_id" --arg id "$message_id" '{using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],methodCalls:[["Email/recoveryReceipt",{accountId:$account,ids:[$id]},"r1"]]}')"
  jmap_call "$body" "$token" "$receipt_response" recovery_receipt_get
  [ "$(jq -r '.methodResponses[0][1].list | length' "$receipt_response")" = "1" ] ||
    die "recovery receipt did not return exactly one later message"
  jq -c '.methodResponses[0][1].list[0].receipt' "$receipt_response" >"$SNAPSHOT_DIR/receipt.json"
  jq -r '.methodResponses[0][1].list[0].artifactIdentity' "$receipt_response" >"$SNAPSHOT_DIR/artifact-identity.txt"
  raw_url="$(jq -r '.methodResponses[0][1].list[0].raw.url' "$receipt_response")"
  status="$(curl -ksS --max-time 30 --resolve "mail.example.com:443:$A_IP" \
    -H "Authorization: Bearer $token" -o "$SNAPSHOT_DIR/later-message.eml" -w '%{http_code}' \
    "https://mail.example.com$raw_url")"
  expect_status "$status" 200 recovery_raw
  [ "$(sha256sum "$SNAPSHOT_DIR/later-message.eml" | awk '{print $1}')" = \
    "$(jq -r '.methodResponses[0][1].list[0].receipt.claims.rawMimeSha256' "$receipt_response")" ] ||
    die "downloaded raw MIME digest differs from its signed receipt"
  [ "$(wc -c <"$SNAPSHOT_DIR/later-message.eml" | tr -d ' ')" = \
    "$(jq -r '.methodResponses[0][1].list[0].receipt.claims.rawMimeSize' "$receipt_response")" ] ||
    die "downloaded raw MIME size differs from its signed receipt"
}

restore_machine() {
  say "Destroy exact A state and recreate it from the portable snapshot"
  local minio_image offline_minio="$SNAPSHOT_DIR/restored-minio-offline"
  minio_image="$(sed -n '1p' "$EVIDENCE_DIR/minio-image-id.txt")"
  docker rm -f -v "$MINIO" "$A" >/dev/null
  docker volume create "$SNAPSHOT_VOLUME" >/dev/null
  docker run --rm -v "$SNAPSHOT_VOLUME:/data" \
    -v "$SNAPSHOT_DIR/minio-data:/snapshot:ro" --entrypoint /bin/sh "$minio_image" \
    -c 'cp -a /snapshot/. /data/'
  install -d -m 0700 "$offline_minio"
  docker run --rm -v "$SNAPSHOT_VOLUME:/data:ro" \
    -v "$offline_minio:/restored" --entrypoint /bin/sh "$minio_image" \
    -c 'cp -a /data/. /restored/'
  host_tree_digest "$offline_minio" >"$EVIDENCE_DIR/restored-minio-offline.sha256"
  docker run -d --name "$A" \
    --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock \
    -v "$ROOT":/mnt/repo-src:ro \
    -v ga-smoke-gomodcache:/root/go/pkg/mod \
    -v ga-smoke-gobuildcache:/root/.cache/go-build \
    -v ga-smoke-npmcache:/root/.npm \
    --network "$NETWORK" --ip "$A_IP" --dns "$DNS_IP" --hostname org-a.test \
    "$SNAPSHOT_IMAGE" >/dev/null
  docker run -d --name "$MINIO" --network "container:$A" \
    -v "$SNAPSHOT_VOLUME:/data" \
    -e MINIO_ROOT_USER="$ACCESS_KEY" -e MINIO_ROOT_PASSWORD="$SECRET_KEY" \
    "$minio_image" server /data --console-address :9001 >/dev/null
  restore_egress_cache
  wait_stack
}

prove_restored_boundary() {
  say "Prove database, protected config, object/index, updater, releases, and continuity rewound together"
  local after_minio="$SNAPSHOT_DIR/after-minio-data"
  state_snapshot >"$EVIDENCE_DIR/restored-state.json"
  db_digest >"$EVIDENCE_DIR/restored-db.sha256"
  threat_feed_digest >"$EVIDENCE_DIR/restored-threat-feed.sha256"
  container_tree_digest /etc/setjoin >"$EVIDENCE_DIR/restored-config.sha256"
  container_tree_digest /var/lib/setjoin-updater >"$EVIDENCE_DIR/restored-updater.sha256"
  container_tree_digest /opt/setjoin >"$EVIDENCE_DIR/restored-release-tree.sha256"
  release_links >"$EVIDENCE_DIR/restored-release-links.txt"
  install -d -m 0700 "$after_minio"
  docker cp "$MINIO:/data/." "$after_minio"
  host_tree_digest "$after_minio" >"$EVIDENCE_DIR/restored-minio.sha256"
  cmp -s "$EVIDENCE_DIR/baseline-state.json" "$EVIDENCE_DIR/restored-state.json" ||
    die "restored database authority snapshot differs from baseline"
  for component in db config updater release-tree; do
    cmp -s "$EVIDENCE_DIR/baseline-${component}.sha256" "$EVIDENCE_DIR/restored-${component}.sha256" ||
      die "restored $component digest differs from baseline"
  done
  cmp -s "$EVIDENCE_DIR/baseline-minio.sha256" "$EVIDENCE_DIR/restored-minio-offline.sha256" ||
    die "restored offline object/index digest differs from baseline"
  cmp -s "$EVIDENCE_DIR/baseline-threat-feed.sha256" "$EVIDENCE_DIR/restored-threat-feed.sha256" ||
    die "restored threat-feed CIDR/source set differs from baseline"
  cmp -s "$EVIDENCE_DIR/baseline-release-links.txt" "$EVIDENCE_DIR/restored-release-links.txt" ||
    die "restored immutable release links differ from baseline"
  [ "$(psql_a "SELECT count(*) FROM messages WHERE message_id='<setjoin-u8-rewind@$RUN_PREFIX.test>'")" = "0" ] ||
    die "later message survived the complete-machine rewind"
}

present_and_recover() {
  say "Present the external witness, reject tampering, and recover exactly one copy"
  set_recovery_flags true
  local user_token admin_token mailbox_id token token_digest present_body present_out
  local generation incident_id incident_key expires reason open_body open_out status
  local receipt identity session_id device_id upload_key inventory begin_body begin_out
  local bad_receipt bad_session bad_device bad_key bad_body bad_out raw_size raw_end
  local commit_out finalize_out quarantine_id accept_reason accept_body accept_out replay_out
  user_token="$(fresh_token "$PROBE_EMAIL" "$PROBE_PASSWORD" restored-probe)"
  admin_token="$(fresh_token "$ADMIN_EMAIL" "$ADMIN_PASSWORD" restored-admin)"
  mailbox_id="$(sed -n '1p' "$EVIDENCE_DIR/mailbox-id.txt")"
  token="$(sed -n '1p' "$SNAPSHOT_DIR/continuity-token.txt")"
  token_digest="$(printf '%s' "$token" | sha256sum | awk '{print $1}')"
  present_body="$(jq -nc --arg account "$mailbox_id" --arg token "$token" '{using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],methodCalls:[["Continuity/present",{accountId:$account,token:$token},"p1"]]}')"
  present_out="$EVIDENCE_DIR/restored-continuity-present.json"
  jmap_call "$present_body" "$user_token" "$present_out" continuity_present
  [ "$(jq -r '.methodResponses[0][1].verificationStatus' "$present_out")" = "verified" ] ||
    die "restored server did not cryptographically verify the saved witness"
  [ "$(jq -r '.methodResponses[0][1].signalClass' "$present_out")" = "client_observed_newer_timeline" ] ||
    die "restored server did not classify the later client watermark as credible"

  receipt="$(sed -n '1p' "$SNAPSHOT_DIR/receipt.json")"
  identity="$(sed -n '1p' "$SNAPSHOT_DIR/artifact-identity.txt")"
  generation="$(jq -r '.claims.timelineGeneration' "$SNAPSHOT_DIR/receipt.json")"
  incident_id="$(new_uuid)"
  incident_key="$(new_uuid)"
  expires="$(python3 - <<'PY'
import datetime
print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat().replace('+00:00','Z'))
PY
)"
  reason="Exercise complete-machine rewind recovery"
  open_body="$(jq -nc --arg incident "$incident_id" --arg mailbox "$mailbox_id" \
    --arg digest "$token_digest" --arg timeline "$generation" --arg expires "$expires" \
    --arg reason "$reason" --arg key "$incident_key" \
    '{incidentId:$incident,mailboxIds:[$mailbox],evidence:{($mailbox):$digest},minimumTimeline:$timeline,maximumTimeline:$timeline,expiresAt:$expires,reason:$reason,approvalRequired:false,idempotencyKey:$key}')"
  open_out="$EVIDENCE_DIR/incident-open.json"
  status="$(api_call POST /api/admin/system/recovery/incidents "$open_body" "$admin_token" "$open_out" "$reason" "$incident_key")"
  expect_status "$status" 201 incident_open "$open_out"

  raw_size="$(wc -c <"$SNAPSHOT_DIR/later-message.eml" | tr -d ' ')"
  inventory="$(jq -nc --arg sha "$(sha256sum "$SNAPSHOT_DIR/later-message.eml" | awk '{print $1}')" --arg size "$raw_size" '[{itemId:"raw",role:"raw",sha256:$sha,size:$size}]')"
  bad_receipt="$(jq -c '.signature=((if (.signature|startswith("A")) then "B" else "A" end)+(.signature[1:]))' "$SNAPSHOT_DIR/receipt.json")"
  bad_session="$(new_uuid)"; bad_device="$(new_uuid)"; bad_key="$(new_uuid)"
  bad_body="$(jq -nc --arg session "$bad_session" --arg incident "$incident_id" --arg account "$mailbox_id" \
    --arg device "$bad_device" --arg identity "$identity" --argjson receipt "$bad_receipt" \
    --argjson inventory "$inventory" --arg consent "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg key "$bad_key" \
    '{sessionId:$session,incidentId:$incident,accountId:$account,deviceId:$device,artifactIdentity:$identity,eligibility:"received",receipt:$receipt,inventory:$inventory,consentedAt:$consent,idempotencyKey:$key}')"
  bad_out="$EVIDENCE_DIR/adversarial-receipt-rejected.json"
  status="$(api_call POST /api/recovery/uploads "$bad_body" "$user_token" "$bad_out" "" "$bad_key")"
  expect_status "$status" 403 adversarial_receipt_rejection "$bad_out"
  [ "$(psql_a "SELECT count(*) FROM mail_recovery_upload_sessions WHERE id='$bad_session'")" = "0" ] ||
    die "tampered receipt created durable upload state"

  session_id="$(new_uuid)"; device_id="$(new_uuid)"; upload_key="$(new_uuid)"
  begin_body="$(jq -nc --arg session "$session_id" --arg incident "$incident_id" --arg account "$mailbox_id" \
    --arg device "$device_id" --arg identity "$identity" --argjson receipt "$receipt" \
    --argjson inventory "$inventory" --arg consent "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg key "$upload_key" \
    '{sessionId:$session,incidentId:$incident,accountId:$account,deviceId:$device,artifactIdentity:$identity,eligibility:"received",receipt:$receipt,inventory:$inventory,consentedAt:$consent,idempotencyKey:$key}')"
  begin_out="$EVIDENCE_DIR/upload-begin.json"
  status="$(api_call POST /api/recovery/uploads "$begin_body" "$user_token" "$begin_out" "" "$upload_key")"
  expect_status "$status" 201 upload_begin "$begin_out"
  raw_end=$((raw_size-1))
  status="$(curl -ksS --max-time 60 --resolve "mail.example.com:443:$A_IP" \
    -o "$EVIDENCE_DIR/upload-chunk.txt" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $user_token" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes 0-${raw_end}/${raw_size}" \
    --data-binary "@$SNAPSHOT_DIR/later-message.eml" \
    "https://mail.example.com/api/recovery/uploads/$session_id/items/raw")"
  expect_status "$status" 204 upload_chunk "$EVIDENCE_DIR/upload-chunk.txt"
  commit_out="$EVIDENCE_DIR/upload-commit.json"
  status="$(api_call POST "/api/recovery/uploads/$session_id/items/raw/commit" '{}' "$user_token" "$commit_out")"
  expect_status "$status" 200 upload_commit "$commit_out"
  finalize_out="$EVIDENCE_DIR/upload-finalize.json"
  status="$(api_call POST "/api/recovery/uploads/$session_id/finalize" '{}' "$user_token" "$finalize_out")"
  expect_status "$status" 201 upload_finalize "$finalize_out"
  [ "$(jq -r '.status' "$finalize_out")" = "quarantined" ] ||
    die "valid recovery artifact did not enter quarantine"
  quarantine_id="$(jq -r '.id' "$finalize_out")"
  accept_reason="Accept verified portable rewind artifact"
  accept_body="$(jq -nc --arg reason "$accept_reason" '{resolution:"accept",reason:$reason}')"
  accept_out="$EVIDENCE_DIR/artifact-accept.json"
  status="$(api_call POST "/api/admin/system/recovery/artifacts/$quarantine_id/accept" "$accept_body" "$admin_token" "$accept_out" "$accept_reason")"
  expect_status "$status" 200 artifact_accept "$accept_out"
  [ "$(jq -r '.status' "$accept_out")" = "accepted" ] || die "valid recovery artifact was not accepted"
  replay_out="$EVIDENCE_DIR/artifact-accept-replay.json"
  status="$(api_call POST "/api/admin/system/recovery/artifacts/$quarantine_id/accept" "$accept_body" "$admin_token" "$replay_out" "$accept_reason")"
  expect_status "$status" 200 artifact_accept_replay "$replay_out"
  [ "$(jq -r '.replayed' "$replay_out")" = "true" ] || die "accept replay was not idempotent"
  [ "$(psql_a "SELECT count(*) FROM messages WHERE message_id='<setjoin-u8-rewind@$RUN_PREFIX.test>'")" = "1" ] ||
    die "recovery did not create exactly one recovered copy"
  [ "$(psql_a "SELECT count(*) FROM mail_recovery_ledger WHERE artifact_identity=decode('$identity','hex') AND outcome='accepted'")" = "1" ] ||
    die "recovery ledger does not contain exactly one accepted artifact"
}

terminal_off() {
  if docker container inspect "$A" >/dev/null 2>&1 &&
     [ "$(docker inspect -f '{{.State.Running}}' "$A" 2>/dev/null)" = "true" ]; then
    set_recovery_flags false
    printf '{"version":1,"enabled":false}\n' |
      docker exec -i "$A" sh -c 'umask 077; tee /etc/setjoin-updater/execution.json >/dev/null'
    docker exec "$A" systemctl restart setjoin-updater
    docker exec "$A" systemctl is-active --quiet setjoin-updater
  fi
}

run_rewind() {
  prepare_scanner
  snapshot_machine
  capture_later_client_evidence
  restore_machine
  prove_restored_boundary
  present_and_recover
  terminal_off
  {
    printf 'run_prefix=%s\nportable_complete_machine_rewind=PASS\n' "$RUN_PREFIX"
    printf 'database_config_object_index_updater_release_continuity=RESTORED\n'
    printf 'later_client_witness=VERIFIED\nadversarial_receipt=REJECTED\n'
    printf 'accepted_recovered_copies=1\nidempotent_accept_replay=PASS\n'
    printf 'terminal_client_recovery_flags=OFF\nphysical_devices=DEFERRED\n'
    printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$EVIDENCE_DIR/result.txt"
  say "Portable complete-machine rewind PASS"
}

cleanup_resources() {
  validate_prefix
  if docker container inspect "$A" >/dev/null 2>&1 &&
     [ "$(docker inspect -f '{{.State.Running}}' "$A" 2>/dev/null)" = "true" ]; then
    terminal_off
  fi
  docker image rm -f "$SNAPSHOT_IMAGE" >/dev/null 2>&1 || true
  docker volume rm -f "$SNAPSHOT_VOLUME" >/dev/null 2>&1 || true
  docker rm -f -v "$SNAPSHOT_BUILDER" >/dev/null 2>&1 || true
  if [ -d "$SNAPSHOT_DIR" ]; then
    find "$SNAPSHOT_DIR" -type f -delete
    find "$SNAPSHOT_DIR" -depth -type d -empty -delete
  fi
}

self_test() {
  RUN_PREFIX="rewind-self-test"
  REWIND_ATTEMPT="attempt-2"
  TEST_SUBNET="172.30.240.0/24"
  validate_prefix
  [ "$A:$MINIO:$A_IP:$DNS_IP:$NETWORK" = \
    "rewind-self-test-a:rewind-self-test-a-minio:172.30.240.11:172.30.240.53:rewind-self-test-net" ] ||
    die "prefix-derived resource contract drifted"
  [ "$SNAPSHOT_IMAGE:$SNAPSHOT_VOLUME" = \
    "setjoin-rewind-rewind-self-test-attempt-2-a:baseline:rewind-self-test-attempt-2-rewind-minio-data" ] ||
    die "snapshot resource contract drifted"
  bash -n "$0"
  grep -Fq "terminal_client_recovery_flags=OFF" "$0" || die "terminal OFF evidence drifted"
  grep -Fq "docker image rm -f \"\$SNAPSHOT_IMAGE\"" "$0" || die "exact image cleanup drifted"
  grep -Fq "docker volume rm -f \"\$SNAPSHOT_VOLUME\"" "$0" || die "exact volume cleanup drifted"
  grep -Fq "docker rm -f -v \"\$SNAPSHOT_BUILDER\"" "$0" || die "exact builder cleanup drifted"
  grep -Fq "adversarial_receipt=REJECTED" "$0" || die "adversarial evidence drifted"
  printf 'SELF_TEST_PASS prefix=%s snapshot_image=%s snapshot_volume=%s\n' \
    "$RUN_PREFIX" "$SNAPSHOT_IMAGE" "$SNAPSHOT_VOLUME"
}

case "$ACTION" in
  (prepare) validate_runtime; run_rewind ;;
  (terminal-off) validate_prefix; terminal_off ;;
  (cleanup-resources) cleanup_resources ;;
  (self-test) self_test ;;
  (*) die "usage: $0 prepare|terminal-off|cleanup-resources|self-test" ;;
esac
