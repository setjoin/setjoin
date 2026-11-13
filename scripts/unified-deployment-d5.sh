#!/usr/bin/env bash
# D5: three-full-stack Federation rehearsal on retained A/B/C.
# Every private CA/leaf key is generated and retained inside its owning
# disposable environment. Only public CA certificates cross boundaries.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
ACTION="${1:-prepare}"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="Sm0ke-Test-Passw0rd!1"
API_BASE="https://mail.example.com"
EVIDENCE_DIR=""
TMP_DIR=""
DNS=""
NETWORK=""
PARTITIONED_A=0
PARTITIONED_B=0
PARTITIONED_C=0
declare -A CONTAINER IP DOMAIN TOKEN

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }
cleanup_tmp() {
  if [ "$PARTITIONED_A" = "1" ]; then
    docker network connect --ip "${IP[a]}" "$NETWORK" "${CONTAINER[a]}" \
      >/dev/null 2>&1 || true
    PARTITIONED_A=0
  fi
  if [ "$PARTITIONED_B" = "1" ]; then
    docker network connect --ip "${IP[b]}" "$NETWORK" "${CONTAINER[b]}" \
      >/dev/null 2>&1 || true
    PARTITIONED_B=0
  fi
  if [ "$PARTITIONED_C" = "1" ]; then
    docker network connect --ip "${IP[c]}" "$NETWORK" "${CONTAINER[c]}" \
      >/dev/null 2>&1 || true
    PARTITIONED_C=0
  fi
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    find "$TMP_DIR" -type f -delete
    rmdir "$TMP_DIR"
  fi
}
trap cleanup_tmp EXIT

validate() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac
  case "$ACTION" in
    (prepare|resume|journey|rotate|adversarial|peer-reset|pressure|status|cleanup) ;;
    (*) die "usage: $0 prepare|resume|journey|rotate|adversarial|peer-reset|pressure|status|cleanup" ;;
  esac
  local base="${TEST_SUBNET%.0/24}"
  local env
  for env in a b c; do
    CONTAINER[$env]="${RUN_PREFIX}-${env}"
    DOMAIN[$env]="org-${env}.test"
  done
  IP[a]="${base}.11"
  IP[b]="${base}.12"
  IP[c]="${base}.13"
  DNS="${RUN_PREFIX}-dns"
  NETWORK="${RUN_PREFIX}-net"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d5"
  install -d -m 0700 "$EVIDENCE_DIR/public-anchors"
  TMP_DIR="$(mktemp -d)"
  for env in a b c; do
    [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER[$env]}" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: ${CONTAINER[$env]}"
  done
}

wait_sql_equal() {
  local env="$1" sql="$2" expected="$3" description="$4"
  local actual=""
  for _ in $(seq 1 120); do
    actual="$(psql_env "$env" "$sql")"
    if [ "$actual" = "$expected" ]; then
      return
    fi
    sleep 1
  done
  die "$description (got ${actual:-empty}, want $expected)"
}

seed_journey_user() {
  local env="$1" user_id="$2" local_part="$3" domain="$4"
  psql_env "$env" "
    INSERT INTO domains(name,is_local) VALUES ('$domain',true)
      ON CONFLICT(name) DO UPDATE SET is_local=true;
    INSERT INTO users(id,username,domain_id,email,display_name,password_hash,enabled)
      SELECT $user_id,'$local_part',id,'$local_part@$domain',
             '$local_part','\$2a\$10\$deploymentreadinessfixture',true
        FROM domains WHERE name='$domain'
      ON CONFLICT(id) DO NOTHING;
    INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,is_primary,enabled,receive_enabled)
      SELECT $user_id,$user_id,id,'$local_part@$domain',
             '$local_part',true,true,true
        FROM domains WHERE name='$domain'
      ON CONFLICT(id) DO NOTHING;
  " >/dev/null
  [ "$(psql_env "$env" "
    SELECT count(*) FROM mailboxes mb
      JOIN users u ON u.id=mb.user_id
     WHERE u.id=$user_id AND lower(mb.email)='$local_part@$domain'
       AND u.enabled AND mb.enabled AND mb.receive_enabled
  ")" = "1" ] || die "failed to seed $env federation journey user"
}

psql_env() {
  local env="$1" sql="$2"
  docker exec -i "${CONTAINER[$env]}" bash -s -- "$sql" <<'INNER'
set -Eeuo pipefail
sql="$1"
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAc "$sql"
INNER
}

api_call() {
  local env="$1" method="$2" path="$3" body="$4" bearer="$5" out="$6"
  local args=(
    -ksS --max-time 30
    --resolve "mail.example.com:443:${IP[$env]}"
    -o "$out" -w '%{http_code}'
    -X "$method" "$API_BASE$path"
    -H 'Content-Type: application/json'
  )
  [ -n "$bearer" ] && args+=(-H "Authorization: Bearer $bearer")
  [ -n "$body" ] && args+=(--data-binary "$body")
  curl "${args[@]}"
}

enroll_admin_and_issue_token() {
  local env="$1" response setup confirm status mfa_token uri secret code token
  response="$TMP_DIR/${env}-login.json"
  setup="$TMP_DIR/${env}-setup.json"
  confirm="$TMP_DIR/${env}-confirm.json"
  psql_env "$env" "
    UPDATE users
       SET totp_enabled=false,totp_enabled_at=NULL,totp_secret_enc=NULL
     WHERE lower(email)=lower('$ADMIN_EMAIL');
    DELETE FROM oauth_tokens
     WHERE user_id=(SELECT id FROM users WHERE lower(email)=lower('$ADMIN_EMAIL'));
    DELETE FROM rate_limit_counters WHERE key='auth:http:127.0.0.1';
  " >/dev/null
  status="$(api_call "$env" POST /auth/login \
    "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "" "$response")"
  [ "$status" = "403" ] || die "$env admin enrollment: HTTP $status"
  mfa_token="$(jq -r '.mfa_token // empty' "$response")"
  [ -n "$mfa_token" ] || die "$env admin login omitted mfa_token"
  status="$(api_call "$env" POST /auth/totp/enroll/setup \
    "$(jq -nc --arg token "$mfa_token" '{mfa_token:$token}')" "" "$setup")"
  [ "$status" = "200" ] || die "$env TOTP setup: HTTP $status"
  uri="$(jq -r '.provisioning_uri // empty' "$setup")"
  secret="$(sh "$ROOT/scripts/rehearsal-totp.sh" secret "$uri")"
  code="$(sh "$ROOT/scripts/rehearsal-totp.sh" code "$secret")"
  status="$(api_call "$env" POST /auth/totp/enroll/confirm \
    "$(jq -nc --arg token "$mfa_token" --arg code "$code" \
      '{mfa_token:$token,code:$code}')" "" "$confirm")"
  [ "$status" = "200" ] || die "$env TOTP confirm: HTTP $status"
  token="$(jq -r '.access_token // empty' "$confirm")"
  [ -n "$token" ] || die "$env TOTP confirmation omitted access token"
  printf '%s' "$token"
}

generate_owned_federation_identity() {
  local env="$1"
  docker exec -i "${CONTAINER[$env]}" bash -s -- "${DOMAIN[$env]}" "$RUN_PREFIX" <<'INNER'
set -Eeuo pipefail
domain="$1"
prefix="$2"
dir=/etc/setjoin/federation
install -d -m 0700 -o setjoin -g setjoin "$dir"
if [ ! -s "$dir/ca.crt" ] || [ ! -s "$dir/ca.key" ] ||
   [ ! -s "$dir/leaf.crt" ] || [ ! -s "$dir/leaf.key" ]; then
  rm -f "$dir"/*
  openssl req -x509 -newkey rsa:3072 -sha256 -days 3 -nodes \
    -subj "/CN=${prefix}-${domain}-federation-ca" \
    -keyout "$dir/ca.key" -out "$dir/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:3072 -sha256 -nodes -subj "/CN=$domain" \
    -keyout "$dir/leaf.key" -out "$dir/leaf.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n' \
    "$domain" >"$dir/leaf.ext"
  openssl x509 -req -sha256 -days 3 -in "$dir/leaf.csr" \
    -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -extfile "$dir/leaf.ext" -out "$dir/leaf.crt" >/dev/null 2>&1
  rm -f "$dir/leaf.csr" "$dir/leaf.ext" "$dir/ca.srl"
fi
chown -R setjoin:setjoin "$dir"
chmod 0700 "$dir"
chmod 0600 "$dir/ca.key" "$dir/leaf.key"
chmod 0644 "$dir/ca.crt" "$dir/leaf.crt"
begin="# ${prefix}-d5-federation-begin"
end="# ${prefix}-d5-federation-end"
sed -i "/^${begin}$/,/^${end}$/d" /etc/setjoin/config.env
cat >>/etc/setjoin/config.env <<EOF
$begin
FEDERATION_LOCAL_DOMAIN=$domain
FEDERATION_LISTEN_ADDR=:7443
FEDERATION_CERT=$dir/leaf.crt
FEDERATION_KEY=$dir/leaf.key
$end
EOF
openssl verify -CAfile "$dir/ca.crt" "$dir/leaf.crt"
openssl x509 -in "$dir/leaf.crt" -noout -checkhost "$domain"
test "$(stat -c '%a' "$dir/ca.key")" = 600
test "$(stat -c '%a' "$dir/leaf.key")" = 600
INNER
  docker exec "${CONTAINER[$env]}" cat /etc/setjoin/federation/ca.crt \
    >"$EVIDENCE_DIR/public-anchors/${DOMAIN[$env]}.ca.crt"
  if grep -Eq 'BEGIN (.* )?PRIVATE KEY' \
      "$EVIDENCE_DIR/public-anchors/${DOMAIN[$env]}.ca.crt"; then
    die "$env public anchor export contains a private key"
  fi
}

restart_and_wait() {
  local env="$1"
  docker exec "${CONTAINER[$env]}" systemctl reset-failed setjoin
  docker exec "${CONTAINER[$env]}" systemctl restart setjoin
  local _
  for _ in $(seq 1 45); do
    if docker exec "${CONTAINER[$env]}" \
      curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null; then
      return
    fi
    sleep 1
  done
  die "$env gateway did not return ready"
}

install_mailctl_loopback_name() {
  local env="$1"
  docker exec -i "${CONTAINER[$env]}" bash -s -- "$RUN_PREFIX" <<'INNER'
set -Eeuo pipefail
prefix="$1"
marker="# ${prefix}-d5-mailctl"
if ! grep -Eq '^[[:space:]]*127\.0\.0\.1[[:space:]].*([[:space:]]|^)mail\.example\.com([[:space:]]|$)' /etc/hosts; then
  printf '127.0.0.1 mail.example.com %s\n' "$marker" >>/etc/hosts
fi
getent hosts mail.example.com >/dev/null
INNER
}

set_feature() {
  local env="$1" enabled="$2"
  # Keep the hosts repair and static Go resolver in one docker exec. Docker
  # may regenerate /etc/hosts between separate execs after DNS replacement.
  docker exec -i \
    -e MAILCTL_SERVER="$API_BASE" \
    -e MAILCTL_TOKEN="${TOKEN[$env]}" \
    -e SSL_CERT_FILE=/etc/setjoin/tls/server.pem \
    "${CONTAINER[$env]}" bash -s -- "$RUN_PREFIX" "$enabled" <<'INNER'
set -Eeuo pipefail
prefix="$1"
enabled="$2"
if ! grep -Eq '^[[:space:]]*127\.0\.0\.1[[:space:]].*([[:space:]]|^)mail\.example\.com([[:space:]]|$)' /etc/hosts; then
  printf '127.0.0.1 mail.example.com # %s-d5-mailctl\n' "$prefix" >>/etc/hosts
fi
exec /opt/setjoin/mailctl feature set feature.federation "$enabled" --yes
INNER
}

upsert_peer() {
  local env="$1" peer="$2" anchor_file="$3" scope="$4" enabled="$5"
  local out="$TMP_DIR/peer-${env}-${peer}.json" status body
  body="$(jq -nc \
    --arg domain "${DOMAIN[$peer]}" \
    --rawfile anchor "$anchor_file" \
    --arg scope "$scope" \
    --argjson enabled "$enabled" \
    '{domain:$domain,anchorPem:$anchor,scope:$scope,enabled:$enabled}')"
  status="$(api_call "$env" POST /api/admin/federation/peers \
    "$body" "${TOKEN[$env]}" "$out")"
  [ "$status" = "204" ] ||
    die "$env -> $peer peer upsert: HTTP $status $(tr -d '\n' <"$out")"
}

assert_srv() {
  local env="$1"
  docker exec "${CONTAINER[$env]}" getent hosts "${DOMAIN[$env]}" >/dev/null
  docker exec "$DNS" grep -Fx \
    "_setjoin-im._tcp IN SRV 0 0 7443 ${DOMAIN[$env]}." \
    "/etc/bind/db.${DOMAIN[$env]}" >/dev/null
}

journal_cursor() {
  local env="$1"
  docker exec "${CONTAINER[$env]}" \
    journalctl -u setjoin -n 0 --show-cursor --no-pager |
    sed -n 's/^-- cursor: //p'
}

journal_after_cursor() {
  local env="$1" cursor="$2" out="$3"
  docker exec "${CONTAINER[$env]}" \
    journalctl -u setjoin --after-cursor="$cursor" --no-pager >"$out"
}

ensure_dns_srv() {
  if ! docker exec "$DNS" grep -Fq \
      '_setjoin-im._tcp IN SRV 0 0 7443 ' \
      /etc/bind/db.org-a.test 2>/dev/null; then
    docker rm -f "$DNS" >/dev/null 2>&1 || true
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" resume-provision >/dev/null
  fi
}

repair_unambiguous_bootstrap_authority() {
  local env="$1"
  psql_env "$env" "
    INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
    SELECT u.id,g.id,u.id
      FROM users u
      JOIN admin_role_groups g
        ON g.name='Super Admin' AND g.is_builtin=TRUE
     WHERE u.enabled=TRUE
       AND u.is_local_admin=TRUE
       AND (SELECT count(*) FROM users candidate
             WHERE candidate.enabled=TRUE
               AND candidate.is_local_admin=TRUE)=1
       AND NOT EXISTS (
             SELECT 1 FROM admin_role_assignments live_assignment
              WHERE live_assignment.expires_at IS NULL
                 OR live_assignment.expires_at>now()
           )
       AND NOT EXISTS (
             SELECT 1 FROM admin_role_assignments existing
              WHERE existing.user_id=u.id
           )
    ON CONFLICT(user_id,role_group_id) DO NOTHING;
  " >/dev/null
  [ "$(psql_env "$env" "
    SELECT count(*) FROM admin_role_assignments a
      JOIN admin_role_groups g ON g.id=a.role_group_id
     WHERE a.user_id=(SELECT id FROM users WHERE lower(email)=lower('$ADMIN_EMAIL'))
       AND g.name='Super Admin'
       AND (a.expires_at IS NULL OR a.expires_at>now())
  ")" = "1" ] || die "$env has no unambiguous governed bootstrap authority"
}

prepare_action() {
  local env
  if [ "$ACTION" = "prepare" ]; then
    say "Repair private DNS with production Federation SRV port"
    ensure_dns_srv
    for env in a b c; do
      generate_owned_federation_identity "$env"
    done
    for env in a b c; do
      restart_and_wait "$env"
      assert_srv "$env"
    done
  else
    ensure_dns_srv
    for env in a b c; do
      [ -s "$EVIDENCE_DIR/public-anchors/${DOMAIN[$env]}.ca.crt" ] ||
        die "resume requires the public-anchor checkpoint for $env"
      docker exec "${CONTAINER[$env]}" test -s /etc/setjoin/federation/leaf.key ||
        die "resume requires the owned federation identity for $env"
      assert_srv "$env"
    done
  fi
  for env in a b c; do
    repair_unambiguous_bootstrap_authority "$env"
    install_mailctl_loopback_name "$env"
    TOKEN[$env]="$(enroll_admin_and_issue_token "$env")"
  done

  say "Enable Federation and prove wrong-anchor refusal before trust correction"
  for env in a b c; do set_feature "$env" on; done
  local disable_cursor wrong_cursor
  disable_cursor="$(journal_cursor a)"
  upsert_peer a b "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" room false
  for _ in $(seq 1 30); do
    journal_after_cursor a "$disable_cursor" "$EVIDENCE_DIR/disable-b-a.log"
    if grep -Eq 'federation: reconcile: dropped dial loop.*peer=org-b\.test' \
         "$EVIDENCE_DIR/disable-b-a.log"; then
      break
    fi
    sleep 1
  done
  grep -Eq 'federation: reconcile: dropped dial loop.*peer=org-b\.test' \
    "$EVIDENCE_DIR/disable-b-a.log" ||
    die "A did not actively evict the existing B stream before anchor rotation"
  wrong_cursor="$(journal_cursor a)"
  upsert_peer a b "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" room true
  upsert_peer b a "$EVIDENCE_DIR/public-anchors/${DOMAIN[a]}.ca.crt" room true
  for _ in $(seq 1 30); do
    journal_after_cursor a "$wrong_cursor" "$EVIDENCE_DIR/wrong-anchor-a.log"
    if grep -Eiq 'certificate|tls|anchor|unknown authority|verify' \
         "$EVIDENCE_DIR/wrong-anchor-a.log"; then
      break
    fi
    sleep 1
  done
  grep -Eiq 'certificate|tls|anchor|unknown authority|verify' \
    "$EVIDENCE_DIR/wrong-anchor-a.log" ||
    die "wrong-anchor refusal did not emit a bounded TLS diagnostic"
  if grep -Eq 'msg="federation: dialed peer".*peer=org-b\.test' \
      "$EVIDENCE_DIR/wrong-anchor-a.log"; then
    die "wrong anchor unexpectedly authenticated B"
  fi

  upsert_peer a b "$EVIDENCE_DIR/public-anchors/${DOMAIN[b]}.ca.crt" room false
  sleep 3
  upsert_peer a b "$EVIDENCE_DIR/public-anchors/${DOMAIN[b]}.ca.crt" room true
  upsert_peer a c "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" room true
  upsert_peer c a "$EVIDENCE_DIR/public-anchors/${DOMAIN[a]}.ca.crt" room true
  for _ in $(seq 1 30); do
    docker exec "${CONTAINER[a]}" journalctl -u setjoin --since "5 minutes ago" --no-pager \
      >"$EVIDENCE_DIR/hub-streams-a.log"
    if grep -Eq 'msg="federation: dialed peer".*peer=org-b\.test' \
         "$EVIDENCE_DIR/hub-streams-a.log" &&
       grep -Eq 'msg="federation: dialed peer".*peer=org-c\.test' \
         "$EVIDENCE_DIR/hub-streams-a.log"; then
      break
    fi
    sleep 2
  done
  grep -Eq 'msg="federation: dialed peer".*peer=org-b\.test' \
    "$EVIDENCE_DIR/hub-streams-a.log" ||
    die "A did not establish the production B stream"
  grep -Eq 'msg="federation: dialed peer".*peer=org-c\.test' \
    "$EVIDENCE_DIR/hub-streams-a.log" ||
    die "A did not establish the production C stream"
  [ "$(psql_env b "SELECT count(*) FROM federation_allowlist WHERE peer_domain='${DOMAIN[c]}'")" = "0" ] ||
    die "B unexpectedly allow-listed C"
  [ "$(psql_env c "SELECT count(*) FROM federation_allowlist WHERE peer_domain='${DOMAIN[b]}'")" = "0" ] ||
    die "C unexpectedly allow-listed B"
  {
    printf 'federation_static_config=PASS\n'
    printf 'private_key_modes=PASS\n'
    printf 'public_anchor_only_exchange=PASS\n'
    printf 'private_dns_srv_7443=PASS\n'
    printf 'wrong_anchor_refused=PASS\n'
    printf 'hub_spoke_streams=2\n'
    printf 'spoke_to_spoke_allowlist=0\n'
  } | tee "$EVIDENCE_DIR/prepare.txt"
  printf 'D5_PREPARE_PASS\n'
}

journey_action() {
  [ -s "$EVIDENCE_DIR/prepare.txt" ] ||
    die "journey requires a completed prepare/resume phase"
  local hub_user=91000 bravo_user=91001 charlie_user=91002
  local checkpoint="$EVIDENCE_DIR/room.checkpoint"
  local channel_id room_id bravo_channel charlie_channel
  local tag
  tag="d5-$(date -u +%Y%m%d%H%M%S)"

  say "Seed disposable local identities for real DM and room delivery"
  seed_journey_user a "$hub_user" hubowner "${DOMAIN[a]}"
  seed_journey_user b "$bravo_user" contact "${DOMAIN[b]}"
  seed_journey_user c "$charlie_user" contact "${DOMAIN[c]}"

  if [ -s "$checkpoint" ]; then
    IFS='|' read -r channel_id room_id <"$checkpoint"
    [ "$(psql_env a "
      SELECT count(*) FROM chat_channels
       WHERE id=$channel_id AND federated_room_id='$room_id'
    ")" = "1" ] || die "stored federation room checkpoint is stale"
  else
    channel_id="$(psql_env a \
      "SELECT chat_channel_create($hub_user,'${RUN_PREFIX}-federation-room')")"
    room_id="$(psql_env a \
      "SELECT federation_room_create($hub_user,$channel_id,'${DOMAIN[a]}')")"
    printf '%s|%s\n' "$channel_id" "$room_id" >"$checkpoint"
  fi

  psql_env a "
    SELECT federation_room_invite(
      $hub_user,$channel_id,'${DOMAIN[b]}','contact@${DOMAIN[b]}');
    SELECT federation_room_invite(
      $hub_user,$channel_id,'${DOMAIN[c]}','contact@${DOMAIN[c]}');
  " >/dev/null
  wait_sql_equal b "
    SELECT count(*) FROM chat_channels
     WHERE federated_room_id='$room_id'
       AND federated_peer_domain='${DOMAIN[a]}'
  " 1 "B room mirror did not materialize"
  wait_sql_equal c "
    SELECT count(*) FROM chat_channels
     WHERE federated_room_id='$room_id'
       AND federated_peer_domain='${DOMAIN[a]}'
  " 1 "C room mirror did not materialize"
  bravo_channel="$(psql_env b \
    "SELECT id FROM chat_channels WHERE federated_room_id='$room_id'")"
  charlie_channel="$(psql_env c \
    "SELECT id FROM chat_channels WHERE federated_room_id='$room_id'")"

  say "Exercise a bilateral federated DM on the production Service"
  local dm_a dm_b dm_ab="D5-DM-A2B-$tag" dm_ba="D5-DM-B2A-$tag"
  dm_a="$(psql_env a \
    "SELECT federation_dm_ensure($hub_user,'contact@${DOMAIN[b]}')")"
  psql_env a "SELECT chat_message_send($hub_user,$dm_a,'$dm_ab')" >/dev/null
  wait_sql_equal b "
    SELECT count(*) FROM chat_messages
     WHERE body='$dm_ab' AND federated_origin_domain='${DOMAIN[a]}'
  " 1 "A to B federated DM did not land exactly once"
  dm_b="$(psql_env b \
    "SELECT channel_id FROM chat_messages WHERE body='$dm_ab'")"
  psql_env b "SELECT chat_message_send($bravo_user,$dm_b,'$dm_ba')" >/dev/null
  wait_sql_equal a "
    SELECT count(*) FROM chat_messages
     WHERE body='$dm_ba' AND federated_origin_domain='${DOMAIN[b]}'
  " 1 "B to A federated DM did not land exactly once"

  say "Exercise hub-and-spoke room relay and honest origin attribution"
  local b_room="D5-ROOM-B-$tag" a_room="D5-ROOM-A-$tag"
  psql_env b \
    "SELECT chat_message_send($bravo_user,$bravo_channel,'$b_room')" >/dev/null
  wait_sql_equal a "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$channel_id AND body='$b_room'
       AND federated_origin_domain='${DOMAIN[b]}'
  " 1 "B room message did not land on A exactly once"
  wait_sql_equal c "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$charlie_channel AND body='$b_room'
       AND federated_origin_domain='${DOMAIN[b]}'
  " 1 "B room message did not relay through A to C exactly once"
  psql_env a \
    "SELECT chat_message_send($hub_user,$channel_id,'$a_room')" >/dev/null
  wait_sql_equal b "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$bravo_channel AND body='$a_room'
       AND federated_origin_domain='${DOMAIN[a]}'
  " 1 "A room message did not land on B exactly once"
  wait_sql_equal c "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$charlie_channel AND body='$a_room'
       AND federated_origin_domain='${DOMAIN[a]}'
  " 1 "A room message did not land on C exactly once"

  say "Partition the hub, force a cross-org numeric-ID collision, queue and reconnect"
  local collide_b="D5-COLLISION-B-$tag" collide_c="D5-COLLISION-C-$tag"
  local collide_at b_message_id c_message_id b_pid c_pid
  collide_at="$(
    printf '%s\n%s\n' \
      "$(psql_env b "SELECT COALESCE(max(id),0) FROM chat_messages")" \
      "$(psql_env c "SELECT COALESCE(max(id),0) FROM chat_messages")" |
      sort -nr | head -1
  )"
  collide_at=$((collide_at + 100))
  docker network disconnect "$NETWORK" "${CONTAINER[a]}"
  PARTITIONED_A=1
  sleep 3
  psql_env b "SELECT setval(pg_get_serial_sequence('chat_messages','id'),$collide_at,true)" \
    >/dev/null
  psql_env c "SELECT setval(pg_get_serial_sequence('chat_messages','id'),$collide_at,true)" \
    >/dev/null
  psql_env b \
    "SELECT chat_message_send($bravo_user,$bravo_channel,'$collide_b')" \
    >"$EVIDENCE_DIR/collision-b.json" &
  b_pid=$!
  psql_env c \
    "SELECT chat_message_send($charlie_user,$charlie_channel,'$collide_c')" \
    >"$EVIDENCE_DIR/collision-c.json" &
  c_pid=$!
  wait "$b_pid"
  wait "$c_pid"
  b_message_id="$(psql_env b \
    "SELECT id FROM chat_messages WHERE channel_id=$bravo_channel AND body='$collide_b'")"
  c_message_id="$(psql_env c \
    "SELECT id FROM chat_messages WHERE channel_id=$charlie_channel AND body='$collide_c'")"
  [ "$b_message_id" = "$c_message_id" ] ||
    die "partitioned spoke sends did not receive the same numeric message id"
  wait_sql_equal b "
    SELECT count(*) FROM federation_peers
     WHERE peer_domain='${DOMAIN[a]}' AND last_seq>last_acked_seq
  " 1 "B did not retain an unacknowledged message while A was partitioned"
  wait_sql_equal c "
    SELECT count(*) FROM federation_peers
     WHERE peer_domain='${DOMAIN[a]}' AND last_seq>last_acked_seq
  " 1 "C did not retain an unacknowledged message while A was partitioned"
  [ "$(psql_env b \
    "SELECT count(*) FROM chat_messages WHERE body='$collide_c'")" = "0" ] ||
    die "B received C traffic directly while hub A was partitioned"
  [ "$(psql_env c \
    "SELECT count(*) FROM chat_messages WHERE body='$collide_b'")" = "0" ] ||
    die "C received B traffic directly while hub A was partitioned"
  docker network connect --ip "${IP[a]}" "$NETWORK" "${CONTAINER[a]}"
  PARTITIONED_A=0
  wait_sql_equal a "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$channel_id AND body='$collide_b'
       AND federated_origin_domain='${DOMAIN[b]}'
  " 1 "A did not apply B's queued collision message after reconnect"
  wait_sql_equal a "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$channel_id AND body='$collide_c'
       AND federated_origin_domain='${DOMAIN[c]}'
  " 1 "A did not apply C's queued collision message after reconnect"
  wait_sql_equal b "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$bravo_channel AND body='$collide_c'
       AND federated_origin_domain='${DOMAIN[c]}'
  " 1 "B lost C's same-numeric-ID relay"
  wait_sql_equal c "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$charlie_channel AND body='$collide_b'
       AND federated_origin_domain='${DOMAIN[b]}'
  " 1 "C lost B's same-numeric-ID relay"
  wait_sql_equal b "
    SELECT count(*) FROM federation_peers
     WHERE peer_domain='${DOMAIN[a]}' AND last_seq=last_acked_seq
  " 1 "B federation cursor did not converge after reconnect"
  wait_sql_equal c "
    SELECT count(*) FROM federation_peers
     WHERE peer_domain='${DOMAIN[a]}' AND last_seq=last_acked_seq
  " 1 "C federation cursor did not converge after reconnect"
  wait_sql_equal a "
    SELECT count(*) FROM generate_series(
      1,COALESCE((SELECT last_applied_seq FROM federation_inbox_cursor
                   WHERE peer_domain='${DOMAIN[b]}'),0)
    ) seq
    WHERE NOT EXISTS (
      SELECT 1 FROM federation_inbox i
       WHERE i.peer_domain='${DOMAIN[b]}' AND i.peer_seq=seq
    )
  " 0 "A federation inbox contains a sequence gap after reconnect"
  wait_sql_equal a "
    SELECT count(*) FROM generate_series(
      1,COALESCE((SELECT last_applied_seq FROM federation_inbox_cursor
                   WHERE peer_domain='${DOMAIN[c]}'),0)
    ) seq
    WHERE NOT EXISTS (
      SELECT 1 FROM federation_inbox i
       WHERE i.peer_domain='${DOMAIN[c]}' AND i.peer_seq=seq
    )
  " 0 "A federation inbox contains a C sequence gap after reconnect"

  {
    printf 'journey_tag=%s\n' "$tag"
    printf 'bilateral_dm=PASS\n'
    printf 'room_mirrors=2\n'
    printf 'hub_spoke_room_relay=PASS\n'
    printf 'origin_attribution=PASS\n'
    printf 'same_numeric_id=%s\n' "$b_message_id"
    printf 'same_numeric_id_dedup=PASS\n'
    printf 'hub_partition_queue=PASS\n'
    printf 'reconnect_ack_convergence=PASS\n'
    printf 'inbox_gaps=0\n'
  } | tee "$EVIDENCE_DIR/journey.txt"
  printf 'D5_JOURNEY_PASS\n'
}

rotate_action() {
  [ -s "$EVIDENCE_DIR/journey.txt" ] ||
    die "rotate requires a completed production DM/room journey"
  local cursor
  say "Rotate B's private CA and leaf entirely inside B"
  cursor="$(journal_cursor a)"
  docker exec -i "${CONTAINER[b]}" bash -s -- "${DOMAIN[b]}" <<'INNER'
set -Eeuo pipefail
domain="$1"
dir=/etc/setjoin/federation
next="$(mktemp -d /etc/setjoin/federation-next.XXXXXX)"
trap 'find "$next" -type f -delete 2>/dev/null || true; rmdir "$next" 2>/dev/null || true' EXIT
openssl genrsa -out "$next/ca.key" 3072 >/dev/null 2>&1
openssl req -x509 -new -sha256 -days 3 -key "$next/ca.key" \
  -subj "/CN=${domain} D5 rotated CA" -out "$next/ca.crt" >/dev/null 2>&1
openssl genrsa -out "$next/leaf.key" 3072 >/dev/null 2>&1
openssl req -new -key "$next/leaf.key" -subj "/CN=$domain" \
  -out "$next/leaf.csr" >/dev/null 2>&1
cat >"$next/leaf.ext" <<EOF
subjectAltName=DNS:$domain
extendedKeyUsage=serverAuth,clientAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl x509 -req -sha256 -days 3 -in "$next/leaf.csr" \
  -CA "$next/ca.crt" -CAkey "$next/ca.key" -CAcreateserial \
  -extfile "$next/leaf.ext" -out "$next/leaf.crt" >/dev/null 2>&1
openssl verify -CAfile "$next/ca.crt" "$next/leaf.crt"
openssl x509 -in "$next/leaf.crt" -noout -checkhost "$domain"
install -o setjoin -g setjoin -m 0600 "$next/ca.key" "$dir/ca.key"
install -o setjoin -g setjoin -m 0600 "$next/leaf.key" "$dir/leaf.key"
install -o setjoin -g setjoin -m 0644 "$next/ca.crt" "$dir/ca.crt"
install -o setjoin -g setjoin -m 0644 "$next/leaf.crt" "$dir/leaf.crt"
INNER
  docker exec "${CONTAINER[b]}" cat /etc/setjoin/federation/ca.crt \
    >"$EVIDENCE_DIR/public-anchors/${DOMAIN[b]}.rotated.ca.crt"
  if grep -Eq 'BEGIN (.* )?PRIVATE KEY' \
      "$EVIDENCE_DIR/public-anchors/${DOMAIN[b]}.rotated.ca.crt"; then
    die "rotated public anchor export contains a private key"
  fi

  restart_and_wait b
  for _ in $(seq 1 40); do
    journal_after_cursor a "$cursor" "$EVIDENCE_DIR/rotation-old-anchor-a.log"
    if grep -Eiq 'anchor|unknown authority|certificate signed by' \
         "$EVIDENCE_DIR/rotation-old-anchor-a.log"; then
      break
    fi
    sleep 1
  done
  grep -Eiq 'anchor|unknown authority|certificate signed by' \
    "$EVIDENCE_DIR/rotation-old-anchor-a.log" ||
    die "A did not reject B's rotated identity before anchor approval"

  repair_unambiguous_bootstrap_authority a
  install_mailctl_loopback_name a
  TOKEN[a]="$(enroll_admin_and_issue_token a)"
  cursor="$(journal_cursor a)"
  upsert_peer a b \
    "$EVIDENCE_DIR/public-anchors/${DOMAIN[b]}.rotated.ca.crt" room false
  upsert_peer a b \
    "$EVIDENCE_DIR/public-anchors/${DOMAIN[b]}.rotated.ca.crt" room true
  for _ in $(seq 1 40); do
    journal_after_cursor a "$cursor" "$EVIDENCE_DIR/rotation-approved-a.log"
    if grep -Eq 'msg="federation: dialed peer".*peer=org-b\.test' \
         "$EVIDENCE_DIR/rotation-approved-a.log"; then
      break
    fi
    sleep 1
  done
  grep -Eq 'msg="federation: dialed peer".*peer=org-b\.test' \
    "$EVIDENCE_DIR/rotation-approved-a.log" ||
    die "A did not reconnect to B after approving the rotated public anchor"
  {
    printf 'old_anchor_rejected=PASS\n'
    printf 'rotated_public_anchor_approved=PASS\n'
    printf 'private_rotation_material_stayed_in_b=PASS\n'
    printf 'rotation_reconnect=PASS\n'
  } | tee "$EVIDENCE_DIR/rotation.txt"
  printf 'D5_ROTATION_PASS\n'
}

adversarial_action() {
  [ -s "$EVIDENCE_DIR/rotation.txt" ] ||
    die "adversarial requires the completed certificate rotation"
  local channel_id room_id bravo_channel charlie_channel
  local tag
  tag="d5-adv-$(date -u +%Y%m%d%H%M%S)"
  local trigger="D5-SCOPE-REVOKE-$tag" straggler="D5-STRAGGLER-$tag"
  IFS='|' read -r channel_id room_id <"$EVIDENCE_DIR/room.checkpoint"
  bravo_channel="$(psql_env b \
    "SELECT id FROM chat_channels WHERE federated_room_id='$room_id'")"
  charlie_channel="$(psql_env c \
    "SELECT id FROM chat_channels WHERE federated_room_id='$room_id'")"

  repair_unambiguous_bootstrap_authority a
  install_mailctl_loopback_name a
  TOKEN[a]="$(enroll_admin_and_issue_token a)"

  say "Downgrade C to DM scope, prove visible revocation, then re-admit"
  upsert_peer a c "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" dm true
  psql_env b \
    "SELECT chat_message_send(91001,$bravo_channel,'$trigger')" >/dev/null
  wait_sql_equal a "
    SELECT count(*) FROM federation_room_members
     WHERE room_id='$room_id' AND member_domain='${DOMAIN[c]}'
       AND left_reason='revoked' AND left_at IS NOT NULL
  " 1 "C was not revoked after its room scope was withdrawn"
  wait_sql_equal c "
    SELECT count(*) FROM chat_channels
     WHERE id=$charlie_channel AND federated_room_removed_at IS NOT NULL
  " 1 "C did not receive the visible room-revoked advisory"
  upsert_peer a c "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" room true
  psql_env a "
    SELECT federation_room_invite(
      91000,$channel_id,'${DOMAIN[c]}','contact@${DOMAIN[c]}')
  " >/dev/null
  wait_sql_equal c "
    SELECT count(*) FROM chat_channels
     WHERE id=$charlie_channel AND federated_room_removed_at IS NULL
  " 1 "C mirror did not reactivate after re-invite"
  wait_sql_equal c "
    SELECT (count(*)>=1)::int FROM chat_messages
     WHERE channel_id=$charlie_channel AND msg_type='system'
       AND body LIKE '%federation_gap%'
  " 1 "C re-invite did not materialize the visible gap marker"

  say "Kick B while partitioned, prove straggler poison and read-only mirror"
  docker network disconnect "$NETWORK" "${CONTAINER[b]}"
  PARTITIONED_B=1
  sleep 3
  psql_env a \
    "SELECT federation_room_remove(91000,$channel_id,'${DOMAIN[b]}')" >/dev/null
  psql_env b \
    "SELECT chat_message_send(91001,$bravo_channel,'$straggler')" >/dev/null
  [ "$(psql_env a \
    "SELECT count(*) FROM chat_messages WHERE channel_id=$channel_id AND body='$straggler'")" = "0" ] ||
    die "partitioned B straggler landed on A before reconnect"
  docker network connect --ip "${IP[b]}" "$NETWORK" "${CONTAINER[b]}"
  PARTITIONED_B=0
  wait_sql_equal b "
    SELECT count(*) FROM chat_channels
     WHERE id=$bravo_channel AND federated_room_removed_at IS NOT NULL
  " 1 "B mirror did not become read-only after kick"
  sleep 3
  [ "$(psql_env a \
    "SELECT count(*) FROM chat_messages WHERE channel_id=$channel_id AND body='$straggler'")" = "0" ] ||
    die "kicked B straggler was applied on A"
  [ "$(psql_env c \
    "SELECT count(*) FROM chat_messages WHERE channel_id=$charlie_channel AND body='$straggler'")" = "0" ] ||
    die "kicked B straggler leaked to C"
  psql_env b "
    DO \$block\$
    BEGIN
      PERFORM chat_message_send(91001,$bravo_channel,'D5-POST-KICK-$tag');
      RAISE EXCEPTION 'post-kick send unexpectedly succeeded';
    EXCEPTION
      WHEN SQLSTATE 'BZ213' THEN NULL;
    END
    \$block\$;
  " >/dev/null
  psql_env a "
    SELECT federation_room_invite(
      91000,$channel_id,'${DOMAIN[b]}','contact@${DOMAIN[b]}')
  " >/dev/null
  wait_sql_equal b "
    SELECT count(*) FROM chat_channels
     WHERE id=$bravo_channel AND federated_room_removed_at IS NULL
  " 1 "B mirror did not reactivate after re-invite"

  {
    printf 'scope_downgrade_revocation=PASS\n'
    printf 'revocation_advisory=PASS\n'
    printf 'reinvitation_gap_marker=PASS\n'
    printf 'partitioned_kick=PASS\n'
    printf 'straggler_poison=PASS\n'
    printf 'post_kick_send_refusal=BZ213\n'
    printf 'kick_reinvite=PASS\n'
  } | tee "$EVIDENCE_DIR/adversarial.txt"
  printf 'D5_ADVERSARIAL_PASS\n'
}

peer_reset_action() {
  [ -s "$EVIDENCE_DIR/adversarial.txt" ] ||
    die "peer-reset requires the completed adversarial journey"
  local channel_id room_id charlie_channel body
  IFS='|' read -r channel_id room_id <"$EVIDENCE_DIR/room.checkpoint"
  charlie_channel="$(psql_env c \
    "SELECT id FROM chat_channels WHERE federated_room_id='$room_id'")"
  body="D5-POST-PEER-RESET-$(date -u +%Y%m%d%H%M%S)"

  say "Bilateral A/C delete, full transport reap, re-add and clean sequence"
  for env in a c; do
    repair_unambiguous_bootstrap_authority "$env"
    install_mailctl_loopback_name "$env"
    TOKEN[$env]="$(enroll_admin_and_issue_token "$env")"
  done
  upsert_peer a c "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" room false
  upsert_peer c a "$EVIDENCE_DIR/public-anchors/${DOMAIN[a]}.ca.crt" room false
  sleep 3
  [ "$(psql_env a "SELECT federation_peer_delete(91000,'${DOMAIN[c]}')")" = "t" ] ||
    die "A did not delete C"
  [ "$(psql_env c "SELECT federation_peer_delete(91002,'${DOMAIN[a]}')")" = "t" ] ||
    die "C did not delete A"
  for pair in "a:${DOMAIN[c]}" "c:${DOMAIN[a]}"; do
    local env="${pair%%:*}" peer="${pair#*:}"
    [ "$(psql_env "$env" "
      SELECT
        (SELECT count(*) FROM federation_allowlist WHERE peer_domain='$peer')+
        (SELECT count(*) FROM federation_outbox WHERE peer_domain='$peer')+
        (SELECT count(*) FROM federation_peers WHERE peer_domain='$peer')+
        (SELECT count(*) FROM federation_inbox WHERE peer_domain='$peer')+
        (SELECT count(*) FROM federation_inbox_cursor WHERE peer_domain='$peer')
    ")" = "0" ] || die "$env retained transport state for deleted peer $peer"
  done

  upsert_peer a c "$EVIDENCE_DIR/public-anchors/${DOMAIN[c]}.ca.crt" room true
  upsert_peer c a "$EVIDENCE_DIR/public-anchors/${DOMAIN[a]}.ca.crt" room true
  psql_env a "
    SELECT federation_room_invite(
      91000,$channel_id,'${DOMAIN[c]}','contact@${DOMAIN[c]}');
    SELECT chat_message_send(91000,$channel_id,'$body');
  " >/dev/null
  wait_sql_equal c "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$charlie_channel AND body='$body'
       AND federated_origin_domain='${DOMAIN[a]}'
  " 1 "C did not receive room traffic after bilateral clean re-add"
  [ "$(psql_env a "
    SELECT last_seq FROM federation_peers WHERE peer_domain='${DOMAIN[c]}'
  ")" -ge 1 ] || die "A/C clean re-add did not recreate the sequence rail"
  {
    printf 'bilateral_delete=PASS\n'
    printf 'transport_rows_after_delete=0\n'
    printf 'clean_readd=PASS\n'
    printf 'post_readd_room_delivery=PASS\n'
  } | tee "$EVIDENCE_DIR/peer-reset.txt"
  printf 'D5_PEER_RESET_PASS\n'
}

pressure_action() {
  [ -s "$EVIDENCE_DIR/peer-reset.txt" ] ||
    die "pressure requires the completed bilateral peer reset"
  local channel_id room_id i tag
  IFS='|' read -r channel_id room_id <"$EVIDENCE_DIR/room.checkpoint"
  tag="d5-pressure-$(date -u +%Y%m%d%H%M%S)"

  say "Partition C and prove pre-cap warning, park, recover and re-admit"
  psql_env a "
    INSERT INTO system_config(key,value) VALUES
      ('federation.outbox_cap','3'::jsonb),
      ('federation.outbox_warn_pct','80'::jsonb)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
  " >/dev/null
  docker network disconnect "$NETWORK" "${CONTAINER[c]}"
  PARTITIONED_C=1
  sleep 3
  for i in $(seq 1 5); do
    psql_env a \
      "SELECT chat_message_send(91000,$channel_id,'$tag-$i')" >/dev/null
  done
  wait_sql_equal a "
    SELECT count(*) FROM federation_room_members
     WHERE room_id='$room_id' AND member_domain='${DOMAIN[c]}'
       AND parked_at IS NOT NULL AND parked_reason='backpressure'
  " 1 "C did not park after crossing the bounded outbox cap"
  [ "$(psql_env a "
    SELECT (
      (SELECT min(occurred_at) FROM admin_audit_log
        WHERE action='federation.room_member_depth_warn'
          AND occurred_at>statement_timestamp()-interval '5 minutes')
      <
      (SELECT min(occurred_at) FROM admin_audit_log
        WHERE action='federation.room_member_parked'
          AND occurred_at>statement_timestamp()-interval '5 minutes')
    )::int
  ")" = "1" ] || die "depth warning did not precede the backpressure park"
  docker network connect --ip "${IP[c]}" "$NETWORK" "${CONTAINER[c]}"
  PARTITIONED_C=0
  psql_env a "
    DELETE FROM system_config
     WHERE key IN ('federation.outbox_cap','federation.outbox_warn_pct');
    SELECT federation_room_invite(
      91000,$channel_id,'${DOMAIN[c]}','contact@${DOMAIN[c]}');
  " >/dev/null
  wait_sql_equal a "
    SELECT count(*) FROM federation_room_members
     WHERE room_id='$room_id' AND member_domain='${DOMAIN[c]}'
       AND parked_at IS NULL AND left_at IS NULL
  " 1 "C did not recover from park through explicit re-invite"
  {
    printf 'outbox_cap=3\n'
    printf 'depth_warn_before_park=PASS\n'
    printf 'backpressure_park=PASS\n'
    printf 'explicit_reinvite_recovery=PASS\n'
    printf 'temporary_cap_removed=PASS\n'
  } | tee "$EVIDENCE_DIR/pressure.txt"
  printf 'D5_PRESSURE_PASS\n'
}

status_action() {
  local env
  for env in a b c; do
    printf '%s|' "$env"
    psql_env "$env" "
      SELECT jsonb_build_object(
        'toggle',(SELECT enabled FROM feature_toggles WHERE key='feature.federation'),
        'allowlist',(SELECT count(*) FROM federation_allowlist WHERE enabled),
        'peers',(SELECT count(*) FROM federation_peers),
        'outbox',(SELECT count(*) FROM federation_outbox WHERE acked_at IS NULL)
      )
    "
  done
}

cleanup_action() {
  local env
  for env in a b c; do
    psql_env "$env" "
      UPDATE feature_toggles SET enabled=false,updated_at=now()
       WHERE key='feature.federation';
      UPDATE federation_allowlist SET enabled=false,updated_at=now();
    " >/dev/null
    docker exec -i "${CONTAINER[$env]}" bash -s -- "$RUN_PREFIX" <<'INNER'
set -Eeuo pipefail
prefix="$1"
sed -i "/^# ${prefix}-d5-federation-begin$/,/^# ${prefix}-d5-federation-end$/d" \
  /etc/setjoin/config.env
systemctl restart setjoin
INNER
  done
  printf 'D5_CLEANUP_PASS\n'
}

validate
case "$ACTION" in
  (prepare|resume) prepare_action ;;
  (journey) journey_action ;;
  (rotate) rotate_action ;;
  (adversarial) adversarial_action ;;
  (peer-reset) peer_reset_action ;;
  (pressure) pressure_action ;;
  (status) status_action ;;
  (cleanup) cleanup_action ;;
esac
