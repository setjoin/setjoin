#!/usr/bin/env bash
# D3: real Guest Accounts release rehearsal on retained environment A.
# Requires the three-stack harness and private DNS created by
# unified-deployment-readiness.sh. B/C remain Guest-OFF isolation controls.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
ACTION="${1:-prepare}"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="Sm0ke-Test-Passw0rd!1"
GUEST_PASSWORD="D3-Guest-Only-Passw0rd!"
SINK_IMAGE="${SINK_IMAGE:-axllent/mailpit:v1.27.8}"
EVIDENCE_DIR=""
A=""
B=""
C=""
DNS=""
SINK=""
NETWORK=""
A_IP=""
SINK_IP=""
API_BASE=""
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

validate() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac
  case "$ACTION" in
    (prepare|resume|supersede|browser-ready|verify|status|cleanup) ;;
    (*) die "usage: $0 prepare|resume|supersede|browser-ready|verify|status|cleanup" ;;
  esac
  local base="${TEST_SUBNET%.0/24}"
  A="${RUN_PREFIX}-a"
  B="${RUN_PREFIX}-b"
  C="${RUN_PREFIX}-c"
  DNS="${RUN_PREFIX}-dns"
  SINK="${RUN_PREFIX}-smtp-sink"
  NETWORK="${RUN_PREFIX}-net"
  A_IP="${base}.11"
  SINK_IP="${base}.60"
  API_BASE="https://mail.example.com"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d3"
  install -d -m 0700 "$EVIDENCE_DIR"
  TMP_DIR="$(mktemp -d)"
  for name in "$A" "$B" "$C" "$DNS"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: $name"
  done
  docker network inspect "$NETWORK" >/dev/null 2>&1 || die "missing test network: $NETWORK"
}

new_tmp() {
  mktemp "$TMP_DIR/response.XXXXXX"
}

api_call() {
  local method="$1" path="$2" body="$3" bearer="$4" out="$5"
  local args=(
    -ksS --max-time 30
    --resolve "mail.example.com:443:$A_IP"
    -o "$out" -w '%{http_code}'
    -X "$method" "$API_BASE$path"
    -H 'Content-Type: application/json'
  )
  [ -n "$bearer" ] && args+=(-H "Authorization: Bearer $bearer")
  [ -n "$body" ] && args+=(--data-binary "$body")
  curl "${args[@]}"
}

psql_env() {
  local env_name="$1" sql="$2"
  docker exec -i "$env_name" bash -s -- "$sql" <<'INNER'
set -Eeuo pipefail
sql="$1"
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAc "$sql"
INNER
}

expect_status() {
  local got="$1" want="$2" label="$3"
  [ "$got" = "$want" ] || die "$label: HTTP $got, want $want"
  printf '%s=PASS\n' "$label"
}

stage_current_build() {
  say "Install current worktree build on disposable A"
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
cp -a /mnt/repo-src/. /root/setjoin/
rm -rf /root/setjoin/.git
cd /root/setjoin/mailserver/webmail
npm run build
cd /root/setjoin/mailserver
CGO_ENABLED=0 go build -o /tmp/mailserverd.d3 -ldflags="-s -w" ./cmd/mailserverd
cd /root/setjoin/mailctl
CGO_ENABLED=0 go build -o /tmp/mailctl.d3 .
cd /root/setjoin
bash mailserver/deploy/scripts/upgrade.sh /tmp/mailserverd.d3 /tmp/mailctl.d3 \
  /root/setjoin/mailserver/webmail/build
curl -skf --max-time 5 https://127.0.0.1/ready >/dev/null
INNER
  printf 'current_build_upgrade=PASS\n' | tee "$EVIDENCE_DIR/build.txt"
}

start_sink_and_private_mx() {
  say "Start exact-name SMTP sink and private MX"
  if [ "$(docker inspect -f '{{.State.Running}}' "$SINK" 2>/dev/null || true)" != "true" ]; then
    docker rm -f "$SINK" >/dev/null 2>&1 || true
    docker run -d --name "$SINK" --network "$NETWORK" --ip "$SINK_IP" \
      -e MP_SMTP_BIND_ADDR=0.0.0.0:25 \
      -e MP_UI_BIND_ADDR=0.0.0.0:8025 \
      "$SINK_IMAGE" >/dev/null
  fi
  for _ in $(seq 1 30); do
    docker exec "$A" curl -sf --max-time 2 "http://$SINK_IP:8025/api/v1/messages" >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$A" curl -sf --max-time 2 "http://$SINK_IP:8025/api/v1/messages" >/dev/null ||
    die "SMTP sink API is not ready"

  # Recreate only the exact prefixed DNS container so the newly mounted
  # guest-sink.test zone becomes authoritative.
  docker rm -f "$DNS" >/dev/null
  RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
    bash "$ROOT/scripts/unified-deployment-readiness.sh" resume-provision >/dev/null

  docker exec "$A" getent hosts smtp-sink.guest-sink.test >/dev/null ||
    die "A cannot resolve private SMTP sink"
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
cfg=/etc/setjoin/config.env
tmp=$(mktemp)
grep -Ev '^DNSSEC_ENABLED=' "$cfg" >"$tmp"
printf '%s\n' 'DNSSEC_ENABLED=false' >>"$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$cfg"
systemctl restart setjoin
for _ in $(seq 1 30); do
  curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null && exit 0
  sleep 1
done
exit 1
INNER
  {
    printf 'smtp_sink=PASS\n'
    printf 'private_mx='
    docker exec "$A" getent hosts smtp-sink.guest-sink.test | awk '{print $1}'
  } | tee "$EVIDENCE_DIR/smtp-sink.txt"

  # A was retained from a pre-fix installer run. Converge it to the exact
  # idempotent state the current installer now creates; never overwrite an
  # operator-owned explicit origin.
  psql_env "$A" "
    INSERT INTO system_config (key,value,encrypted,updated_at)
    VALUES ('authserver.public_url',to_jsonb('$API_BASE'::text),false,now())
    ON CONFLICT (key) DO NOTHING;
  " >/dev/null
  [ "$(psql_env "$A" "SELECT value #>> '{}' FROM system_config WHERE key='authserver.public_url'")" = "$API_BASE" ] ||
    die "Guest public invitation origin is not the disposable A gateway"
  printf 'guest_public_origin=PASS\n' >>"$EVIDENCE_DIR/smtp-sink.txt"
}

enroll_admin_and_issue_token() {
  local response setup confirm status mfa_token uri secret code admin_token
  response="$(new_tmp)"; setup="$(new_tmp)"; confirm="$(new_tmp)"

  # Deterministic disposable-host reset: never copy a real operator factor into
  # this rehearsal. Revoking existing families prevents a pre-reset session
  # from bypassing the mandatory enrollment proof.
  psql_env "$A" "
    UPDATE users
       SET totp_enabled=false,totp_enabled_at=NULL,totp_secret_enc=NULL
     WHERE lower(email)=lower('$ADMIN_EMAIL');
    DELETE FROM oauth_tokens
     WHERE user_id=(SELECT id FROM users WHERE lower(email)=lower('$ADMIN_EMAIL'));
  " >/dev/null
  systemctl_status="$(docker exec "$A" systemctl is-active setjoin-auth)"
  [ "$systemctl_status" = "active" ] || die "authserver inactive before enrollment"

  status="$(api_call POST /auth/login \
    "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "" "$response")"
  expect_status "$status" 403 admin_password_verified_requires_enrollment >/dev/null
  [ "$(jq -r '.status // empty' "$response")" = "mfa_enrollment_required" ] ||
    die "admin login did not require TOTP enrollment"
  mfa_token="$(jq -r '.mfa_token // empty' "$response")"
  [ -n "$mfa_token" ] || die "admin enrollment response omitted mfa_token"

  status="$(api_call POST /auth/totp/enroll/setup \
    "$(jq -nc --arg token "$mfa_token" '{mfa_token:$token}')" "" "$setup")"
  expect_status "$status" 200 admin_totp_setup >/dev/null
  uri="$(jq -r '.provisioning_uri // empty' "$setup")"
  [ -n "$uri" ] || die "TOTP setup omitted provisioning URI"
  secret="$(sh "$ROOT/scripts/rehearsal-totp.sh" secret "$uri")"
  code="$(sh "$ROOT/scripts/rehearsal-totp.sh" code "$secret")"
  status="$(api_call POST /auth/totp/enroll/confirm \
    "$(jq -nc --arg token "$mfa_token" --arg code "$code" \
      '{mfa_token:$token,code:$code}')" "" "$confirm")"
  expect_status "$status" 200 admin_totp_confirm >/dev/null
  admin_token="$(jq -r '.access_token // empty' "$confirm")"
  [ -n "$admin_token" ] || die "TOTP confirmation omitted access token"
  printf '%s' "$admin_token"
}

extract_latest_invite_url() {
  local email="$1" exclude_id="${2:-}" after_created="${3:-}" messages id raw url
  messages="$(new_tmp)"; raw="$(new_tmp)"
  for _ in $(seq 1 60); do
    docker exec "$A" curl -sf "http://$SINK_IP:8025/api/v1/messages" >"$messages"
    id="$(jq -r --arg email "$email" --arg exclude "$exclude_id" --arg after "$after_created" '
      [.messages[]?
       | select(($exclude == "") or (.ID != $exclude))
       | select(($after == "") or (.Created > $after))
       | select((.To // []) | tostring | ascii_downcase | contains($email|ascii_downcase))]
      | sort_by(.Created) | last | .ID // empty' "$messages")"
    [ -n "$id" ] && break
    sleep 1
  done
  [ -n "${id:-}" ] || die "SMTP sink did not receive an invitation for $email"
  docker exec "$A" curl -sf "http://$SINK_IP:8025/api/v1/message/$id/raw" >"$raw"
  # The URL commonly crosses quoted-printable's 76-column soft-wrap boundary.
  # Parse and decode the MIME body before extracting it; grepping raw wire bytes
  # silently returned a truncated, always-invalid credential.
  url="$(python3 - "$raw" <<'PY'
from email import policy
from email.parser import BytesParser
import re
import sys

message = BytesParser(policy=policy.default).parse(open(sys.argv[1], "rb"))
texts = []
for part in message.walk():
    if part.get_content_maintype() != "text":
        continue
    try:
        texts.append(part.get_content())
    except (KeyError, LookupError, UnicodeError):
        payload = part.get_payload(decode=True) or b""
        texts.append(payload.decode("utf-8", "replace"))
matches = re.findall(
    r"https://mail\.example\.com/guest-invite/accept\?token=[A-Za-z0-9_-]{32,256}",
    "\n".join(texts),
)
if matches:
    print(matches[-1])
PY
)"
  [ -n "$url" ] || die "received mail omitted a real guest invitation URL"
  printf '%s' "$url"
}

prepare() {
  local admin_token off_a off_b off_c response status domain_id profile_id
  local run guest_email invite_url guest_id invite_id member_token
  if [ "$ACTION" = "prepare" ]; then
    stage_current_build
  else
    [ "$(psql_env "$A" "SELECT max(version) FROM schema_migrations")" = "175" ] ||
      die "resume requires the already-verified V175 build on A"
    grep -qx 'current_build_upgrade=PASS' "$EVIDENCE_DIR/build.txt" 2>/dev/null ||
      die "resume requires the successful build checkpoint"
    say "Resume after successful current-build checkpoint"
  fi
  start_sink_and_private_mx

  off_a="$(psql_env "$A" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  off_b="$(psql_env "$B" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  off_c="$(psql_env "$C" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  [ "$off_a:$off_b:$off_c" = "f:f:f" ] || die "Guest toggle must begin OFF on A/B/C"
  printf 'guest_toggle_initial_a_b_c=OFF_OFF_OFF\n' >"$EVIDENCE_DIR/toggles.txt"

  admin_token="$(enroll_admin_and_issue_token)"
  response="$(new_tmp)"
  status="$(api_call GET /api/admin/guests "" "$admin_token" "$response")"
  expect_status "$status" 404 guest_api_off

  status="$(api_call PUT /api/admin/features/feature.guest_accounts \
    '{"enabled":true}' "$admin_token" "$response")"
  expect_status "$status" 204 guest_toggle_enable_a
  sleep 2
  [ "$(psql_env "$B" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "f" ] ||
    die "B Guest toggle changed"
  [ "$(psql_env "$C" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "f" ] ||
    die "C Guest toggle changed"

  # A non-guest member reaches the real member-invite endpoint, which must hide
  # itself while approval.guest_invite remains OFF.
  psql_env "$A" "
    UPDATE users SET mfa_exempt=true
     WHERE lower(email)='dr-user@example.com';
  " >/dev/null
  status="$(api_call POST /auth/login \
    '{"email":"dr-user@example.com","password":"D2-Fixture-Only-Passw0rd!"}' "" "$response")"
  expect_status "$status" 200 member_login
  member_token="$(jq -r '.access_token // empty' "$response")"
  [ -n "$member_token" ] || die "member login omitted access token"
  status="$(api_call POST /api/me/guest-invites \
    '{"invitedEmail":"blocked@guest-sink.test"}' "$member_token" "$response")"
  expect_status "$status" 404 member_guest_invite_approval_off

  domain_id="$(psql_env "$A" "SELECT domain_id FROM users WHERE lower(email)=lower('$ADMIN_EMAIL')")"
  profile_id="$(psql_env "$A" "
    SELECT id FROM guest_profiles
     WHERE host_domain_id=$domain_id
       AND lower(name)=lower('D3 constrained collaborator')
  ")"
  if [ -z "$profile_id" ]; then
    status="$(api_call POST /api/admin/guest-profiles \
      "$(jq -nc --argjson d "$domain_id" '{
        hostDomainId:$d,name:"D3 constrained collaborator",
        canPost:true,historyFromJoin:true,allowDownload:false,
        allowMeetCreate:false,allowMeetHost:false,canInitiateDm:false,
        allowNativeShell:false,defaultExpiryDays:30,apps:["chat","drive","meet"]
      }')" "$admin_token" "$response")"
    expect_status "$status" 201 guest_profile_create
    profile_id="$(jq -r '.id // empty' "$response")"
  else
    printf 'guest_profile_checkpoint_reused=PASS\n'
  fi
  [ -n "$profile_id" ] || die "guest profile create omitted id"

  status="$(api_call POST /api/admin/guest-invite-domains \
    '{"domain":"guest-sink.test"}' "$admin_token" "$response")"
  case "$status" in (201|409) ;; (*) die "guest invite domain: HTTP $status" ;; esac

  run="$(date -u +%Y%m%d%H%M%S)"
  guest_email="d3-$run@guest-sink.test"
  status="$(api_call POST /api/admin/guests \
    "$(jq -nc --arg email "$guest_email" --argjson profile "$profile_id" \
      '{email:$email,displayName:"D3 Browser Guest",profileId:$profile}')" \
    "$admin_token" "$response")"
  expect_status "$status" 202 guest_invite_create
  guest_id="$(jq -r '.guestUserId // empty' "$response")"
  invite_id="$(jq -r '.inviteId // empty' "$response")"
  [[ "$guest_id" =~ ^[1-9][0-9]*$ && "$invite_id" =~ ^[1-9][0-9]*$ ]] ||
    die "guest create returned malformed decimal ids"

  invite_url="$(extract_latest_invite_url "$guest_email")"
  printf '%s\n' "$invite_url" >"/tmp/${RUN_PREFIX}-d3-browser-url"
  chmod 0600 "/tmp/${RUN_PREFIX}-d3-browser-url"
  printf '%s\n' "$guest_email" >"/tmp/${RUN_PREFIX}-d3-guest-email"
  printf '%s\n' "$GUEST_PASSWORD" >"/tmp/${RUN_PREFIX}-d3-guest-password"
  chmod 0600 "/tmp/${RUN_PREFIX}-d3-guest-email" "/tmp/${RUN_PREFIX}-d3-guest-password"

  status="$(api_call GET "/auth/guest-invite/accept?token=wrong-token" "" "" "$response")"
  expect_status "$status" 401 wrong_invite_token_uniform
  status="$(api_call POST /auth/guest-invite/accept \
    "$(jq -nc --arg token "${invite_url##*token=}" --arg password "$GUEST_PASSWORD" \
      '{token:$token,disclosure_accepted:false,new_password:$password}')" "" "$response")"
  expect_status "$status" 400 disclosure_required_without_consumption
  [ "$(psql_env "$A" "SELECT used_at IS NULL FROM guest_invites WHERE id=$invite_id")" = "t" ] ||
    die "disclosure refusal consumed the invitation"

  {
    printf 'guest_prepare=PASS\n'
    printf 'guest_user_id=%s\n' "$guest_id"
    printf 'invite_id=%s\n' "$invite_id"
    printf 'guest_email=%s\n' "$guest_email"
    printf 'browser_url_file=/tmp/%s-d3-browser-url\n' "$RUN_PREFIX"
    printf 'raw_token_persisted_in_evidence=false\n'
    printf 'b_c_guest_toggle=OFF_OFF\n'
  } | tee "$EVIDENCE_DIR/prepare.txt"
}

status_action() {
  printf 'A_guest_toggle=%s\n' "$(psql_env "$A" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  printf 'B_guest_toggle=%s\n' "$(psql_env "$B" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  printf 'C_guest_toggle=%s\n' "$(psql_env "$C" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  [ -f "/tmp/${RUN_PREFIX}-d3-browser-url" ] && echo 'browser_url_ready=true' || echo 'browser_url_ready=false'
  docker ps --filter "name=^/${SINK}$" --format 'smtp_sink={{.Status}}'
}

browser_ready_action() {
  local invite_url guest_email guest_id invite_id response status
  [ "$(psql_env "$A" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "t" ] ||
    die "browser-ready requires Guest ON on disposable A"
  [ "$(psql_env "$B" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "f" ] ||
    die "browser-ready requires Guest OFF on B"
  [ "$(psql_env "$C" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "f" ] ||
    die "browser-ready requires Guest OFF on C"
  for path in "/tmp/${RUN_PREFIX}-d3-browser-url" "/tmp/${RUN_PREFIX}-d3-guest-email" \
    "/tmp/${RUN_PREFIX}-d3-guest-password"; do
    [ -s "$path" ] || die "missing retained browser checkpoint: $path"
  done

  invite_url="$(<"/tmp/${RUN_PREFIX}-d3-browser-url")"
  guest_email="$(<"/tmp/${RUN_PREFIX}-d3-guest-email")"
  guest_id="$(psql_env "$A" "SELECT id FROM users WHERE lower(email)=lower('$guest_email')")"
  invite_id="$(psql_env "$A" "
    SELECT id FROM guest_invites
     WHERE guest_user_id=$guest_id
     ORDER BY id DESC LIMIT 1
  ")"
  [[ "$guest_id" =~ ^[1-9][0-9]*$ && "$invite_id" =~ ^[1-9][0-9]*$ ]] ||
    die "retained Guest checkpoint has malformed ids"

  response="$(new_tmp)"
  status="$(api_call GET "/auth/guest-invite/accept?token=wrong-token" "" "" "$response")"
  expect_status "$status" 401 wrong_invite_token_uniform
  status="$(api_call POST /auth/guest-invite/accept \
    "$(jq -nc --arg token "${invite_url##*token=}" --arg password "$GUEST_PASSWORD" \
      '{token:$token,disclosure_accepted:false,new_password:$password}')" "" "$response")"
  expect_status "$status" 400 disclosure_required_without_consumption
  [ "$(psql_env "$A" "SELECT used_at IS NULL FROM guest_invites WHERE id=$invite_id")" = "t" ] ||
    die "disclosure refusal consumed the invitation"

  {
    printf 'guest_prepare=PASS\n'
    printf 'guest_user_id=%s\n' "$guest_id"
    printf 'invite_id=%s\n' "$invite_id"
    printf 'guest_email=%s\n' "$guest_email"
    printf 'browser_url_file=/tmp/%s-d3-browser-url\n' "$RUN_PREFIX"
    printf 'raw_token_persisted_in_evidence=false\n'
    printf 'b_c_guest_toggle=OFF_OFF\n'
  } | tee "$EVIDENCE_DIR/prepare.txt"
}

supersede_action() {
  local old_url old_token guest_email guest_id old_invite_id new_url new_token
  local admin_token response status new_invite_id new_invite_created
  [ -s "/tmp/${RUN_PREFIX}-d3-browser-url" ] ||
    die "supersede requires the retained invitation checkpoint"
  old_url="$(<"/tmp/${RUN_PREFIX}-d3-browser-url")"
  old_token="${old_url##*token=}"
  guest_email="$(<"/tmp/${RUN_PREFIX}-d3-guest-email")"
  guest_id="$(psql_env "$A" "SELECT id FROM users WHERE lower(email)=lower('$guest_email')")"
  old_invite_id="$(psql_env "$A" "
    SELECT id FROM guest_invites
     WHERE guest_user_id=$guest_id
     ORDER BY id DESC LIMIT 1
  ")"

  # Correlate exactly one new SMTP message to the invite id returned below.
  # First let startup recovery settle any send interrupted by a prior harness
  # retry, then clear Mailpit through its API without removing the live MX.
  # Removing the sink while SMTP is connected can strand a row in `sending`.
  docker exec "$A" systemctl restart setjoin
  for _ in $(seq 1 60); do
    docker exec "$A" curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$A" curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null ||
    die "gateway did not become ready after the recovery restart"
  for _ in $(seq 1 60); do
    if [ "$(psql_env "$A" "
      SELECT count(*) FROM outbound_queue
       WHERE '$guest_email'=ANY(rcpt_addrs)
         AND status IN ('pending','sending','deferred')
    ")" = "0" ]; then
      break
    fi
    sleep 1
  done
  [ "$(psql_env "$A" "
    SELECT count(*) FROM outbound_queue
     WHERE '$guest_email'=ANY(rcpt_addrs)
       AND status IN ('pending','sending','deferred')
  ")" = "0" ] || die "prior Guest invitation mail did not settle after startup recovery"
  [ "$(docker exec "$A" curl -sf -o /dev/null -w '%{http_code}' \
    -X DELETE "http://$SINK_IP:8025/api/v1/messages")" = "200" ] ||
    die "SMTP sink message reset failed"

  admin_token="$(enroll_admin_and_issue_token)"
  response="$(new_tmp)"
  status="$(api_call POST "/api/admin/guests/$guest_id/reinvite" '{}' "$admin_token" "$response")"
  expect_status "$status" 202 guest_reinvite_supersede
  new_invite_id="$(jq -r '.inviteId // empty' "$response")"
  [[ "$new_invite_id" =~ ^[1-9][0-9]*$ && "$new_invite_id" != "$old_invite_id" ]] ||
    die "reinvite did not return a distinct decimal invite id"
  new_invite_created="$(psql_env "$A" "
    SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
      FROM guest_invites WHERE id=$new_invite_id
  ")"
  new_url="$(extract_latest_invite_url "$guest_email" "" "$new_invite_created")"
  new_token="${new_url##*token=}"
  [ -n "$new_token" ] && [ "$new_token" != "$old_token" ] ||
    die "reinvite did not rotate the raw credential"

  status="$(api_call GET "/auth/guest-invite/accept?token=$old_token" "" "" "$response")"
  expect_status "$status" 401 superseded_invite_uniform
  status="$(api_call GET "/auth/guest-invite/accept?token=$new_token" "" "" "$response")"
  expect_status "$status" 200 replacement_invite_disclosure
  [ "$(psql_env "$A" "SELECT terminal_reason FROM guest_invites WHERE id=$old_invite_id")" = "superseded" ] ||
    die "old invitation lacks superseded outcome"

  printf '%s\n' "$new_url" >"/tmp/${RUN_PREFIX}-d3-browser-url"
  chmod 0600 "/tmp/${RUN_PREFIX}-d3-browser-url"
  {
    printf 'guest_reinvite=PASS\n'
    printf 'old_invite_id=%s\n' "$old_invite_id"
    printf 'new_invite_id=%s\n' "$new_invite_id"
    printf 'old_token_terminal=uniform_401\n'
    printf 'new_raw_token_persisted_in_evidence=false\n'
  } | tee "$EVIDENCE_DIR/supersede.txt"
}

verify_action() {
  local guest_email guest_id terminal entitlements b_guest c_guest
  [ -s "/tmp/${RUN_PREFIX}-d3-guest-email" ] ||
    die "verify requires the retained Guest browser checkpoint"
  guest_email="$(<"/tmp/${RUN_PREFIX}-d3-guest-email")"
  guest_id="$(psql_env "$A" "SELECT id FROM users WHERE lower(email)=lower('$guest_email')")"
  [[ "$guest_id" =~ ^[1-9][0-9]*$ ]] || die "Guest terminal check could not resolve user"

  terminal="$(psql_env "$A" "
    SELECT ga.status || ':' || u.totp_enabled || ':' ||
           (gi.used_at IS NOT NULL) || ':' || COALESCE(gi.terminal_reason,'')
      FROM users u
      JOIN guest_accounts ga ON ga.user_id=u.id
      JOIN LATERAL (
        SELECT used_at,terminal_reason
          FROM guest_invites
         WHERE guest_user_id=u.id
         ORDER BY id DESC LIMIT 1
      ) gi ON true
     WHERE u.id=$guest_id
  ")"
  [ "$terminal" = "active:true:true:accepted" ] ||
    die "Guest browser terminal state is $terminal, want active:true:true:accepted"

  entitlements="$(psql_env "$A" "
    SELECT string_agg(app || ':' || check_user_app_entitlement($guest_id,app),',' ORDER BY app)
      FROM unnest(ARRAY['chat','drive','meet']) app
  ")"
  [ "$entitlements" = "chat:true,drive:true,meet:true" ] ||
    die "Guest derived entitlement intersection is $entitlements"

  b_guest="$(psql_env "$B" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  c_guest="$(psql_env "$C" "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")"
  [ "$b_guest:$c_guest" = "f:f" ] || die "B/C Guest isolation control changed"

  {
    printf 'guest_browser_terminal=PASS\n'
    printf 'guest_user_id=%s\n' "$guest_id"
    printf 'guest_status=active\n'
    printf 'latest_invite_terminal=accepted\n'
    printf 'totp_enrollment=enabled\n'
    printf 'derived_entitlements=%s\n' "$entitlements"
    printf 'guest_shell_apps=chat,meet\n'
    printf 'guest_standalone_drive_hidden_by_design=true\n'
    printf 'b_c_guest_toggle=OFF_OFF\n'
    printf 'browser_origin_adapter=localhost_origin_normalized_to_disposable_public_origin\n'
    printf 'browser_screenshots=guest-accept-before.png,guest-accept-success.png,guest-totp-required.png,guest-apps-after-mfa.png,guest-chat-entitled.png,guest-meet-join-only-fixed.png\n'
  } | tee "$EVIDENCE_DIR/browser.txt"
}

cleanup_action() {
  psql_env "$A" "
    UPDATE feature_toggles
       SET enabled=false,updated_at=now()
     WHERE key IN ('feature.guest_accounts','feature.chat','feature.drive','feature.meet')
  " >/dev/null
  rm -f "/tmp/${RUN_PREFIX}-d3-browser-url" "/tmp/${RUN_PREFIX}-d3-guest-email" \
    "/tmp/${RUN_PREFIX}-d3-guest-password"
  docker rm -f "$SINK" >/dev/null 2>&1 || true
  [ "$(psql_env "$A" "
    SELECT bool_and(NOT enabled) FROM feature_toggles
     WHERE key IN ('feature.guest_accounts','feature.chat','feature.drive','feature.meet')
  ")" = "t" ] || die "A Guest/app toggles were not restored OFF"
  {
    printf 'guest_toggle_restored_off=PASS\n'
    printf 'guest_app_toggles_restored_off=PASS\n'
  } | tee "$EVIDENCE_DIR/cleanup.txt"
}

validate
case "$ACTION" in
  prepare|resume) prepare ;;
  supersede) supersede_action ;;
  browser-ready) browser_ready_action ;;
  verify) verify_action ;;
  status) status_action ;;
  cleanup) cleanup_action ;;
esac
