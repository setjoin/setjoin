#!/usr/bin/env bash
# D4: Identity Model deployment rehearsal on retained environment A.
# A real, TLS-only OpenLDAP server runs as one exact-prefix Docker resource on
# the shared private network. The 24-hour observation is sampled by a resumable
# host-side watcher; PostgreSQL remains the authoritative per-sync evidence.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
ACTION="${1:-prepare}"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="Sm0ke-Test-Passw0rd!1"
SOURCE_KEY="ldap:d4-corp"
LDAP_BASE_DN="dc=d4,dc=test"
LDAP_BIND_DN="cn=Manager,$LDAP_BASE_DN"
LDAP_BASE_IMAGE="${LDAP_BASE_IMAGE:-alpine:3.24}"
EVIDENCE_DIR=""
PRIVATE_DIR=""
A=""
B=""
C=""
DNS=""
LDAP=""
NETWORK=""
A_IP=""
LDAP_IP=""
API_BASE="https://mail.example.com"
TMP_DIR=""
ADMIN_TOKEN=""

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
    (prepare|resume|observe|status|verify-window|cleanup) ;;
    (*) die "usage: $0 prepare|resume|observe|status|verify-window|cleanup" ;;
  esac
  local base="${TEST_SUBNET%.0/24}"
  A="${RUN_PREFIX}-a"
  B="${RUN_PREFIX}-b"
  C="${RUN_PREFIX}-c"
  DNS="${RUN_PREFIX}-dns"
  LDAP="${RUN_PREFIX}-ldap"
  NETWORK="${RUN_PREFIX}-net"
  A_IP="${base}.11"
  LDAP_IP="${base}.61"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d4"
  PRIVATE_DIR="$EVIDENCE_DIR/private"
  install -d -m 0700 "$EVIDENCE_DIR" "$PRIVATE_DIR"
  TMP_DIR="$(mktemp -d)"
  for name in "$A" "$B" "$C" "$DNS"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: $name"
  done
  docker network inspect "$NETWORK" >/dev/null 2>&1 ||
    die "missing test network: $NETWORK"
}

new_tmp() {
  mktemp "$TMP_DIR/response.XXXXXX"
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

api_call_retry_429() {
  local method="$1" path="$2" body="$3" bearer="$4" out="$5"
  local status attempt
  for attempt in 1 2 3 4 5; do
    status="$(api_call "$method" "$path" "$body" "$bearer" "$out")"
    if [ "$status" != "429" ]; then
      printf '%s' "$status"
      return
    fi
    [ "$attempt" -lt 5 ] || break
    sleep 20
  done
  printf '%s' "$status"
}

expect_status() {
  local got="$1" want="$2" label="$3"
  [ "$got" = "$want" ] || die "$label: HTTP $got, want $want"
  printf '%s=PASS\n' "$label"
}

enroll_admin_and_issue_token() {
  local response setup confirm status mfa_token uri secret code token
  response="$(new_tmp)"
  setup="$(new_tmp)"
  confirm="$(new_tmp)"
  psql_env "$A" "
    UPDATE users
       SET totp_enabled=false,totp_enabled_at=NULL,totp_secret_enc=NULL
     WHERE lower(email)=lower('$ADMIN_EMAIL');
    DELETE FROM oauth_tokens
     WHERE user_id=(SELECT id FROM users WHERE lower(email)=lower('$ADMIN_EMAIL'));
    DELETE FROM rate_limit_counters
     WHERE key='auth:http:127.0.0.1';
  " >/dev/null
  status="$(api_call_retry_429 POST /auth/login \
    "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "" "$response")"
  expect_status "$status" 403 identity_admin_enrollment_required >/dev/null
  mfa_token="$(jq -r '.mfa_token // empty' "$response")"
  [ -n "$mfa_token" ] || die "admin enrollment response omitted mfa_token"
  status="$(api_call_retry_429 POST /auth/totp/enroll/setup \
    "$(jq -nc --arg token "$mfa_token" '{mfa_token:$token}')" "" "$setup")"
  expect_status "$status" 200 identity_admin_totp_setup >/dev/null
  uri="$(jq -r '.provisioning_uri // empty' "$setup")"
  secret="$(sh "$ROOT/scripts/rehearsal-totp.sh" secret "$uri")"
  code="$(sh "$ROOT/scripts/rehearsal-totp.sh" code "$secret")"
  status="$(api_call_retry_429 POST /auth/totp/enroll/confirm \
    "$(jq -nc --arg token "$mfa_token" --arg code "$code" \
      '{mfa_token:$token,code:$code}')" "" "$confirm")"
  expect_status "$status" 200 identity_admin_totp_confirm >/dev/null
  token="$(jq -r '.access_token // empty' "$confirm")"
  [ -n "$token" ] || die "TOTP confirmation omitted access token"
  printf '%s' "$token"
}

mailctl_exec() {
  [ -n "$ADMIN_TOKEN" ] || die "mailctl token is unavailable"
  docker exec \
    -e MAILCTL_SERVER="$API_BASE" \
    -e MAILCTL_TOKEN="$ADMIN_TOKEN" \
    -e SSL_CERT_FILE=/etc/setjoin/tls/server.pem \
    "$A" /opt/setjoin/mailctl "$@"
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
CGO_ENABLED=0 go build -o /tmp/mailserverd.d4 -ldflags="-s -w" ./cmd/mailserverd
cd /root/setjoin/mailctl
CGO_ENABLED=0 go build -o /tmp/mailctl.d4 .
cd /root/setjoin
bash mailserver/deploy/scripts/upgrade.sh /tmp/mailserverd.d4 /tmp/mailctl.d4 \
  /root/setjoin/mailserver/webmail/build
curl -skf --max-time 5 https://127.0.0.1/ready >/dev/null
INNER
  printf 'current_build_upgrade=PASS\n' | tee "$EVIDENCE_DIR/build.txt"
}

refresh_mailctl_build() {
  say "Refresh mailctl before resumed orchestration"
  docker exec -i "$A" bash -s <<'INNER'
set -Eeuo pipefail
cp -a /mnt/repo-src/mailctl/. /root/setjoin/mailctl/
cd /root/setjoin/mailctl
CGO_ENABLED=0 go build -o /tmp/mailctl.d4-resume .
install -m 0755 /tmp/mailctl.d4-resume /opt/setjoin/mailctl
INNER
  docker exec "$A" /opt/setjoin/mailctl version \
    >"$EVIDENCE_DIR/mailctl-resume-version.txt"
}

install_mailctl_loopback_name() {
  docker exec -i "$A" bash -s -- "$RUN_PREFIX" <<'INNER'
set -Eeuo pipefail
prefix="$1"
marker="# ${prefix}-d4-mailctl"
if ! grep -Fq "$marker" /etc/hosts; then
  printf '127.0.0.1 mail.example.com %s\n' "$marker" >>/etc/hosts
fi
getent hosts mail.example.com >/dev/null
INNER
}

write_ldap_build_context() {
  local build="$EVIDENCE_DIR/ldap-build"
  install -d -m 0700 "$build" "$build/data"
  if [ ! -s "$PRIVATE_DIR/ca-key.pem" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
      -out "$PRIVATE_DIR/ca-key.pem" >/dev/null 2>&1
    openssl req -x509 -new -sha256 -days 3 \
      -key "$PRIVATE_DIR/ca-key.pem" \
      -subj "/CN=${RUN_PREFIX} D4 LDAP CA" \
      -out "$EVIDENCE_DIR/ldap-ca.pem"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
      -out "$PRIVATE_DIR/ldap-key.pem" >/dev/null 2>&1
    openssl req -new -sha256 -key "$PRIVATE_DIR/ldap-key.pem" \
      -subj "/CN=ldap.org-b.test" -out "$PRIVATE_DIR/ldap.csr"
    printf '%s\n' \
      'subjectAltName=DNS:ldap.org-b.test' \
      'extendedKeyUsage=serverAuth' \
      'keyUsage=digitalSignature,keyEncipherment' >"$PRIVATE_DIR/ldap.ext"
    openssl x509 -req -sha256 -days 3 \
      -in "$PRIVATE_DIR/ldap.csr" \
      -CA "$EVIDENCE_DIR/ldap-ca.pem" -CAkey "$PRIVATE_DIR/ca-key.pem" \
      -CAcreateserial -extfile "$PRIVATE_DIR/ldap.ext" \
      -out "$EVIDENCE_DIR/ldap.pem" >/dev/null 2>&1
    chmod 0600 "$PRIVATE_DIR"/*
    chmod 0644 "$EVIDENCE_DIR/ldap-ca.pem" "$EVIDENCE_DIR/ldap.pem"
  fi
  if [ ! -s "$PRIVATE_DIR/bind-password" ]; then
    openssl rand -base64 32 | tr -d '\n' >"$PRIVATE_DIR/bind-password"
    chmod 0600 "$PRIVATE_DIR/bind-password"
  fi
  cat >"$build/Dockerfile" <<'EOF'
ARG ALPINE_REF=alpine:3.24
FROM ${ALPINE_REF}
RUN apk add --no-cache openldap openldap-clients openldap-back-mdb
CMD ["slapd","-d","0","-f","/config/slapd.conf","-h","ldaps://0.0.0.0:636/"]
EOF
  cat >"$build/seed.ldif" <<'EOF'
dn: dc=d4,dc=test
objectClass: dcObject
objectClass: organization
dc: d4
o: Setjoin D4 Directory

dn: ou=People,dc=d4,dc=test
objectClass: organizationalUnit
ou: People

dn: uid=d4-alice,ou=People,dc=d4,dc=test
objectClass: inetOrgPerson
uid: d4-alice
cn: D4 Alice
sn: Alice
givenName: D4
displayName: D4 Alice
mail: d4-alice@example.com
telephoneNumber: +1-555-0401

dn: uid=d4-bob,ou=People,dc=d4,dc=test
objectClass: inetOrgPerson
uid: d4-bob
cn: D4 Bob
sn: Bob
givenName: D4
displayName: D4 Bob
mail: d4-bob@example.com
telephoneNumber: +1-555-0402
manager: uid=d4-alice,ou=People,dc=d4,dc=test
EOF
}

start_tls_ldap() {
  say "Start isolated TLS-only LDAP lifecycle authority"
  local build="$EVIDENCE_DIR/ldap-build"
  local image="${RUN_PREFIX}-ldap:v1"
  local base_ref root_hash
  docker pull "$LDAP_BASE_IMAGE" >/dev/null
  base_ref="$(docker image inspect "$LDAP_BASE_IMAGE" \
    --format '{{index .RepoDigests 0}}')"
  [ -n "$base_ref" ] || die "LDAP base image has no immutable digest"
  write_ldap_build_context
  docker build --pull=false --build-arg "ALPINE_REF=$base_ref" \
    -t "$image" "$build" >/dev/null
  root_hash="$(docker run --rm \
    -v "$PRIVATE_DIR/bind-password:/run/bind-password:ro" \
    "$image" slappasswd -T /run/bind-password)"
  [ -n "$root_hash" ] || die "LDAP root password hash generation failed"
  cat >"$build/slapd.conf" <<EOF
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
pidfile /run/openldap/slapd.pid
argsfile /run/openldap/slapd.args
modulepath /usr/lib/openldap
moduleload back_mdb
TLSCertificateFile /certs/ldap.pem
TLSCertificateKeyFile /certs/ldap-key.pem
TLSCACertificateFile /certs/ca.pem
TLSProtocolMin 3.3
database mdb
maxsize 1073741824
suffix "$LDAP_BASE_DN"
rootdn "$LDAP_BIND_DN"
rootpw $root_hash
directory /var/lib/openldap/openldap-data
index objectClass eq
index entryUUID eq
EOF
  chmod 0600 "$build/slapd.conf"
  docker rm -f "$LDAP" >/dev/null 2>&1 || true
  find "$build/data" -mindepth 1 -delete
  docker run --rm \
    -v "$build:/config:ro" \
    -v "$build/data:/var/lib/openldap/openldap-data" \
    "$image" slapadd -f /config/slapd.conf -l /config/seed.ldif
  docker run -d --name "$LDAP" --network "$NETWORK" --ip "$LDAP_IP" \
    --network-alias ldap.org-b.test \
    -v "$build/slapd.conf:/config/slapd.conf:ro" \
    -v "$build/data:/var/lib/openldap/openldap-data" \
    -v "$EVIDENCE_DIR/ldap.pem:/certs/ldap.pem:ro" \
    -v "$PRIVATE_DIR/ldap-key.pem:/certs/ldap-key.pem:ro" \
    -v "$EVIDENCE_DIR/ldap-ca.pem:/certs/ca.pem:ro" \
    "$image" >/dev/null
  for _ in $(seq 1 30); do
    if docker exec "$A" timeout 3 openssl s_client \
      -connect ldap.org-b.test:636 -servername ldap.org-b.test \
      -CAfile "/usr/local/share/ca-certificates/${RUN_PREFIX}-d4-ldap.crt" \
      </dev/null >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  docker exec "$A" timeout 3 openssl s_client \
    -connect ldap.org-b.test:636 -servername ldap.org-b.test \
    -CAfile "/usr/local/share/ca-certificates/${RUN_PREFIX}-d4-ldap.crt" \
    </dev/null >/dev/null 2>&1 ||
    die "A could not complete a verified TLS handshake with isolated LDAP"
  {
    printf 'ldap_container=%s\n' "$LDAP"
    printf 'ldap_ip=%s\n' "$LDAP_IP"
    printf 'ldap_base_image=%s\n' "$base_ref"
    openssl x509 -in "$EVIDENCE_DIR/ldap.pem" -noout \
      -subject -issuer -serial -dates -ext subjectAltName
  } >"$EVIDENCE_DIR/ldap-manifest.txt"
}

repair_dns_and_install_ldap_ca() {
  docker rm -f "$DNS" >/dev/null
  RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
    bash "$ROOT/scripts/unified-deployment-readiness.sh" resume-provision >/dev/null
  docker cp "$EVIDENCE_DIR/ldap-ca.pem" \
    "$A:/usr/local/share/ca-certificates/${RUN_PREFIX}-d4-ldap.crt"
  docker exec "$A" update-ca-certificates >/dev/null
  docker exec "$A" getent hosts ldap.org-b.test |
    tee "$EVIDENCE_DIR/ldap-dns.txt"
}

run_upgrade_preflight_and_backfill() {
  say "Run identity preflight and bounded legacy backfill"
  local preflight="$EVIDENCE_DIR/preflight.json"
  local job="$EVIDENCE_DIR/backfill-job.json"
  local checksum job_id
  if [ -s "$EVIDENCE_DIR/backfill-terminal.json" ] &&
     [ "$(jq -r '.state // empty' "$EVIDENCE_DIR/backfill-terminal.json")" = "completed" ]; then
    printf 'backfill_checkpoint=reused\n'
    return
  fi
  mailctl_exec identity upgrade preflight --json >"$preflight"
  checksum="$(jq -r '.sha256 // empty' "$preflight")"
  [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || die "identity preflight omitted checksum"
  if mailctl_exec identity upgrade --json backfill plan \
      >"$EVIDENCE_DIR/backfill-plan.json" 2>"$EVIDENCE_DIR/backfill-plan.stderr"; then
    :
  else
    [ "$?" = "2" ] || die "identity backfill plan failed"
  fi
  mailctl_exec identity upgrade backfill start \
    --preflight-checksum "$checksum" \
    --reason "D4 isolated deployment backfill" --json >"$job"
  job_id="$(jq -r '.jobId // empty' "$job")"
  [[ "$job_id" =~ ^[0-9a-f-]{36}$ ]] || die "identity backfill omitted job id"
  mailctl_exec identity job watch "$job_id" --timeout 5m --json \
    >"$EVIDENCE_DIR/backfill-terminal.json"
  [ "$(jq -r '.state' "$EVIDENCE_DIR/backfill-terminal.json")" = "completed" ] ||
    die "identity backfill did not complete"
}

configure_source() {
  say "Configure, validate, and activate normalized LDAP source"
  local source_doc="$EVIDENCE_DIR/source.json"
  local source_in_container="/tmp/${RUN_PREFIX}-d4-source.json"
  local secret_in_container="/tmp/${RUN_PREFIX}-d4-bind-password"
  local source_state
  cat >"$source_doc" <<EOF
{
  "apiVersion": "setjoin.io/v1",
  "kind": "IdentitySource",
  "metadata": {
    "sourceKey": "$SOURCE_KEY",
    "displayName": "D4 TLS LDAP"
  },
  "spec": {
    "type": "ldap",
    "endpoint": {
      "host": "ldap.org-b.test",
      "port": 636,
      "tls": "ldaps"
    },
    "subjectAttribute": "entryUUID",
    "baseDN": "$LDAP_BASE_DN",
    "bindDN": "$LDAP_BIND_DN",
    "userFilter": "(objectClass=inetOrgPerson)"
  }
}
EOF
  docker cp "$source_doc" "$A:$source_in_container"
  docker cp "$PRIVATE_DIR/bind-password" "$A:$secret_in_container"
  docker exec "$A" chmod 0600 "$source_in_container" "$secret_in_container"
  mailctl_exec identity source validate --file "$source_in_container" --json \
    >"$EVIDENCE_DIR/source-validate.json"
  source_state="$(psql_env "$A" "
    SELECT state FROM identity_sources WHERE source_key='$SOURCE_KEY'
  ")"
  case "$source_state" in
    ("")
      if mailctl_exec identity source plan --file "$source_in_container" --json \
          >"$EVIDENCE_DIR/source-plan.json" 2>"$EVIDENCE_DIR/source-plan.stderr"; then
        die "new identity source plan unexpectedly reported no change"
      else
        [ "$?" = "2" ] || die "identity source plan failed"
      fi
      mailctl_exec identity source apply --file "$source_in_container" \
        --reason "D4 create TLS LDAP source" --json >"$EVIDENCE_DIR/source-apply.json"
      source_state="draft"
      ;;
    (active)
      printf 'identity_source_checkpoint=active\n'
      docker exec "$A" rm -f "$source_in_container" "$secret_in_container"
      return
      ;;
    (draft|validated) ;;
    (*) die "identity source cannot resume from state: $source_state" ;;
  esac
  if [ "$source_state" = "draft" ]; then
    mailctl_exec identity source set-secret "$SOURCE_KEY" --name bindPassword \
      --file "$secret_in_container" --reason "D4 install isolated LDAP bind secret" \
      --json >"$EVIDENCE_DIR/source-secret.json"
    mailctl_exec identity source dry-run "$SOURCE_KEY" \
      --reason "D4 prove TLS LDAP transport" --json >"$EVIDENCE_DIR/source-dry-run.json"
    [ "$(jq -r '.valid' "$EVIDENCE_DIR/source-dry-run.json")" = "true" ] ||
      die "identity source dry-run was not valid"
  else
    # `validated` is the durable commit point of a successful dry-run. A prior
    # client-side decode/output failure may occur after that commit. Reissuing
    # with a fresh idempotency key is an illegal validated -> validated edge,
    # so recover from the server state and retain its exact audit evidence.
    psql_env "$A" "
      SELECT jsonb_build_object(
        'sourceKey',s.source_key,
        'state',s.state,
        'generation',s.generation::text,
        'validatedEvents',count(e.id),
        'lastValidatedAt',max(e.occurred_at)
      )
        FROM identity_sources s
        LEFT JOIN identity_link_events e
          ON e.source_id=s.id AND e.action='source_validated'
       WHERE s.source_key='$SOURCE_KEY'
       GROUP BY s.id
    " >"$EVIDENCE_DIR/source-dry-run-checkpoint.json"
    [ "$(jq -r '.state' "$EVIDENCE_DIR/source-dry-run-checkpoint.json")" = "validated" ] ||
      die "validated source checkpoint could not be proven"
    [ "$(jq -r '.validatedEvents' "$EVIDENCE_DIR/source-dry-run-checkpoint.json")" -ge 1 ] ||
      die "validated source checkpoint omitted audit evidence"
  fi
  mailctl_exec identity source activate "$SOURCE_KEY" \
    --reason "D4 activate isolated LDAP source" --json \
    >"$EVIDENCE_DIR/source-activate.json"
  docker exec "$A" rm -f "$source_in_container" "$secret_in_container"
}

enable_model_and_wait_for_syncs() {
  say "Enable model v2 and prove repeated real network sync"
  mailctl_exec feature set feature.identity_model_v2 on --yes \
    >"$EVIDENCE_DIR/model-enable.txt"
  local source_id
  source_id="$(psql_env "$A" "SELECT id FROM identity_sources WHERE source_key='$SOURCE_KEY'")"
  [[ "$source_id" =~ ^[1-9][0-9]*$ ]] || die "normalized source id is malformed"
  for _ in $(seq 1 90); do
    [ "$(psql_env "$A" "
      SELECT count(*) FROM identity_source_batches
       WHERE source_id=$source_id AND state='completed'
    ")" -ge 1 ] && break
    sleep 2
  done
  [ "$(psql_env "$A" "
    SELECT count(*) FROM identity_source_batches
     WHERE source_id=$source_id AND state='completed'
  ")" -ge 1 ] || die "first normalized LDAP batch did not complete"
  docker exec "$A" systemctl restart setjoin
  for _ in $(seq 1 90); do
    [ "$(psql_env "$A" "
      SELECT count(*) FROM identity_source_batches
       WHERE source_id=$source_id AND state='completed'
    ")" -ge 2 ] && break
    sleep 2
  done
  [ "$(psql_env "$A" "
    SELECT count(*) FROM identity_source_batches
     WHERE source_id=$source_id AND state='completed'
  ")" -ge 2 ] || die "restart did not produce a second normalized LDAP batch"
  [ "$(psql_env "$A" "
    SELECT count(*) FROM user_identity_links l
      JOIN users u ON u.id=l.user_id
     WHERE l.source_id=$source_id
       AND l.state='active'
       AND lower(u.email) IN ('d4-alice@example.com','d4-bob@example.com')
  ")" = "2" ] || die "LDAP people did not receive exact active source links"
  [ "$(psql_env "$A" "
    SELECT count(*) FROM user_identity_links l
      JOIN guest_accounts g ON g.user_id=l.user_id
     WHERE l.source_id=$source_id
  ")" = "0" ] || die "Guest entered normalized lifecycle authority"
  {
    printf 'real_tls_ldap_sync=PASS\n'
    printf 'completed_batches=%s\n' "$(psql_env "$A" "
      SELECT count(*) FROM identity_source_batches
       WHERE source_id=$source_id AND state='completed'
    ")"
    printf 'active_source_links=2\n'
    printf 'guest_source_links=0\n'
    printf 'model_v2_enabled_on_a=true\n'
    printf 'identity_flags_b_c=OFF_OFF\n'
  } | tee "$EVIDENCE_DIR/initial-sync.txt"
}

write_observer() {
  local observer="$EVIDENCE_DIR/observe.sh"
  cat >"$observer" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
container="$1"
source_key="$2"
log="$3"
while :; do
  line="$(docker exec -u postgres "$container" psql -d mailserver -F '|' -Atc "
    SELECT statement_timestamp(),
           count(*) FILTER (WHERE b.state='completed'),
           min(b.completed_at) FILTER (WHERE b.state='completed'),
           max(b.completed_at) FILTER (WHERE b.state='completed'),
           count(*) FILTER (WHERE b.state<>'completed'),
           round(extract(epoch FROM (
             max(b.completed_at) FILTER (WHERE b.state='completed') -
             min(b.completed_at) FILTER (WHERE b.state='completed')
           ))/3600,2)
      FROM identity_sources s
      LEFT JOIN identity_source_batches b ON b.source_id=s.id
     WHERE s.source_key='$source_key'
     GROUP BY s.id")"
  printf '%s\n' "$line" >>"$log"
  completed="$(printf '%s' "$line" | cut -d'|' -f2)"
  open="$(printf '%s' "$line" | cut -d'|' -f5)"
  hours="$(printf '%s' "$line" | cut -d'|' -f6)"
  if [ "${completed:-0}" -ge 7 ] && [ "${open:-1}" -eq 0 ] &&
     awk -v h="${hours:-0}" 'BEGIN { exit !(h >= 24) }'; then
    exit 0
  fi
  sleep 900
done
EOF
  chmod 0700 "$observer"
}

start_observer() {
  write_observer
  local pid_file="$EVIDENCE_DIR/observer.pid"
  if [ -s "$pid_file" ] && kill -0 "$(<"$pid_file")" 2>/dev/null; then
    printf 'observer_already_running=true\n'
    return
  fi
  nohup "$EVIDENCE_DIR/observe.sh" "$A" "$SOURCE_KEY" \
    "$EVIDENCE_DIR/observation.log" \
    >"$EVIDENCE_DIR/observer.stdout" 2>"$EVIDENCE_DIR/observer.stderr" &
  printf '%s\n' "$!" >"$pid_file"
  chmod 0600 "$pid_file"
  printf 'observer_started=true\nobserver_pid=%s\n' "$(<"$pid_file")"
}

prepare_action() {
  local flags
  flags="$(for n in "$A" "$B" "$C"; do
    psql_env "$n" "
      SELECT string_agg(key || ':' || enabled,',' ORDER BY key)
        FROM feature_toggles WHERE key LIKE 'feature.identity_%'
    "; done)"
  local all_off
  all_off=$'feature.identity_model_v2:false,feature.identity_normalized_reads:false,feature.identity_transitions:false\nfeature.identity_model_v2:false,feature.identity_normalized_reads:false,feature.identity_transitions:false\nfeature.identity_model_v2:false,feature.identity_normalized_reads:false,feature.identity_transitions:false'
  if [ "$ACTION" = "prepare" ]; then
    [ "$flags" = "$all_off" ] ||
      die "identity toggles must begin OFF on A/B/C"
    stage_current_build
    write_ldap_build_context
    repair_dns_and_install_ldap_ca
    start_tls_ldap
  else
    case "$flags" in
      ("$all_off") ;;
      ($'feature.identity_model_v2:true,feature.identity_normalized_reads:false,feature.identity_transitions:false\nfeature.identity_model_v2:false,feature.identity_normalized_reads:false,feature.identity_transitions:false\nfeature.identity_model_v2:false,feature.identity_normalized_reads:false,feature.identity_transitions:false') ;;
      (*) die "resume found an unsupported identity-toggle checkpoint" ;;
    esac
    grep -qx 'current_build_upgrade=PASS' "$EVIDENCE_DIR/build.txt" 2>/dev/null ||
      die "resume requires the successful current-build checkpoint"
    [ "$(docker inspect -f '{{.State.Running}}' "$LDAP" 2>/dev/null)" = "true" ] ||
      die "resume requires the verified TLS LDAP checkpoint"
    [ -s "$EVIDENCE_DIR/ldap-manifest.txt" ] ||
      die "resume requires the LDAP manifest checkpoint"
    refresh_mailctl_build
  fi
  # Docker may regenerate /etc/hosts when the test DNS container is replaced;
  # install the loopback name only after the DNS/LDAP checkpoint is stable.
  install_mailctl_loopback_name
  ADMIN_TOKEN="$(enroll_admin_and_issue_token)"
  run_upgrade_preflight_and_backfill
  configure_source
  enable_model_and_wait_for_syncs
  start_observer | tee "$EVIDENCE_DIR/observer-start.txt"
  printf 'D4_PREPARE_PASS\n'
}

status_action() {
  psql_env "$A" "
    SELECT jsonb_build_object(
      'flags',(SELECT jsonb_object_agg(key,enabled) FROM feature_toggles
                WHERE key LIKE 'feature.identity_%'),
      'source',(SELECT jsonb_build_object(
          'state',state,'generation',generation,'readMode',read_mode,
          'lastSuccessAt',last_success_at,'lastErrorCode',last_error_code)
        FROM identity_sources WHERE source_key='$SOURCE_KEY'),
      'batches',(SELECT jsonb_build_object(
          'completed',count(*) FILTER (WHERE b.state='completed'),
          'open',count(*) FILTER (WHERE b.state<>'completed'),
          'first',min(b.completed_at) FILTER (WHERE b.state='completed'),
          'last',max(b.completed_at) FILTER (WHERE b.state='completed'),
          'hours',round(extract(epoch FROM (
            max(b.completed_at) FILTER (WHERE b.state='completed')-
            min(b.completed_at) FILTER (WHERE b.state='completed')
          ))/3600,2))
        FROM identity_sources s LEFT JOIN identity_source_batches b ON b.source_id=s.id
       WHERE s.source_key='$SOURCE_KEY' GROUP BY s.id),
      'guestLinks',(SELECT count(*) FROM user_identity_links l
          JOIN guest_accounts g ON g.user_id=l.user_id
          JOIN identity_sources s ON s.id=l.source_id
         WHERE s.source_key='$SOURCE_KEY')
    )
  "
  if [ -s "$EVIDENCE_DIR/observer.pid" ] &&
     kill -0 "$(<"$EVIDENCE_DIR/observer.pid")" 2>/dev/null; then
    echo "observer=running"
  else
    echo "observer=stopped"
  fi
}

verify_window_action() {
  ADMIN_TOKEN="$(enroll_admin_and_issue_token)"
  mailctl_exec identity upgrade shadow --source "$SOURCE_KEY" --json \
    >"$EVIDENCE_DIR/shadow-window.json"
  [ "$(jq -r '.eligible' "$EVIDENCE_DIR/shadow-window.json")" = "true" ] ||
    die "real 24-hour identity observation is not yet eligible"
  printf 'D4_WINDOW_PASS\n'
}

cleanup_action() {
  if [ -s "$EVIDENCE_DIR/observer.pid" ]; then
    kill "$(<"$EVIDENCE_DIR/observer.pid")" 2>/dev/null || true
  fi
  psql_env "$A" "
    UPDATE feature_toggles SET enabled=false,updated_at=now()
     WHERE key IN (
       'feature.identity_model_v2',
       'feature.identity_normalized_reads',
       'feature.identity_transitions'
     )
  " >/dev/null
  docker rm -f "$LDAP" >/dev/null 2>&1 || true
  docker exec -i "$A" bash -s -- "$RUN_PREFIX" <<'INNER'
set -Eeuo pipefail
prefix="$1"
tmp="$(mktemp)"
grep -Fv "# ${prefix}-d4-mailctl" /etc/hosts >"$tmp"
cat "$tmp" >/etc/hosts
rm -f "$tmp" "/usr/local/share/ca-certificates/${prefix}-d4-ldap.crt"
update-ca-certificates >/dev/null
INNER
  find "$PRIVATE_DIR" -type f -delete
  printf 'identity_flags_restored_off=PASS\nldap_private_keys_removed=PASS\n' |
    tee "$EVIDENCE_DIR/cleanup.txt"
}

validate
case "$ACTION" in
  prepare|resume) prepare_action ;;
  observe) start_observer ;;
  status) status_action ;;
  verify-window) verify_window_action ;;
  cleanup) cleanup_action ;;
esac
