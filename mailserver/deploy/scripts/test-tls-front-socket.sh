#!/usr/bin/env bash
# Hermetic release seam: public TLS belongs to the native activated front door.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-tlsfront-render.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
INSTALL_DIR="$tmp/runtime" GATEWAY_ENV="$tmp/gateway.env" CONFIG_ENV="$tmp/config.env" DB_CRED_FILE="$tmp/db.env" TLS_ENV="$tmp/tls.env"
cat > "$CONFIG_ENV" <<'ENV'
HOSTNAME=mail.example.test
LISTEN_ADDR=:443
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
TLS_AUTOCERT_DOMAINS=mail.example.test
TLS_AUTOCERT_CHALLENGE=tls-alpn-01
TLS_AUTOCERT_EMAIL=ops@example.test
TLS_AUTOCERT_CACHE_DIR=/fixture/autocert
TLS_SESSION_TICKET_KEY_ROTATE_SECS=60
TLS_DNS_PROVIDER=cloudflare
TLS_DNS_CONFIG={"CF_API_TOKEN":"literal-$-value"}
DB_DSN=postgres://app@fixture/db
GO_WORKERS_OFF=backup-engine,federation-service,federation-residue-reap
RUST_WORKERS_ON=federation-residue-reap
DB_OWNER_DSN=must-not-reach-gateway
S3_SECRET_KEY=must-not-reach-gateway
JWT_SECRET=must-not-reach-gateway
ENV
cat > "$DB_CRED_FILE" <<'ENV'
DB_WORKER_DSN=postgres://worker@fixture/db
DB_OWNER_DSN=must-not-reach-gateway
ENV
configure_tls_front "$CONFIG_ENV"
render_tls_front_env "$TLS_ENV" "$CONFIG_ENV"
render_federation_env "$tmp/federation.env" "$CONFIG_ENV" "$DB_CRED_FILE"
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
test -s "$tmp/setjoin-https.socket"
grep -qx 'FileDescriptorName=https' "$tmp/setjoin-https.socket"
grep -qx 'ListenStream=443' "$tmp/setjoin-https.socket"
grep -qx 'Service=setjoin-gateway.service' "$tmp/setjoin-https.socket"
grep -qx 'Wants=setjoin-https.socket' "$tmp/setjoin-gateway.service"
grep -qx "EnvironmentFile=-$TLS_ENV" "$tmp/setjoin-gateway.service"
grep -qx 'ReadWritePaths=-/fixture/autocert' "$tmp/setjoin-gateway.service"
grep -qx 'CapabilityBoundingSet=' "$tmp/setjoin-gateway.service"
grep -qx 'LISTEN_ADDR=127.0.0.1:0' "$CONFIG_ENV"
for name in cert-monitor tls-ticket-keys http-tls http-h2c acme-renewal; do
  for key in GO_WORKERS_OFF RUST_WORKERS_ON; do
    sed -n "s/^$key=//p" "$tmp/federation.env" | tr ',' '\n' | grep -qx "$name"
  done
done
grep -q '^RUST_WORKERS_ON=.*federation-residue-reap' "$tmp/federation.env"
grep -qx 'TLS_CERT=/fixture/leaf.crt' "$TLS_ENV"
grep -qx 'TLS_SESSION_TICKET_KEY_ROTATE_SECS=60' "$TLS_ENV"
grep -Fxq 'TLS_DNS_CONFIG={"CF_API_TOKEN":"literal-$-value"}' "$TLS_ENV"
! grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET|DB_DSN' "$TLS_ENV"
test "$(stat -c '%a' "$TLS_ENV")" = 640
# Re-rendering is idempotent and leaves unrelated worker ownership intact.
cp "$CONFIG_ENV" "$tmp/once.env"
configure_tls_front "$CONFIG_ENV"
diff -u "$tmp/once.env" "$CONFIG_ENV"
# Config regeneration preserves managed settings and literal credentials;
# explicit empty/updated environment assignments override previous values.
TLS_AUTOCERT_EMAIL=new@example.test TLS_DNS_PROVIDER=cloudflare tls_front_preserve_settings "$CONFIG_ENV" > "$tmp/preserved.env"
grep -qx 'TLS_AUTOCERT_EMAIL=new@example.test' "$tmp/preserved.env"
grep -qx 'TLS_SESSION_TICKET_KEY_ROTATE_SECS=60' "$tmp/preserved.env"
grep -Fxq 'TLS_DNS_CONFIG={"CF_API_TOKEN":"literal-$-value"}' "$tmp/preserved.env"
! grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET|DB_DSN' "$tmp/preserved.env"
GATEWAY_HTTPS_LISTEN='[::1]:1443' render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
grep -Fxq 'ListenStream=[::1]:1443' "$tmp/setjoin-https.socket"
echo 'native TLS release socket: PASS'
