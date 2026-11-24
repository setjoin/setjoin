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
if grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET|DB_DSN' "$TLS_ENV"; then echo 'secret leaked to tls.env' >&2; exit 1; fi
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
if grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET|DB_DSN' "$tmp/preserved.env"; then echo 'secret leaked to preserved.env' >&2; exit 1; fi
GATEWAY_HTTPS_LISTEN='[::1]:1443' render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
grep -Fxq 'ListenStream=[::1]:1443' "$tmp/setjoin-https.socket"
cat > "$tmp/yaml-config.env" <<'ENV'
HOSTNAME=mail.example.test
ENV
cat > "$tmp/setjoin.yaml" <<'YAML'
tls:
  nested:
    autocert_cache_dir: /wrong/nested/path
  "autocert_cache_dir": /var/lib/setjoin/custom-tls
YAML
echo 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/stale-cache' > "$tmp/yaml-gateway.env"
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/yaml-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 SETJOIN_CONFIG="$tmp/setjoin.yaml" render_gateway_env "$tmp/yaml-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/custom-tls' "$tmp/yaml-gateway.env"
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/yaml-gateway.env" SETJOIN_CONFIG="$tmp/setjoin.yaml" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/yaml-gateway.service"
grep -qx 'ReadWritePaths=-/var/lib/setjoin/custom-tls' "$tmp/yaml-gateway.service"

cat > "$tmp/quoted-config.env" <<'ENV'
HOSTNAME=mail.example.test
TLS_AUTOCERT_CACHE_DIR="/var/lib/setjoin/quoted"
WORM_MODE="compliance"
WORM_RETENTION_DAYS="3650"
WORM_LEGAL_HOLD_ENABLED=
S3_ENDPOINT=http://127.0.0.1:9000
S3_BUCKET=mailblobs
S3_ACCESS_KEY=ak-test
S3_SECRET_KEY=must-not-reach-gateway
DB_OWNER_DSN=must-not-reach-gateway
JWT_SECRET=must-not-reach-gateway
ENV
CONFIG_ENV="$tmp/quoted-config.env" GATEWAY_ENV="$tmp/quoted-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/quoted-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/quoted' "$tmp/quoted-gateway.env"
grep -qx 'WORM_MODE=compliance' "$tmp/quoted-gateway.env"
grep -qx 'WORM_RETENTION_DAYS=3650' "$tmp/quoted-gateway.env"
grep -qx 'WORM_LEGAL_HOLD_ENABLED=' "$tmp/quoted-gateway.env"
if grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET' "$tmp/quoted-gateway.env"; then echo 'secret leaked to gateway.env' >&2; exit 1; fi
tls_front_preserve_settings "$tmp/quoted-config.env" > "$tmp/quoted-preserved.env"
grep -qx 'WORM_MODE="compliance"' "$tmp/quoted-preserved.env"
grep -qx 'WORM_RETENTION_DAYS="3650"' "$tmp/quoted-preserved.env"
grep -qx 'WORM_LEGAL_HOLD_ENABLED=' "$tmp/quoted-preserved.env"
CONFIG_ENV="$tmp/quoted-config.env" GATEWAY_ENV="$tmp/quoted-gateway.env" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/quoted-gateway.service"
grep -qx 'ReadWritePaths=-/var/lib/setjoin/quoted' "$tmp/quoted-gateway.service"

# Storage allowlist is rendered independent of SMTP enablement.
printf 'SMTP_FRONT_ENABLED=false\nSMTP_INBOUND_ADDR=\nSMTP_SUBMISSION_ADDR=\n' >> "$tmp/quoted-config.env"
render_smtp_env "$tmp/quoted-smtp.env" "$tmp/quoted-config.env" /nonexistent
test ! -s "$tmp/quoted-smtp.env"
render_storage_env "$tmp/quoted-storage.env" "$tmp/quoted-config.env"
grep -qx 'S3_ENDPOINT=http://127.0.0.1:9000' "$tmp/quoted-storage.env"
grep -qx 'S3_BUCKET=mailblobs' "$tmp/quoted-storage.env"
grep -qx 'S3_ACCESS_KEY=ak-test' "$tmp/quoted-storage.env"
grep -qx 'S3_SECRET_KEY=must-not-reach-gateway' "$tmp/quoted-storage.env"
if grep -Eq 'OWNER_DSN|JWT_SECRET|DB_DSN' "$tmp/quoted-storage.env"; then echo 'secret leaked to storage.env' >&2; exit 1; fi
test "$(stat -c '%a' "$tmp/quoted-storage.env")" = 640

# Quoted empty TLS_AUTOCERT_CACHE_DIR="" must not enter tls.env and override gateway.env.
cat > "$tmp/empty-cache.env" <<'ENV'
HOSTNAME=mail.example.test
TLS_AUTOCERT_CACHE_DIR=""
ENV
render_tls_front_env "$tmp/empty-tls.env" "$tmp/empty-cache.env"
if grep -q '^TLS_AUTOCERT_CACHE_DIR=' "$tmp/empty-tls.env"; then echo 'TLS_AUTOCERT_CACHE_DIR leaked into tls.env' >&2; exit 1; fi
CONFIG_ENV="$tmp/empty-cache.env" GATEWAY_ENV="$tmp/empty-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/empty-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/cache/mailserver/autocert' "$tmp/empty-gateway.env"
CONFIG_ENV="$tmp/empty-cache.env" GATEWAY_ENV="$tmp/empty-gateway.env" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/empty-gateway.service"
grep -qx 'ReadWritePaths=-/var/cache/mailserver/autocert' "$tmp/empty-gateway.service"

cat > "$tmp/flow.yaml" <<'YAML'
tls: {
  nested: { autocert_cache_dir: /wrong/flow }, # comment after comma must not hide next entry
  autocert_cache_dir: "/var/lib/setjoin\/flow-tls"
}
worm:
  mode: governance
  retention_days: 730
  legal_hold_enabled: false
s3:
  endpoint: http://127.0.0.1:9100
  secure: false
  bucket: yaml-blobs
  access_key: yaml-ak
  secret_key: yaml-sk
YAML
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/flow-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 SETJOIN_CONFIG="$tmp/flow.yaml" render_gateway_env "$tmp/flow-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/flow-tls' "$tmp/flow-gateway.env"
grep -qx 'WORM_MODE=governance' "$tmp/flow-gateway.env"
grep -qx 'WORM_RETENTION_DAYS=730' "$tmp/flow-gateway.env"
# Go overrides YAML worm.legal_hold_enabled unless WORM_LEGAL_HOLD_ENABLED is explicitly set in env.
if grep -q '^WORM_LEGAL_HOLD_ENABLED=' "$tmp/flow-gateway.env"; then echo 'YAML worm.legal_hold_enabled should not override Go default' >&2; exit 1; fi
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/flow-gateway.env" SETJOIN_CONFIG="$tmp/flow.yaml" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/flow-gateway.service"
grep -qx 'ReadWritePaths=-/var/lib/setjoin/flow-tls' "$tmp/flow-gateway.service"

# YAML-only S3 settings populate storage.env when config.env has no S3_* literals, and SETJOIN_CONFIG is preserved.
SETJOIN_CONFIG="$tmp/flow.yaml" render_storage_env "$tmp/yaml-storage.env" "$tmp/yaml-config.env"
grep -qx 'S3_ENDPOINT=http://127.0.0.1:9100' "$tmp/yaml-storage.env"
grep -qx 'S3_BUCKET=yaml-blobs' "$tmp/yaml-storage.env"
grep -qx 'S3_ACCESS_KEY=yaml-ak' "$tmp/yaml-storage.env"
grep -qx 'S3_SECRET_KEY=yaml-sk' "$tmp/yaml-storage.env"
SETJOIN_CONFIG="$tmp/flow.yaml" tls_front_preserve_settings "$tmp/yaml-config.env" > "$tmp/yaml-preserved.env"
grep -qx "SETJOIN_CONFIG=$tmp/flow.yaml" "$tmp/yaml-preserved.env"

# Double-quoted YAML backslash escapes and path traversal rejection.
cat > "$tmp/esc.yaml" <<'YAML'
tls:
  autocert_cache_dir: "/var/lib\\setjoin/cache\ndir"
YAML
esc_val=$(yaml_section_value "$tmp/esc.yaml" tls autocert_cache_dir)
want_esc=$'/var/lib\\setjoin/cache\ndir'
test "$esc_val" = "$want_esc"
for bad in / /var/../etc /var/cache/.. relative/path $'/tmp/has\nnewline' '/tmp/has space'; do
  if validate_tls_cache_dir "$bad" 2>/dev/null; then
    echo "validate_tls_cache_dir accepted unsafe path: $bad" >&2
    exit 1
  fi
done
echo 'native TLS release socket: PASS'
