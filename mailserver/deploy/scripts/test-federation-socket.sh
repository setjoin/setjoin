#!/usr/bin/env bash
# Hermetic installation seam: configured peering belongs to the native gateway socket.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
tmp=$(mktemp -d /tmp/gofree-fed2-render.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
INSTALL_DIR="$tmp/runtime" GATEWAY_ENV="$tmp/gateway.env" CONFIG_ENV="$tmp/config.env" DB_CRED_FILE="$tmp/db.env"
FEDERATION_ENABLED=true FEDERATION_LISTEN_ADDR=127.0.0.1:17443
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
test -s "$tmp/setjoin-federation.socket"
grep -qx 'FileDescriptorName=federation' "$tmp/setjoin-federation.socket"
grep -qx 'ListenStream=127.0.0.1:17443' "$tmp/setjoin-federation.socket"
grep -qx 'Service=setjoin-gateway.service' "$tmp/setjoin-federation.socket"
! grep -qx 'Requires=setjoin-federation.socket' "$tmp/setjoin-gateway.service"
grep -qx 'Wants=setjoin-federation.socket' "$tmp/setjoin-gateway.service"
# Only the dedicated credential surface reaches the internet-facing process.
! grep -Eq '^EnvironmentFile=.*(config.env|db.env|db-credentials.env)$' "$tmp/setjoin-gateway.service"
grep -qx "EnvironmentFile=-$tmp/federation.env" "$tmp/setjoin-gateway.service"
cat > "$CONFIG_ENV" <<'ENV'
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
FEDERATION_LOCAL_DOMAIN=zulu.test
FEDERATION_CERT=/fixture/leaf.crt
FEDERATION_KEY=/fixture/leaf.key
FEDERATION_LISTEN_ADDR=:7443
GO_WORKERS_OFF=backup-engine,federation-service,federation-residue-reap
RUST_WORKERS_ON=push-intent-drain,federation-service,federation-residue-reap
DB_OWNER_DSN=must-not-reach-gateway
DB_DIRECT_OWNER_DSN=must-not-reach-gateway
S3_SECRET_KEY=must-not-reach-gateway
ENV
cat > "$DB_CRED_FILE" <<'ENV'
DB_WORKER_DSN=postgres://worker@fixture/db
DB_OWNER_DSN=must-not-reach-gateway
DB_DIRECT_OWNER_DSN=must-not-reach-gateway
ENV
render_federation_env "$tmp/federation.env" "$CONFIG_ENV" "$DB_CRED_FILE"
cat > "$tmp/expected.env" <<'ENV'
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
FEDERATION_LOCAL_DOMAIN=zulu.test
FEDERATION_CERT=/fixture/leaf.crt
FEDERATION_KEY=/fixture/leaf.key
FEDERATION_LISTEN_ADDR=:7443
DB_WORKER_DSN=postgres://worker@fixture/db
GO_WORKERS_OFF=federation-service,federation-residue-reap
RUST_WORKERS_ON=federation-residue-reap
ENV
diff -u "$tmp/expected.env" "$tmp/federation.env"
test "$(stat -c '%a' "$tmp/federation.env")" = 640
# Production installation pins root ownership and the runtime read group.
grep -Fq 'render_federation_env "$FEDERATION_ENV" "$CONFIG_ENV" "$DB_CRED_FILE"' "$ROOT/mailserver/deploy/scripts/install.sh"
grep -Fq 'chown root:setjoin "$FEDERATION_ENV"' "$ROOT/mailserver/deploy/scripts/install.sh"
RUST_WORKERS_ON=federation-residue-reap AUTHSERVER_URL=http://127.0.0.1:8443 GO_WORKERS_OFF=federation-service,federation-residue-reap render_gateway_env "$GATEWAY_ENV"
! grep -q '^RUST_WORKERS_ON=' "$GATEWAY_ENV"
echo 'federation installation socket: PASS'
