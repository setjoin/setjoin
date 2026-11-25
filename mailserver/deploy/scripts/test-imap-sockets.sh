#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
tmp=$(mktemp -d /tmp/gofree-authrt-render.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
INSTALL_DIR="$tmp/runtime" GATEWAY_ENV="$tmp/gateway.env" CONFIG_ENV="$tmp/config.env"
AUTHSERVER_URL=http://127.0.0.1:8443
cat > "$CONFIG_ENV" <<'ENV'
TLS_CERT=/fixture/cert.pem
TLS_KEY=/fixture/key.pem
IMAP_ADDR=127.0.0.1:1143
IMAP_TLS_ADDR=127.0.0.1:1993
GO_LISTENERS_OFF=other
THREAT_RATE_LIMIT_PER_MIN=17
GEO_BLOCK_ENABLED=false
THREAT_TARPIT_THRESHOLD=9
DB_OWNER_DSN=must-not-leak
ENV
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
for kind in imap imaps; do
 test -s "$tmp/setjoin-$kind.socket"
 grep -qx "FileDescriptorName=$kind" "$tmp/setjoin-$kind.socket"
 grep -qx 'Service=setjoin-gateway.service' "$tmp/setjoin-$kind.socket"
 grep -qx "Wants=setjoin-$kind.socket" "$tmp/setjoin-gateway.service"
done
grep -qx 'ListenStream=127.0.0.1:1143' "$tmp/setjoin-imap.socket"
grep -qx 'ListenStream=127.0.0.1:1993' "$tmp/setjoin-imaps.socket"
grep -qx 'CapabilityBoundingSet=' "$tmp/setjoin-gateway.service"
configure_imap_front "$CONFIG_ENV"
grep -qx 'GO_LISTENERS_OFF=other,imap' "$CONFIG_ENV"
render_gateway_env "$GATEWAY_ENV"
grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$GATEWAY_ENV"
grep -qx 'THREAT_RATE_LIMIT_PER_MIN=17' "$GATEWAY_ENV"
grep -qx 'GEO_BLOCK_ENABLED=false' "$GATEWAY_ENV"
grep -qx 'THREAT_TARPIT_THRESHOLD=9' "$GATEWAY_ENV"
! grep -q 'DB_OWNER_DSN' "$GATEWAY_ENV"
printf 'IMAP_TLS_ADDR=\n' >> "$CONFIG_ENV"
rm "$tmp/setjoin-imap.socket" "$tmp/setjoin-imaps.socket"
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
test -s "$tmp/setjoin-imap.socket"
test ! -f "$tmp/setjoin-imaps.socket"
# Re-running install must preserve the operator's explicit disabled listener.
tls_front_preserve_settings "$CONFIG_ENV" > "$tmp/preserved.env"
grep -qx 'IMAP_TLS_ADDR=' "$tmp/preserved.env"
for path in upgrade.sh setjoin-lifecycle.sh; do
 grep -q 'setjoin-imap.socket setjoin-imaps.socket' "$ROOT/mailserver/deploy/scripts/$path"
done
echo 'IMAP socket installation: PASS'
