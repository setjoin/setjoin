#!/usr/bin/env bash
# #501: rendered SMTP socket set, dedicated least-privilege env file, Go
# listener transfer and preserved explicit listener disables.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
tmp=$(mktemp -d /tmp/gofree-smtp6-render.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
INSTALL_DIR="$tmp/runtime" GATEWAY_ENV="$tmp/gateway.env" CONFIG_ENV="$tmp/config.env" SMTP_ENV="$tmp/smtp.env"
AUTHSERVER_URL=http://127.0.0.1:8443
unset SMTP_FRONT_ENABLED SMTP_INBOUND_ADDR SMTP_INBOUND_TLS_ADDR SMTP_SUBMISSION_ADDR
cat > "$CONFIG_ENV" <<'ENV'
TLS_CERT=/fixture/cert.pem
TLS_KEY=/fixture/key.pem
IMAP_ADDR=127.0.0.1:1143
IMAP_TLS_ADDR=
GO_LISTENERS_OFF=other
DB_DSN=postgres://setjoin_app@127.0.0.1/db
DB_DIRECT_DSN=postgres://setjoin_app@127.0.0.1:5432/db
DB_OWNER_DSN=must-not-leak-owner
DB_DIRECT_OWNER_DSN=must-not-leak-direct-owner
UPDATER_DB_DSN=must-not-leak-updater
JWT_SECRET=smtp6-link-canary
JWT_LINK_PROTECT_TOKEN_VERSION=3
JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET=smtp6-previous-canary
CLAMAV_ADDR=127.0.0.1:3310
SANDBOX_ENABLED=true
SANDBOX_CAPE_URL=http://127.0.0.1:8000
SANDBOX_CAPE_API_KEY=smtp6-cape-canary
SANDBOX_TIMEOUT=6s
SANDBOX_FAIL_MODE=closed
INTERNAL_DOMAINS=smtp1.test
PROTECTED_DOMAINS=smtp1.test
ANTIPHISH_NAME_THRESHOLD=0.9
ANTIPHISH_USER_CACHE_TTL=1m
SMTP_INBOUND_ADDR=127.0.0.1:2525
SMTP_SUBMISSION_ADDR=127.0.0.1:2587
SMTP_INBOUND_TLS_ADDR=127.0.0.1:2465
SMTP_PER_USER_MAX_CONNS=7
S3_BUCKET=mailblobs
THREAT_RATE_LIMIT_PER_MIN=17
ENV
printf 'DB_WORKER_DSN=postgres://setjoin_worker@127.0.0.1/db\nDB_OWNER_DSN=must-not-leak-owner-2\n' > "$tmp/db-credentials.env"
# Default install transfers all configured SMTP listeners without opt-in.
printf 'DB_ENCRYPTION_KEY=enc-canary\nAUDIT_HMAC_KEY=hmac-canary\nS3_SECRET_KEY=s3-canary\n' >> "$CONFIG_ENV"
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
for kind in smtp smtps submission; do
  test -s "$tmp/setjoin-$kind.socket"
  grep -qx "FileDescriptorName=$kind" "$tmp/setjoin-$kind.socket"
  grep -qx 'Service=setjoin-gateway.service' "$tmp/setjoin-$kind.socket"
  # Soft coupling only: an SMTP socket problem must never stop HTTPS.
  grep -qx "Wants=setjoin-$kind.socket" "$tmp/setjoin-gateway.service"
done
! grep -E '^Requires=.*smtp|^Requires=.*submission' "$tmp/setjoin-gateway.service"
grep -qx 'ListenStream=2525' "$tmp/setjoin-smtp.socket" || grep -qx 'ListenStream=127.0.0.1:2525' "$tmp/setjoin-smtp.socket"
grep -qx 'ListenStream=127.0.0.1:2465' "$tmp/setjoin-smtps.socket"
grep -qx 'ListenStream=127.0.0.1:2587' "$tmp/setjoin-submission.socket"
grep -qx 'EnvironmentFile=-'"$tmp"'/smtp.env' "$tmp/setjoin-gateway.service"
grep -qx 'CapabilityBoundingSet=' "$tmp/setjoin-gateway.service"
configure_smtp_front "$CONFIG_ENV"
grep -qx 'GO_LISTENERS_OFF=other,smtp,submission' "$CONFIG_ENV"
configure_smtp_front "$CONFIG_ENV"
test "$(grep -c '^GO_LISTENERS_OFF=' "$CONFIG_ENV")" = 1
render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$tmp/db-credentials.env"
grep -qx 'DB_DSN=postgres://setjoin_app@127.0.0.1/db' "$SMTP_ENV"
grep -qx 'DB_WORKER_DSN=postgres://setjoin_worker@127.0.0.1/db' "$SMTP_ENV"
grep -qx 'SMTP_PER_USER_MAX_CONNS=7' "$SMTP_ENV"
grep -qx 'S3_BUCKET=mailblobs' "$SMTP_ENV"
if grep -Eq 'OWNER|UPDATER|must-not-leak|JWT_SECRET|smtp6-link-canary|smtp6-previous-canary' "$SMTP_ENV"; then echo 'forbidden key in smtp.env' >&2; exit 1; fi
# Only the pre-derived link-protect keys (Go tokenKeyN) are rendered, never the master secret.
want_key="$(printf 'link-protect-v3: link-protect token hmac key' | python3 -c 'import hmac,hashlib,sys;print(hmac.new(b"smtp6-link-canary",sys.stdin.buffer.read(),hashlib.sha256).hexdigest())')"
want_prev="$(printf 'link-protect-v2: link-protect token hmac key' | python3 -c 'import hmac,hashlib,sys;print(hmac.new(b"smtp6-previous-canary",sys.stdin.buffer.read(),hashlib.sha256).hexdigest())')"
grep -qx "SMTP_LINK_PROTECT_KEY=$want_key" "$SMTP_ENV"
grep -qx "SMTP_LINK_PROTECT_KEY_PREVIOUS=$want_prev" "$SMTP_ENV"
grep -qx 'SMTP_LINK_PROTECT_VERSION=3' "$SMTP_ENV"
# A stale smtp.env holding the master secret is replaced, not merged.
printf 'JWT_SECRET=stale-master\n' > "$SMTP_ENV"
render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$tmp/db-credentials.env"
! grep -q 'JWT_SECRET' "$SMTP_ENV"
grep -qx 'DB_ENCRYPTION_KEY=enc-canary' "$SMTP_ENV"
for key in CLAMAV_ADDR SANDBOX_ENABLED SANDBOX_CAPE_URL SANDBOX_CAPE_API_KEY SANDBOX_TIMEOUT SANDBOX_FAIL_MODE INTERNAL_DOMAINS PROTECTED_DOMAINS ANTIPHISH_NAME_THRESHOLD ANTIPHISH_USER_CACHE_TTL; do
  grep "^$key=" "$CONFIG_ENV" | tail -1 | grep -Fxf - "$SMTP_ENV"
done
# Upgrade the previous opt-in marker, including its historical false value.
printf 'SMTP_FRONT_ENABLED=false\n' >> "$CONFIG_ENV"
configure_smtp_front "$CONFIG_ENV"
grep -qx 'SMTP_FRONT_ENABLED=true' "$CONFIG_ENV"
test "$(stat -c %a "$SMTP_ENV")" = 640
# The Go listener transfer reaches the gateway's own env too, merged with IMAP.
render_gateway_env "$GATEWAY_ENV"
grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$GATEWAY_ENV"
grep -qx 'THREAT_RATE_LIMIT_PER_MIN=17' "$GATEWAY_ENV"
! grep -q 'OWNER' "$GATEWAY_ENV"
# An explicit empty address disables that listener and survives a reinstall.
printf 'SMTP_INBOUND_TLS_ADDR=\n' >> "$CONFIG_ENV"
rm -f "$tmp"/setjoin-smtp*.socket "$tmp/setjoin-submission.socket"
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
test -s "$tmp/setjoin-smtp.socket"
test -s "$tmp/setjoin-submission.socket"
test ! -f "$tmp/setjoin-smtps.socket"
tls_front_preserve_settings "$CONFIG_ENV" > "$tmp/preserved.env"
grep -qx 'SMTP_INBOUND_TLS_ADDR=' "$tmp/preserved.env"
grep -qx 'SMTP_FRONT_ENABLED=true' "$tmp/preserved.env"
# Inbound-only transfer must not claim submission.
printf 'SMTP_SUBMISSION_ADDR=\n' >> "$CONFIG_ENV"
sed -i '/^GO_LISTENERS_OFF=/d' "$CONFIG_ENV"
configure_smtp_front "$CONFIG_ENV"
grep -qx 'GO_LISTENERS_OFF=smtp' "$CONFIG_ENV"
for path in upgrade.sh setjoin-lifecycle.sh install.sh; do
  grep -q 'setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket' "$ROOT/mailserver/deploy/scripts/$path"
done
grep -q 'render_smtp_env' "$ROOT/mailserver/deploy/scripts/upgrade.sh"
grep -q 'smtp.env' "$ROOT/mailserver/deploy/scripts/upgrade.sh"
echo 'SMTP socket installation: PASS'
