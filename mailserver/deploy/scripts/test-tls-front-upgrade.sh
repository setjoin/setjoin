#!/usr/bin/env bash
# Operator seam: a flat upgrade installs native federation units/config; failed
# readiness restores the previous release's exact descriptor and config surface.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-tlsfront-upgrade.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FED_TEST_LOG"
MOCK
cat > "$tmp/bin/chown" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
cat > "$tmp/bin/curl" <<'MOCK'
#!/usr/bin/env bash
if [ "$FED_TEST_HEALTH" = gateway-down ]; then
  case "$*" in *'/_gateway/healthz'*) exit 1;; *) exit 0;; esac
fi
if [ "$FED_TEST_HEALTH" = tls-down ]; then
  case "$*" in *'https://'*'/_gateway/healthz'*) exit 1;; *) exit 0;; esac
fi
exit "$FED_TEST_HEALTH"
MOCK
cat > "$tmp/bin/sleep" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod 755 "$tmp/bin/"*
for previous_socket in absent present; do
  for health in 0 1 gateway-down tls-down; do
    fx="$tmp/$previous_socket-$health"
    mkdir -p "$fx/install" "$fx/new" "$fx/config" "$fx/units" "$fx/before-config" "$fx/before-units"
    for artifact in mailserverd setjoin-gateway; do
      echo "old $artifact" > "$fx/install/$artifact"
      echo "new $artifact" > "$fx/new/$artifact"
    done
    printf '#!/bin/sh\nexit 0\n' > "$fx/new/mailctl"
    chmod 755 "$fx/new/mailctl"
    cat > "$fx/config/config.env" <<'ENV'
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
LISTEN_ADDR=:443
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
FEDERATION_ENABLED=true
FEDERATION_LOCAL_DOMAIN=zulu.test
FEDERATION_CERT=/fixture/leaf.crt
FEDERATION_KEY=/fixture/leaf.key
FEDERATION_LISTEN_ADDR=127.0.0.1:17443
GO_WORKERS_OFF=backup-engine
RUST_WORKERS_ON=notify-intent-drain
DB_OWNER_DSN=must-not-reach-gateway
DB_DIRECT_OWNER_DSN=must-not-reach-gateway
S3_SECRET_KEY=must-not-reach-gateway
ENV
    echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$fx/config/gateway.env"
    echo 'previous gateway service' > "$fx/units/setjoin-gateway.service"
    echo 'previous gateway socket' > "$fx/units/setjoin-gateway.socket"
    if [ "$previous_socket" = present ]; then
      echo 'previous federation socket' > "$fx/units/setjoin-federation.socket"
      echo 'previous federation env' > "$fx/config/federation.env"
      echo 'previous HTTPS socket' > "$fx/units/setjoin-https.socket"
      echo 'previous ACME socket' > "$fx/units/setjoin-acme.socket"
      echo 'previous IMAP socket' > "$fx/units/setjoin-imap.socket"
      echo 'previous IMAPS socket' > "$fx/units/setjoin-imaps.socket"
      echo 'previous TLS env' > "$fx/config/tls.env"
    fi
    chmod 0600 "$fx/config/config.env"
    if [ -e "$fx/config/federation.env" ]; then chmod 0640 "$fx/config/federation.env"; fi
    cp -a "$fx/config/." "$fx/before-config/"
    cp -a "$fx/units/." "$fx/before-units/"
    status=0
    PATH="$tmp/bin:$PATH" INSTALL_DIR="$fx/install" SETJOIN_CONFIG_DIR="$fx/config" \
      SYSTEMD_DIR="$fx/units" FED_TEST_HEALTH="$health" FED_TEST_LOG="$fx/actions" \
      bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$fx/new/mailserverd" "$fx/new/mailctl" \
      '' '' "$fx/new/setjoin-gateway" > "$fx/output" 2>&1 || status=$?
    test "$(stat -c '%a' "$fx/install/federation-deploy.prev")" = 700
    if [ "$health" = 0 ]; then
      [ "$status" = 0 ] || { cat "$fx/output" >&2; exit 1; }
      grep -qx 'FileDescriptorName=federation' "$fx/units/setjoin-federation.socket"
      grep -qx 'Wants=setjoin-federation.socket' "$fx/units/setjoin-gateway.service"
      ! grep -Eq '^EnvironmentFile=.*(config.env|db-credentials.env)$' "$fx/units/setjoin-gateway.service"
      grep -qx "EnvironmentFile=-$fx/config/federation.env" "$fx/units/setjoin-gateway.service"
      grep -qx "ExecStart=$fx/install/setjoin-gateway" "$fx/units/setjoin-gateway.service"
      grep -qx 'GO_WORKERS_OFF=backup-engine,federation-service,federation-residue-reap,cert-monitor,tls-ticket-keys,http-tls,http-h2c' "$fx/config/config.env"
      grep -qx 'RUST_WORKERS_ON=notify-intent-drain,federation-residue-reap,cert-monitor,tls-ticket-keys,http-tls,http-h2c' "$fx/config/config.env"
      grep -qx 'GO_WORKERS_OFF=federation-service,federation-residue-reap,cert-monitor,tls-ticket-keys,http-tls,http-h2c' "$fx/config/federation.env"
      grep -qx 'RUST_WORKERS_ON=federation-residue-reap,cert-monitor,tls-ticket-keys,http-tls,http-h2c' "$fx/config/federation.env"
      ! grep -Eq 'OWNER_DSN|S3_SECRET' "$fx/config/federation.env"
      test "$(stat -c '%a' "$fx/config/federation.env")" = 640
      grep -qx 'LISTEN_ADDR=127.0.0.1:0' "$fx/config/config.env"
      grep -qx 'FileDescriptorName=https' "$fx/units/setjoin-https.socket"
      grep -qx 'FileDescriptorName=imap' "$fx/units/setjoin-imap.socket"
      grep -qx 'FileDescriptorName=imaps' "$fx/units/setjoin-imaps.socket"
      grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$fx/config/config.env"
      grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$fx/config/gateway.env"
      grep -qx 'TLS_CERT=/fixture/leaf.crt' "$fx/config/tls.env"
      test ! -e "$fx/units/setjoin-acme.socket"
      test "$(stat -c '%a' "$fx/config/tls.env")" = 640
      grep -qx 'enable setjoin-https.socket' "$fx/actions"
      grep -qx 'daemon-reload' "$fx/actions"
      grep -qx 'enable setjoin-federation.socket' "$fx/actions"
    else
      [ "$status" != 0 ] || { echo 'failed readiness reported success' >&2; exit 1; }
      diff -ru "$fx/before-config" "$fx/config"
      diff -ru "$fx/before-units" "$fx/units"
      test "$(stat -c '%a' "$fx/config/config.env")" = 600
      if [ "$previous_socket" = present ]; then
        test "$(stat -c '%a' "$fx/config/federation.env")" = 640
      fi
      test "$(cat "$fx/install/setjoin-gateway")" = 'old setjoin-gateway'
      # Close the new descriptor before the old gateway is started.
      python3 - "$fx/actions" <<'PY'
import sys
lines=open(sys.argv[1]).read().splitlines()
assert lines.count('stop setjoin-federation.socket') >= 2, lines
assert lines.index('daemon-reload') < len(lines)-1-lines[::-1].index('start setjoin-gateway'), lines
PY
    fi
  done
done
echo 'TLS front upgrade activation and previous-release rollback: PASS'
