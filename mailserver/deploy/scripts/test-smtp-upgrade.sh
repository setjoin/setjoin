#!/usr/bin/env bash
# #501 operator seam: a flat upgrade installs the native SMTP sockets and the
# dedicated least-privilege smtp.env, transfers Go's listeners, and failed
# readiness restores the previous release's exact descriptor/config surface
# (bytes, modes and absence) with the new sockets closed before the old gateway.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-smtp6-upgrade.XXXXXX")
trap '[ -n "${KEEP:-}" ] || rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SMTP_TEST_LOG"
MOCK
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/chown"
cat > "$tmp/bin/curl" <<'MOCK'
#!/usr/bin/env bash
if [ "$SMTP_TEST_HEALTH" = gateway-down ]; then
  case "$*" in *'/_gateway/healthz'*) exit 1;; *) exit 0;; esac
fi
exit "$SMTP_TEST_HEALTH"
MOCK
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/sleep"
chmod 755 "$tmp/bin/"*
for previous in absent present; do
  for health in 0 1 gateway-down; do
    fx="$tmp/$previous-$health"
    mkdir -p "$fx/install" "$fx/new" "$fx/config" "$fx/units" "$fx/before-config" "$fx/before-units"
    for artifact in mailserverd setjoin-gateway; do
      echo "old $artifact" > "$fx/install/$artifact"
      echo "new $artifact" > "$fx/new/$artifact"
    done
    printf '#!/bin/sh\nexit 0\n' > "$fx/new/mailctl"; chmod 755 "$fx/new/mailctl"
    cat > "$fx/config/config.env" <<'ENV'
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
TLS_CERT=/fixture/cert.pem
TLS_KEY=/fixture/key.pem
SMTP_FRONT_ENABLED=false
SMTP_INBOUND_ADDR=127.0.0.1:2525
SMTP_SUBMISSION_ADDR=127.0.0.1:2587
GO_LISTENERS_OFF=other
S3_BUCKET=mailblobs
DB_WORKER_DSN=postgres://worker@fixture/db
DB_OWNER_DSN=must-not-reach-gateway
DB_DIRECT_OWNER_DSN=must-not-reach-gateway
JWT_PRIVATE_KEY=must-not-reach-gateway
JWT_SECRET=smtp6-link-secret
ENV
    echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$fx/config/gateway.env"
    echo 'previous gateway service' > "$fx/units/setjoin-gateway.service"
    echo 'previous gateway socket' > "$fx/units/setjoin-gateway.socket"
    if [ "$previous" = present ]; then
      for kind in smtp smtps submission; do echo "previous $kind socket" > "$fx/units/setjoin-$kind.socket"; done
      printf 'previous smtp env\nJWT_SECRET=stale-master-leak\n' > "$fx/config/smtp.env"
    fi
    chmod 0600 "$fx/config/config.env"
    if [ -e "$fx/config/smtp.env" ]; then chmod 0640 "$fx/config/smtp.env"; fi
    cp -a "$fx/config/." "$fx/before-config/"
    cp -a "$fx/units/." "$fx/before-units/"
    status=0
    PATH="$tmp/bin:$PATH" INSTALL_DIR="$fx/install" SETJOIN_CONFIG_DIR="$fx/config" \
      SYSTEMD_DIR="$fx/units" SMTP_TEST_HEALTH="$health" SMTP_TEST_LOG="$fx/actions" \
      bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$fx/new/mailserverd" "$fx/new/mailctl" \
      '' '' "$fx/new/setjoin-gateway" > "$fx/output" 2>&1 || status=$?
    test "$(stat -c '%a' "$fx/install/federation-deploy.prev")" = 700
    if [ "$health" = 0 ]; then
      [ "$status" = 0 ] || { cat "$fx/output" >&2; exit 1; }
      for kind in smtp submission; do
        grep -qx "FileDescriptorName=$kind" "$fx/units/setjoin-$kind.socket"
        grep -qx "Wants=setjoin-$kind.socket" "$fx/units/setjoin-gateway.service"
        grep -qx "enable setjoin-$kind.socket" "$fx/actions"
      done
      test ! -e "$fx/units/setjoin-smtps.socket"
      ! grep -Eq '^Requires=.*(smtp|submission)' "$fx/units/setjoin-gateway.service"
      ! grep -Eq '^EnvironmentFile=.*(config.env|db-credentials.env)$' "$fx/units/setjoin-gateway.service"
      grep -qx "EnvironmentFile=-$fx/config/smtp.env" "$fx/units/setjoin-gateway.service"
      grep -qx 'SMTP_FRONT_ENABLED=true' "$fx/config/config.env"
      grep -qx 'GO_LISTENERS_OFF=other,imap,smtp,submission' "$fx/config/config.env"
      grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$fx/config/gateway.env"
      grep -qx 'DB_WORKER_DSN=postgres://worker@fixture/db' "$fx/config/smtp.env"
      grep -qx 'DB_DSN=postgres://app@fixture/db' "$fx/config/smtp.env"
      if grep -Eq 'OWNER|UPDATER|JWT_PRIVATE_KEY|JWT_SECRET|must-not-reach|smtp6-link-secret|stale-master-leak' "$fx/config/smtp.env"; then echo leak >&2; exit 1; fi
      grep -Eqx 'SMTP_LINK_PROTECT_KEY=[0-9a-f]{64}' "$fx/config/smtp.env"
      test "$(stat -c '%a' "$fx/config/smtp.env")" = 640
      grep -qx 'daemon-reload' "$fx/actions"
    else
      [ "$status" != 0 ] || { echo 'failed readiness reported success' >&2; exit 1; }
      diff -ru "$fx/before-config" "$fx/config"
      diff -ru "$fx/before-units" "$fx/units"
      test "$(stat -c '%a' "$fx/config/config.env")" = 600
      if [ "$previous" = present ]; then test "$(stat -c '%a' "$fx/config/smtp.env")" = 640; else test ! -e "$fx/config/smtp.env"; fi
      test "$(cat "$fx/install/setjoin-gateway")" = 'old setjoin-gateway'
      python3 - "$fx/actions" <<'PY'
import sys
lines=open(sys.argv[1]).read().splitlines()
for sock in ('setjoin-smtp.socket','setjoin-smtps.socket','setjoin-submission.socket'):
    assert lines.count('stop '+sock) >= 2, (sock, lines)
last_start = len(lines)-1-lines[::-1].index('start setjoin-gateway')
assert lines.index('daemon-reload') < last_start, lines
# the new sockets are closed before the previous gateway can receive an FD
last_stop = max(i for i,l in enumerate(lines) if l=='stop setjoin-submission.socket')
assert last_stop < last_start, lines
PY
    fi
  done
done
echo 'SMTP upgrade activation and previous-release rollback: PASS'
