#!/usr/bin/env bash
# Operator seam: a flat upgrade installs native federation units/config; failed
# readiness restores the previous release's exact descriptor and config surface.
set -euo pipefail
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-tlsfront-upgrade.XXXXXX")
tmp=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$tmp")
export TMPDIR="$tmp"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FED_TEST_LOG"
if [ "${1:-}" = daemon-reload ] && [ "${FED_TEST_FAIL_DAEMON_RELOAD:-0}" = 1 ]; then
  exit 1
fi
if [ "${1:-}" = enable ] && [ -n "${FED_TEST_FAIL_ENABLE:-}" ] && [ "${2:-}" = "$FED_TEST_FAIL_ENABLE" ]; then
  exit 1
fi
if [ "${1:-}" = is-enabled ] && { [ -n "${FED_TEST_ENABLED_SOCKETS+x}" ] || [ -n "${FED_TEST_RUNTIME_SOCKETS+x}" ]; }; then
  target="${3:-${2:-}}"
  case " ${FED_TEST_RUNTIME_SOCKETS:-} " in *" $target "*) printf 'enabled-runtime\n'; exit 0 ;; esac
  case " ${FED_TEST_ENABLED_SOCKETS:-} " in *" $target "*) printf 'enabled\n'; exit 0 ;; esac
  exit 1
fi
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
    for artifact in setjoin-server; do
      echo "old $artifact" > "$fx/install/$artifact"
      echo "new $artifact" > "$fx/new/$artifact"
    done
    printf '#!/bin/sh\nexit 0\n' > "$fx/new/mailctl"
    chmod 755 "$fx/new/mailctl"
    cat > "$fx/config/config.env" <<'ENV'
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
WORM_MODE=compliance
WORM_RETENTION_DAYS=3650
WORM_LEGAL_HOLD_ENABLED=true
S3_BUCKET=mailblobs
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
    printf 'TLS_AUTOCERT_CACHE_DIR=%s/autocert\n' "$fx" >> "$fx/config/config.env"
    echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$fx/config/gateway.env"
    echo 'previous gateway service' > "$fx/units/setjoin-gateway.service"
    echo 'previous gateway socket' > "$fx/units/setjoin-gateway.socket"
    if [ "$previous_socket" = present ]; then
      echo 'previous federation socket' > "$fx/units/setjoin-federation.socket"
      echo 'previous federation env' > "$fx/config/federation.env"
      echo 'previous HTTPS socket' > "$fx/units/setjoin-https.socket"
      echo 'previous IMAP socket' > "$fx/units/setjoin-imap.socket"
      echo 'previous IMAPS socket' > "$fx/units/setjoin-imaps.socket"
      echo 'previous TLS env' > "$fx/config/tls.env"
      echo 'previous storage env' > "$fx/config/storage.env"
      mkdir -p "$fx/autocert" && chmod 0755 "$fx/autocert"
    fi
    chmod 0600 "$fx/config/config.env"
    if [ -e "$fx/config/federation.env" ]; then chmod 0640 "$fx/config/federation.env"; fi
    if [ -e "$fx/config/storage.env" ]; then chmod 0640 "$fx/config/storage.env"; fi
    cp -a "$fx/config/." "$fx/before-config/"
    cp -a "$fx/units/." "$fx/before-units/"
    status=0
    PATH="$tmp/bin:$PATH" INSTALL_DIR="$fx/install" SETJOIN_CONFIG_DIR="$fx/config" \
      SYSTEMD_DIR="$fx/units" FED_TEST_HEALTH="$health" FED_TEST_LOG="$fx/actions" \
      bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$fx/new/setjoin-server" "$fx/new/mailctl" \
      > "$fx/output" 2>&1 || status=$?
    test "$(mode_of "$fx/install/federation-deploy.prev")" = 700
    if [ "$health" = 0 ]; then
      [ "$status" = 0 ] || { cat "$fx/output" >&2; exit 1; }
      grep -qx 'FileDescriptorName=federation' "$fx/units/setjoin-federation.socket"
      grep -qx 'Wants=setjoin-federation.socket' "$fx/units/setjoin-gateway.service"
      if grep -Eq '^EnvironmentFile=.*(config.env|db-credentials.env)$' "$fx/units/setjoin-gateway.service"; then echo 'privileged env leaked into gateway unit' >&2; exit 1; fi
      grep -qx "EnvironmentFile=-$fx/config/federation.env" "$fx/units/setjoin-gateway.service"
      grep -qx "ExecStart=$fx/install/setjoin-server" "$fx/units/setjoin-gateway.service"
      grep -qx 'GO_WORKERS_OFF=backup-engine,federation-service,federation-residue-reap,cert-monitor,http-tls,http-h2c' "$fx/config/config.env"
      grep -qx 'RUST_WORKERS_ON=notify-intent-drain,federation-residue-reap,cert-monitor,http-tls,http-h2c' "$fx/config/config.env"
      grep -qx 'GO_WORKERS_OFF=federation-service,federation-residue-reap,cert-monitor,http-tls,http-h2c' "$fx/config/federation.env"
      grep -qx 'RUST_WORKERS_ON=federation-residue-reap,cert-monitor,http-tls,http-h2c' "$fx/config/federation.env"
      if grep -Eq 'OWNER_DSN|S3_SECRET' "$fx/config/federation.env"; then echo 'secret leaked into federation.env' >&2; exit 1; fi
      test "$(mode_of "$fx/config/federation.env")" = 640
      grep -qx 'LISTEN_ADDR=127.0.0.1:0' "$fx/config/config.env"
      grep -qx 'FileDescriptorName=https' "$fx/units/setjoin-https.socket"
      grep -qx 'FileDescriptorName=imap' "$fx/units/setjoin-imap.socket"
      grep -qx 'FileDescriptorName=imaps' "$fx/units/setjoin-imaps.socket"
      grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$fx/config/config.env"
      grep -qx 'GO_LISTENERS_OFF=imap,smtp,submission' "$fx/config/gateway.env"
      test -d "$fx/autocert"
      test "$(mode_of "$fx/autocert")" = 700
      grep -qx "ReadWritePaths=-$fx/autocert" "$fx/units/setjoin-gateway.service"
      grep -qx "TLS_AUTOCERT_CACHE_DIR=$fx/autocert" "$fx/config/gateway.env"
      grep -qx 'WORM_MODE=compliance' "$fx/config/gateway.env"
      grep -qx 'WORM_RETENTION_DAYS=3650' "$fx/config/gateway.env"
      grep -qx 'WORM_LEGAL_HOLD_ENABLED=true' "$fx/config/gateway.env"
      grep -qx "EnvironmentFile=-$fx/config/storage.env" "$fx/units/setjoin-gateway.service"
      grep -qx 'S3_BUCKET=mailblobs' "$fx/config/storage.env"
      if grep -Eq 'OWNER_DSN|JWT_SECRET|DB_DSN' "$fx/config/storage.env"; then echo 'leak in storage.env' >&2; exit 1; fi
      test "$(mode_of "$fx/config/storage.env")" = 640
      grep -qx 'TLS_CERT=/fixture/leaf.crt' "$fx/config/tls.env"
      test ! -e "$fx/units/setjoin-acme.socket"
      test "$(mode_of "$fx/config/tls.env")" = 640
      grep -qx 'enable setjoin-https.socket' "$fx/actions"
      grep -qx 'daemon-reload' "$fx/actions"
      grep -qx 'enable setjoin-federation.socket' "$fx/actions"
    else
      [ "$status" != 0 ] || { echo 'failed readiness reported success' >&2; exit 1; }
      diff -ru "$fx/before-config" "$fx/config"
      diff -ru "$fx/before-units" "$fx/units"
      test "$(mode_of "$fx/config/config.env")" = 600
      if [ "$previous_socket" = present ]; then
        test "$(mode_of "$fx/config/federation.env")" = 640
        test "$(mode_of "$fx/autocert")" = 755
      else
        test ! -e "$fx/autocert"
      fi
      test "$(cat "$fx/install/setjoin-server")" = 'old setjoin-server'
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

# Missing intermediate TLS cache parent directories are created traversable (0755) while leaf stays 0700.
nc="$tmp/nested-cache"
mkdir -p "$nc/install" "$nc/new" "$nc/config" "$nc/units"
for artifact in setjoin-server; do
  echo "old $artifact" > "$nc/install/$artifact"
  echo "new $artifact" > "$nc/new/$artifact"
done
printf '#!/bin/sh\nexit 0\n' > "$nc/new/mailctl"
chmod 755 "$nc/new/mailctl"
cat > "$nc/config/config.env" <<ENV
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
TLS_AUTOCERT_CACHE_DIR=$nc/missing-parent/autocert
ENV
echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$nc/config/gateway.env"
echo 'previous gateway service' > "$nc/units/setjoin-gateway.service"
echo 'previous gateway socket' > "$nc/units/setjoin-gateway.socket"
PATH="$tmp/bin:$PATH" INSTALL_DIR="$nc/install" SETJOIN_CONFIG_DIR="$nc/config" \
  SYSTEMD_DIR="$nc/units" FED_TEST_HEALTH=0 FED_TEST_LOG="$nc/actions" \
  bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$nc/new/setjoin-server" "$nc/new/mailctl" \
  > "$nc/output" 2>&1
test -d "$nc/missing-parent/autocert"
test "$(mode_of "$nc/missing-parent")" = 755
test "$(mode_of "$nc/missing-parent/autocert")" = 700

# Failed TLS cache removal rollback surfaces Incomplete rollback without claiming full restore.
rf="$tmp/rollback-cache-fail"
mkdir -p "$rf/bin" "$rf/install" "$rf/new" "$rf/config" "$rf/units"
cp "$tmp/bin/"* "$rf/bin/"
cat > "$rf/bin/curl" <<MOCK
#!/usr/bin/env bash
mkdir -p "$rf/new-parent/autocert"
: > "$rf/new-parent/autocert/keep"
exit 1
MOCK
chmod 755 "$rf/bin/curl"
for artifact in setjoin-server; do
  echo "old $artifact" > "$rf/install/$artifact"
  echo "new $artifact" > "$rf/new/$artifact"
done
printf '#!/bin/sh\nexit 0\n' > "$rf/new/mailctl"
chmod 755 "$rf/new/mailctl"
cat > "$rf/config/config.env" <<ENV
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
TLS_AUTOCERT_CACHE_DIR=$rf/new-parent/autocert
ENV
echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$rf/config/gateway.env"
echo 'previous gateway service' > "$rf/units/setjoin-gateway.service"
echo 'previous gateway socket' > "$rf/units/setjoin-gateway.socket"
rf_rc=0
PATH="$rf/bin:$PATH" INSTALL_DIR="$rf/install" SETJOIN_CONFIG_DIR="$rf/config" \
  SYSTEMD_DIR="$rf/units" FED_TEST_HEALTH=1 FED_TEST_LOG="$rf/actions" \
  bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$rf/new/setjoin-server" "$rf/new/mailctl" \
  > "$rf/output" 2>&1 || rf_rc=$?
[ "$rf_rc" != 0 ] || { echo 'expected failed rollback to exit non-zero' >&2; exit 1; }
grep -q 'Incomplete rollback' "$rf/output"
if grep -q 'Restored previous version' "$rf/output"; then
  echo 'unexpected Restored previous version banner after failed TLS cache rollback' >&2
  exit 1
fi

# Immutable layout supports refresh-gateway-env without copying binaries.
im="$tmp/immutable"
mkdir -p "$im/install/releases/r1" "$im/config" "$im/units"
if ln -s "$im/install/releases/r1" "$im/install/current" 2>/dev/null && [ -L "$im/install/current" ]; then
  echo 'immut server' > "$im/install/current/setjoin-server"
  cat > "$im/config/config.env" <<'ENV'
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
  WORM_MODE = compliance
  WORM_LEGAL_HOLD_ENABLED = false
S3_BUCKET=immut-blobs
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
ENV
  printf 'TLS_AUTOCERT_CACHE_DIR=%s/autocert\n' "$im" >> "$im/config/config.env"
  echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$im/config/gateway.env"
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
    SYSTEMD_DIR="$im/units" FED_TEST_LOG="$im/actions" \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env
  grep -qx 'WORM_MODE=compliance' "$im/config/gateway.env"
  grep -qx 'WORM_LEGAL_HOLD_ENABLED=false' "$im/config/gateway.env"
  grep -qx 'S3_BUCKET=immut-blobs' "$im/config/storage.env"
  grep -qx "EnvironmentFile=-$im/config/storage.env" "$im/units/setjoin-gateway.service"
  grep -qx "ExecStart=$im/install/current/setjoin-server" "$im/units/setjoin-gateway.service"

  # Failed refresh-gateway-env rolls back unit/config files without stopping setjoin-gateway.
  : > "$im/actions"
  cp "$im/config/config.env" "$im/config.before"
  cp "$im/config/gateway.env" "$im/gateway.before"
  printf 'TLS_AUTOCERT_CACHE_DIR=/srv/postgres/bad\n' >> "$im/config/config.env"
  bad_rc=0
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
    SYSTEMD_DIR="$im/units" FED_TEST_LOG="$im/actions" UPDATER_STATE_DIR="$im/updater" \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env 2>/dev/null || bad_rc=$?
  [ "$bad_rc" != 0 ] || { echo 'expected bad refresh-gateway-env to fail' >&2; exit 1; }
  if grep -qx 'stop setjoin-gateway' "$im/actions"; then echo 'refresh-gateway-env rollback stopped setjoin-gateway' >&2; exit 1; fi
  diff -u "$im/gateway.before" "$im/config/gateway.env"

  # Restore valid config.env before testing partial-enable rollback and lock contention.
  cp "$im/config.before" "$im/config/config.env"
  mkdir -p "$im/before-enable-cfg" "$im/before-enable-units"
  cp -a "$im/config/." "$im/before-enable-cfg/"
  cp -a "$im/units/." "$im/before-enable-units/"
  : > "$im/actions"
  cat >> "$im/config/config.env" <<'ENV'
FEDERATION_ENABLED=true
FEDERATION_LOCAL_DOMAIN=zulu.test
FEDERATION_CERT=/fixture/leaf.crt
FEDERATION_KEY=/fixture/leaf.key
FEDERATION_LISTEN_ADDR=127.0.0.1:17443
ENV
  en_rc=0
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
    SYSTEMD_DIR="$im/units" FED_TEST_LOG="$im/actions" UPDATER_STATE_DIR="$im/updater" \
    FED_TEST_ENABLED_SOCKETS="" FED_TEST_FAIL_ENABLE="setjoin-federation.socket" \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env 2>/dev/null || en_rc=$?
  [ "$en_rc" != 0 ] || { echo 'expected partial socket enable failure in refresh-gateway-env' >&2; exit 1; }
  if grep -qx 'stop setjoin-gateway' "$im/actions"; then echo 'refresh-gateway-env enable rollback stopped setjoin-gateway' >&2; exit 1; fi
  grep -qx 'enable setjoin-https.socket' "$im/actions"
  grep -qx 'disable setjoin-https.socket' "$im/actions"
  diff -ru "$im/before-enable-units" "$im/units"

  # Partial-enable rollback restores prior enabled-runtime sockets with --runtime instead of making them permanent.
  cp "$im/config.before" "$im/config/config.env"
  : > "$im/actions"
  cat >> "$im/config/config.env" <<'ENV'
FEDERATION_ENABLED=true
FEDERATION_LOCAL_DOMAIN=zulu.test
FEDERATION_CERT=/fixture/leaf.crt
FEDERATION_KEY=/fixture/leaf.key
FEDERATION_LISTEN_ADDR=127.0.0.1:17443
ENV
  rt_rc=0
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
    SYSTEMD_DIR="$im/units" FED_TEST_LOG="$im/actions" UPDATER_STATE_DIR="$im/updater" \
    FED_TEST_ENABLED_SOCKETS="" FED_TEST_RUNTIME_SOCKETS="setjoin-https.socket" \
    FED_TEST_FAIL_ENABLE="setjoin-federation.socket" \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env 2>/dev/null || rt_rc=$?
  [ "$rt_rc" != 0 ] || { echo 'expected runtime socket rollback failure in refresh-gateway-env' >&2; exit 1; }
  if grep -qx 'stop setjoin-gateway' "$im/actions"; then echo 'runtime enable rollback stopped setjoin-gateway' >&2; exit 1; fi
  grep -qx 'disable setjoin-https.socket' "$im/actions"
  grep -qx 'enable --runtime setjoin-https.socket' "$im/actions"
  test "$(grep -xc 'enable setjoin-https.socket' "$im/actions")" = 1
  diff -ru "$im/before-enable-units" "$im/units"

  # Failed daemon-reload during refresh-gateway-env rollback surfaces Incomplete refresh rollback.
  cp "$im/config.before" "$im/config/config.env"
  dr_rc=0
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
    SYSTEMD_DIR="$im/units" FED_TEST_LOG="$im/actions" UPDATER_STATE_DIR="$im/updater" \
    FED_TEST_FAIL_DAEMON_RELOAD=1 \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env >"$im/dr.out" 2>&1 || dr_rc=$?
  [ "$dr_rc" != 0 ] || { echo 'expected daemon-reload failure in refresh-gateway-env' >&2; exit 1; }
  grep -q 'Incomplete refresh rollback' "$im/dr.out"

  # Restore valid config.env before testing lock contention with valid inputs.
  cp "$im/config.before" "$im/config/config.env"
  if command -v flock >/dev/null 2>&1; then
    mkdir -p "$im/updater-journal" "$im/before-im-cfg" "$im/before-im-units"
    printf '[Service]\nExecStart=/usr/libexec/setjoin-updater run --state-dir=%s/updater-journal --release-store=%s/rel\n# old --state-dir=/nonexistent/comment\n' "$im" "$im" > "$im/units/setjoin-updater.service"
    cp -a "$im/config/." "$im/before-im-cfg/"
    cp -a "$im/units/." "$im/before-im-units/"
    exec 8>"$im/updater-journal/executor.lock"
    flock 8
    lock_rc=0
    PATH="$tmp/bin:$PATH" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
      SYSTEMD_DIR="$im/units" FED_TEST_LOG="$im/actions" \
      bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env >"$im/lock.out" 2>&1 || lock_rc=$?
    exec 8>&-
    [ "$lock_rc" != 0 ] || { echo 'expected executor.lock contention to refuse refresh' >&2; exit 1; }
    grep -Eq 'active signed update holds .*executor\.lock' "$im/lock.out"
    diff -ru "$im/before-im-cfg" "$im/config"
    diff -ru "$im/before-im-units" "$im/units"
  fi
fi
# Release N -> N+1 static-HTTPS upgrade (with default install.sh HTTP_MODE=proxy)
# keeps setjoin-https.socket, strips retired tls-ticket-keys / http-port80,
# and stops/disables/removes legacy setjoin-acme.socket (and restores it on rollback).
for reln_health in 0 1; do
  rn="$tmp/reln-$reln_health"
  mkdir -p "$rn/install" "$rn/new" "$rn/config" "$rn/units" "$rn/before-units"
  echo 'old setjoin-server' > "$rn/install/setjoin-server"
  echo 'new setjoin-server' > "$rn/new/setjoin-server"
  printf '#!/bin/sh\nexit 0\n' > "$rn/new/mailctl"
  chmod 755 "$rn/new/mailctl"
  cat > "$rn/config/config.env" <<ENV
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
HTTP_MODE=proxy
LISTEN_ADDR=:443
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
GO_WORKERS_OFF="backup-engine,tls-ticket-keys,http-port80"
RUST_WORKERS_ON="notify-intent-drain,tls-ticket-keys,http-port80"
TLS_AUTOCERT_CACHE_DIR=$rn/autocert
ENV
  echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$rn/config/gateway.env"
  echo 'previous gateway service' > "$rn/units/setjoin-gateway.service"
  echo 'previous gateway socket' > "$rn/units/setjoin-gateway.socket"
  echo 'previous ACME socket' > "$rn/units/setjoin-acme.socket"
  cp -a "$rn/units/." "$rn/before-units/"
  rn_rc=0
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$rn/install" SETJOIN_CONFIG_DIR="$rn/config" \
    SYSTEMD_DIR="$rn/units" FED_TEST_HEALTH="$reln_health" FED_TEST_LOG="$rn/actions" \
    FED_TEST_ENABLED_SOCKETS="setjoin-acme.socket" \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$rn/new/setjoin-server" "$rn/new/mailctl" \
    > "$rn/output" 2>&1 || rn_rc=$?
  if [ "$reln_health" = 0 ]; then
    [ "$rn_rc" = 0 ] || { cat "$rn/output" >&2; exit 1; }
    if grep -Eq '(tls-ticket-keys|http-port80)' "$rn/config/config.env" "$rn/config/federation.env"; then
      echo 'Release N retired worker leaked after upgrade' >&2
      exit 1
    fi
    grep -qx 'RUST_WORKERS_ON=notify-intent-drain,federation-residue-reap,cert-monitor,http-tls,http-h2c' "$rn/config/config.env"
    test -s "$rn/units/setjoin-https.socket"
    grep -qx 'stop setjoin-acme.socket' "$rn/actions"
    grep -qx 'disable setjoin-acme.socket' "$rn/actions"
    test ! -e "$rn/units/setjoin-acme.socket"
  else
    [ "$rn_rc" != 0 ] || { echo 'expected failed Release N upgrade rollback' >&2; exit 1; }
    diff -ru "$rn/before-units" "$rn/units"
    grep -qx 'enable setjoin-acme.socket' "$rn/actions"
    grep -qx 'start setjoin-acme.socket' "$rn/actions"
  fi
done

# Switching an active native-HTTPS host to TLS_EDGE_PROXY=true via refresh-gateway-env
# explicitly stops, disables, and removes setjoin-https.socket so port 443 is freed.
ep="$tmp/edge-proxy-transition"
mkdir -p "$ep/install/releases/r1" "$ep/config" "$ep/units"
if ln -s "$ep/install/releases/r1" "$ep/install/current" 2>/dev/null && [ -L "$ep/install/current" ]; then
  echo 'immut server' > "$ep/install/current/setjoin-server"
  cat > "$ep/config/config.env" <<ENV
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
HTTP_MODE=proxy
TLS_EDGE_PROXY=true
GO_WORKERS_OFF=backup-engine,cert-monitor,http-tls,http-h2c
RUST_WORKERS_ON=notify-intent-drain,cert-monitor,http-tls,http-h2c
DB_DSN=postgres://app@fixture/db
DB_DIRECT_DSN=postgres://app@fixture/db
TLS_AUTOCERT_CACHE_DIR=$ep/autocert
ENV
  echo 'GATEWAY_LISTEN=127.0.0.1:18090' > "$ep/config/gateway.env"
  echo 'active https socket' > "$ep/units/setjoin-https.socket"
  PATH="$tmp/bin:$PATH" INSTALL_DIR="$ep/install" SETJOIN_CONFIG_DIR="$ep/config" \
    SYSTEMD_DIR="$ep/units" FED_TEST_LOG="$ep/actions" \
    bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" refresh-gateway-env
  grep -qx 'stop setjoin-https.socket' "$ep/actions"
  grep -qx 'disable setjoin-https.socket' "$ep/actions"
  test ! -e "$ep/units/setjoin-https.socket"
  grep -qx 'TLS_CERT=/fixture/leaf.crt' "$ep/config/tls.env"
  if grep -Eq '(http-tls|cert-monitor)' "$ep/config/config.env" "$ep/config/federation.env"; then
    echo 'TLS_EDGE_PROXY=true refresh retained http-tls/cert-monitor' >&2
    exit 1
  fi
fi

# Flat upgrade with retired ACME config fails closed BEFORE stopping services or running migrations.
ra="$tmp/retired-acme-preflight"
mkdir -p "$ra/install" "$ra/new" "$ra/config" "$ra/units"
echo 'old setjoin-server' > "$ra/install/setjoin-server"
echo 'new setjoin-server' > "$ra/new/setjoin-server"
printf '#!/bin/sh\necho RAN_MIGRATION > "%s/mig.log"\nexit 0\n' "$ra" > "$ra/new/mailctl"
chmod 755 "$ra/new/mailctl"
printf 'TLS_AUTOCERT_DOMAINS=mail.example.test\nDB_DSN=postgres://app@fixture/db\n' > "$ra/config/config.env"
ra_rc=0
PATH="$tmp/bin:$PATH" INSTALL_DIR="$ra/install" SETJOIN_CONFIG_DIR="$ra/config" \
  SYSTEMD_DIR="$ra/units" FED_TEST_HEALTH=0 FED_TEST_LOG="$ra/actions" \
  bash "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$ra/new/setjoin-server" "$ra/new/mailctl" \
  > "$ra/output" 2>&1 || ra_rc=$?
[ "$ra_rc" != 0 ] || { echo 'expected flat upgrade to refuse retired ACME config' >&2; exit 1; }
[ ! -e "$ra/mig.log" ] || { echo 'flat upgrade ran migration before ACME preflight' >&2; exit 1; }
[ ! -s "$ra/actions" ] || { echo 'flat upgrade invoked service manager before ACME preflight' >&2; exit 1; }

echo 'TLS front upgrade activation and previous-release rollback: PASS'
