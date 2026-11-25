#!/usr/bin/env bash
# Exercise the legacy upgrade command against an isolated, flat installation:
# a failed migration restores the Go binaries and the Rust front door from
# their *.prev copies (#264).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
UPGRADE_SCRIPT="${UPGRADE_SCRIPT:-$ROOT/mailserver/deploy/scripts/upgrade.sh}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/gofree-t13-upgrade-rollback.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/install/webmail" "$tmp/new/webmail" "$tmp/config" "$tmp/units"

cat >"$tmp/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$UPGRADE_TEST_LOG"
MOCK
cat >"$tmp/bin/chown" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod 755 "$tmp/bin/systemctl" "$tmp/bin/chown"
printf 'old mailserver\n' >"$tmp/install/mailserverd"
printf 'old authserver\n' >"$tmp/install/authserverd"
printf 'old mailctl\n' >"$tmp/install/mailctl"
printf 'old gateway\n' >"$tmp/install/setjoin-gateway"
printf 'old webmail\n' >"$tmp/install/webmail/index.html"
printf 'new mailserver\n' >"$tmp/new/mailserverd"
printf 'new authserver\n' >"$tmp/new/authserverd"
printf 'new gateway\n' >"$tmp/new/setjoin-gateway"
printf 'new webmail\n' >"$tmp/new/webmail/index.html"
cat >"$tmp/new/mailctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$UPGRADE_TEST_MIGRATION"
exit 1
MOCK
chmod 755 "$tmp/new/mailctl"
printf 'DB_DSN=postgres://fixture/only\n' >"$tmp/config/config.env"

if PATH="$tmp/bin:$PATH" INSTALL_DIR="$tmp/install" SETJOIN_CONFIG_DIR="$tmp/config" \
  SYSTEMD_DIR="$tmp/units" UPGRADE_TEST_LOG="$tmp/systemctl.log" UPGRADE_TEST_MIGRATION="$tmp/migration.log" \
  bash "$UPGRADE_SCRIPT" "$tmp/new/mailserverd" "$tmp/new/mailctl" \
  "$tmp/new/webmail" "$tmp/new/authserverd" "$tmp/new/setjoin-gateway" >"$tmp/output" 2>&1; then
  echo 'failed migration was reported as a successful upgrade' >&2
  exit 1
fi
[ "$(cat "$tmp/migration.log")" = 'schema apply --yes' ] || {
  echo 'migration was not attempted' >&2
  exit 1
}
for artifact in mailserverd authserverd mailctl setjoin-gateway; do
  case "$artifact" in
    mailserverd) expected='old mailserver' ;;
    authserverd) expected='old authserver' ;;
    mailctl) expected='old mailctl' ;;
    setjoin-gateway) expected='old gateway' ;;
  esac
  [ "$(cat "$tmp/install/$artifact")" = "$expected" ] || {
    echo "$artifact was not restored" >&2
    exit 1
  }
  [ "$(cat "$tmp/install/$artifact.prev")" = "$expected" ] || {
    echo "$artifact.prev does not contain the previous binary" >&2
    exit 1
  }
done
[ "$(cat "$tmp/install/webmail/index.html")" = 'old webmail' ] || {
  echo 'webmail was not restored' >&2
  exit 1
}
[ "$(cat "$tmp/install/webmail.prev/index.html")" = 'old webmail' ] || {
  echo 'webmail.prev does not contain previous content' >&2
  exit 1
}
# Note: `$tmp/units` has no installed unit files, so `restore_gateway_deployment`
# guards its secondary `stop`/`disable` calls with `[ -e "$SYSTEMD_DIR/$unit" ]`
# (avoiding false rollback errors on uninstalled sockets) and proceeds straight
# to `daemon-reload` + service restart.
expected=$'stop setjoin-gateway\nstop setjoin-federation.socket\nstop setjoin-https.socket\ndisable setjoin-https.socket\nstop setjoin-acme.socket\ndisable setjoin-acme.socket\nstop setjoin-imap.socket\ndisable setjoin-imap.socket\nstop setjoin-imaps.socket\ndisable setjoin-imaps.socket\nstop setjoin-smtp.socket\ndisable setjoin-smtp.socket\nstop setjoin-smtps.socket\ndisable setjoin-smtps.socket\nstop setjoin-submission.socket\ndisable setjoin-submission.socket\nstop setjoin\nis-active --quiet setjoin-auth\nstop setjoin-auth\ndaemon-reload\nstart setjoin-auth\nstart setjoin\nstart setjoin-gateway'
[ "$(cat "$tmp/systemctl.log")" = "$expected" ] || {
  echo 'unexpected stop/restart actions' >&2
  cat "$tmp/systemctl.log" >&2
  exit 1
}
echo 'legacy upgrade rollback (Go + Rust *.prev): PASS'

# ── Upgraded-host auth.env migration + posture refusal + rollback (#359b) ────
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
owner="$(id -un)"
group="$(id -gn)"
real_tmp="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$tmp")"

# 1. Immutable host refresh-gateway-env migrates auth.env (with DB_WORKER_DSN +
#    TRUSTED_PROXY_IP=127.0.0.1) and setjoin-auth.service (Rust setjoin-auth,
#    no EnvironmentFile={{DB_CREDENTIALS_FILE}}).
im="$real_tmp/auth-mig"
mkdir -p "$im/install/releases/r1" "$im/config/db-credentials.d" "$im/units"
printf '#!/bin/sh\nexit 0\n' >"$im/install/releases/r1/setjoin-auth"
chmod 755 "$im/install/releases/r1/setjoin-auth"
ln -s "$im/install/releases/r1" "$im/install/current"
cat >"$im/config/config.env" <<'ENV'
DB_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
DB_DIRECT_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
AUTHSERVER_URL=http://127.0.0.1:8443
ENV
cat >"$im/config/db-credentials.d/db-credentials.env" <<'ENV'
DB_WORKER_DSN=postgres://setjoin_worker:workerpw@127.0.0.1:5432/mailserver
DB_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
DB_DIRECT_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
ENV
printf 'LISTEN_ADDR=127.0.0.1:8443\nTLS_CERT=\nTLS_KEY=\n' >"$im/config/auth.env"
printf 'GATEWAY_LISTEN=127.0.0.1:18090\nGATEWAY_AUTH_UPSTREAM=http://127.0.0.1:8443\n' >"$im/config/gateway.env"
printf '[Service]\nExecStart=%s/install/current/authserverd\nEnvironmentFile=%s/config/db-credentials.d/db-credentials.env\n' "$im" "$im" >"$im/units/setjoin-auth.service"
chgrp "$group" "$im/config" "$im/config/db-credentials.d" "$im/config/db-credentials.d/db-credentials.env"
chmod 755 "$im/config"
chmod 750 "$im/config/db-credentials.d"
chmod 600 "$im/config/db-credentials.d/db-credentials.env" "$im/config/config.env" "$im/config/auth.env"

PATH="$tmp/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
  SYSTEMD_DIR="$im/units" TLS_AUTOCERT_CACHE_DIR="$im/autocert" UPGRADE_TEST_LOG="$im/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  bash "$UPGRADE_SCRIPT" refresh-gateway-env >"$im/refresh.out" 2>&1 || {
  cat "$im/refresh.out" >&2
  echo 'auth.env migration refresh-gateway-env failed' >&2
  exit 1
}
[ "$(mode_of "$im/config/auth.env")" = "600" ] || {
  echo 'migrated auth.env is not mode 600' >&2
  exit 1
}
grep -qx 'LISTEN_ADDR=127.0.0.1:8443' "$im/config/auth.env"
grep -qx 'TLS_CERT=' "$im/config/auth.env"
grep -qx 'TLS_KEY=' "$im/config/auth.env"
grep -qx 'TRUSTED_PROXY_IP=127.0.0.1' "$im/config/auth.env"
grep -qx 'DB_WORKER_DSN=postgres://setjoin_worker:workerpw@127.0.0.1:5432/mailserver' "$im/config/auth.env"
! grep -Eq 'DB_OWNER_DSN|DB_DIRECT_OWNER_DSN|AUTHSERVER_GO_UPSTREAM' "$im/config/auth.env" || {
  echo 'migrated auth.env leaked owner DSN or Go upstream' >&2
  exit 1
}
grep -qx "ExecStart=$im/install/current/setjoin-auth" "$im/units/setjoin-auth.service"
grep -qx "EnvironmentFile=$im/config/config.env" "$im/units/setjoin-auth.service"
grep -qx "EnvironmentFile=$im/config/auth.env" "$im/units/setjoin-auth.service"
! grep -Eq 'db-credentials\.env|setjoin-authserverd|auth/login' "$im/units/setjoin-auth.service" || {
  echo 'migrated setjoin-auth.service retained legacy credential file or Go chaining' >&2
  exit 1
}
grep -qx 'GATEWAY_RUST_AUTH_UPSTREAM=http://127.0.0.1:8443' "$im/config/gateway.env"
! grep -Eq '^GATEWAY_(UPSTREAM|AUTH_UPSTREAM)=' "$im/config/gateway.env" || {
  echo 'migrated gateway.env retained retired Go upstream vars' >&2
  exit 1
}

# 2. Tampered/widened DB_CRED_FILE posture refuses refresh and restores prior auth.env + unit.
cp "$im/config/auth.env" "$im/auth.env.before"
cp "$im/units/setjoin-auth.service" "$im/setjoin-auth.service.before"
chmod 644 "$im/config/db-credentials.d/db-credentials.env"
if PATH="$tmp/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
  SYSTEMD_DIR="$im/units" TLS_AUTOCERT_CACHE_DIR="$im/autocert" UPGRADE_TEST_LOG="$im/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  bash "$UPGRADE_SCRIPT" refresh-gateway-env >"$im/bad-posture.out" 2>&1; then
  echo 'widened DB_CRED_FILE was accepted during auth.env migration' >&2
  exit 1
fi
cmp -s "$im/auth.env.before" "$im/config/auth.env" || {
  echo 'auth.env not restored after posture failure' >&2
  exit 1
}
cmp -s "$im/setjoin-auth.service.before" "$im/units/setjoin-auth.service" || {
  echo 'setjoin-auth.service not restored after posture failure' >&2
  exit 1
}

# 3. Failed flat upgrade rolls back BOTH auth.env and setjoin-auth.service from $DEPLOYMENT_PREV.
fl="$real_tmp/auth-flat-rb"
mkdir -p "$fl/bin" "$fl/install" "$fl/new" "$fl/config/db-credentials.d" "$fl/units"
cp "$tmp/bin/systemctl" "$tmp/bin/chown" "$fl/bin/"
printf '#!/usr/bin/env bash\nexit 1\n' >"$fl/bin/curl"
printf '#!/usr/bin/env bash\nexit 0\n' >"$fl/bin/sleep"
chmod 755 "$fl/bin/curl" "$fl/bin/sleep"
printf 'old mailserver\n' >"$fl/install/mailserverd"
printf 'old authserver\n' >"$fl/install/authserverd"
printf 'old setjoin-auth\n' >"$fl/install/setjoin-auth"
printf 'old gateway\n' >"$fl/install/setjoin-gateway"
printf 'new mailserver\n' >"$fl/new/mailserverd"
printf 'new setjoin-auth\n' >"$fl/new/setjoin-auth"
printf 'new gateway\n' >"$fl/new/setjoin-gateway"
chmod 755 "$fl/install/setjoin-auth" "$fl/new/setjoin-auth"
printf '#!/bin/sh\nexit 0\n' >"$fl/new/mailctl"
chmod 755 "$fl/new/mailctl"
cat >"$fl/config/config.env" <<'ENV'
DB_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
DB_DIRECT_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
AUTHSERVER_URL=http://127.0.0.1:8443
ENV
cat >"$fl/config/db-credentials.d/db-credentials.env" <<'ENV'
DB_WORKER_DSN=postgres://setjoin_worker:workerpw@127.0.0.1:5432/mailserver
DB_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
DB_DIRECT_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
ENV
printf '# old auth env\nLISTEN_ADDR=127.0.0.1:8443\n' >"$fl/config/auth.env"
printf 'GATEWAY_LISTEN=127.0.0.1:18090\n' >"$fl/config/gateway.env"
printf '# old auth unit\n[Service]\nExecStart=%s/install/authserverd\n' "$fl" >"$fl/units/setjoin-auth.service"
chgrp "$group" "$fl/config" "$fl/config/db-credentials.d" "$fl/config/db-credentials.d/db-credentials.env"
chmod 755 "$fl/config"
chmod 750 "$fl/config/db-credentials.d"
chmod 600 "$fl/config/db-credentials.d/db-credentials.env" "$fl/config/config.env" "$fl/config/auth.env"
cp "$fl/config/auth.env" "$fl/auth.env.before"
cp "$fl/units/setjoin-auth.service" "$fl/setjoin-auth.service.before"

if PATH="$fl/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$fl/install" SETJOIN_CONFIG_DIR="$fl/config" \
  SYSTEMD_DIR="$fl/units" TLS_AUTOCERT_CACHE_DIR="$fl/autocert" UPGRADE_TEST_LOG="$fl/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  bash "$UPGRADE_SCRIPT" "$fl/new/mailserverd" "$fl/new/mailctl" '' "$fl/new/setjoin-auth" "$fl/new/setjoin-gateway" >"$fl/out" 2>&1; then
  echo 'failed readiness flat upgrade reported success' >&2
  exit 1
fi
grep -q 'Health check FAILED' "$fl/out" || {
  cat "$fl/out" >&2
  echo 'expected readiness failure after auth/gateway render before rollback' >&2
  exit 1
}
cmp -s "$fl/auth.env.before" "$fl/config/auth.env" || {
  echo 'auth.env was not rolled back after readiness failure' >&2
  exit 1
}
cmp -s "$fl/setjoin-auth.service.before" "$fl/units/setjoin-auth.service" || {
  echo 'setjoin-auth.service was not rolled back after readiness failure' >&2
  exit 1
}
[ "$(cat "$fl/install/setjoin-auth")" = 'old setjoin-auth' ] || {
  echo 'setjoin-auth binary was not rolled back' >&2
  exit 1
}

# 4. Pre-#359 immutable host without setjoin-auth binary does NOT overwrite setjoin-auth.service.
rm -f "$im/install/releases/r1/setjoin-auth"
chmod 600 "$im/config/db-credentials.d/db-credentials.env"
printf '[Service]\nExecStart=%s/install/current/authserverd\n' "$im" >"$im/units/setjoin-auth.service"
cp "$im/units/setjoin-auth.service" "$im/units/setjoin-auth.service.pre359"
PATH="$tmp/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$im/install" SETJOIN_CONFIG_DIR="$im/config" \
  SYSTEMD_DIR="$im/units" TLS_AUTOCERT_CACHE_DIR="$im/autocert" UPGRADE_TEST_LOG="$im/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  bash "$UPGRADE_SCRIPT" refresh-gateway-env >"$im/pre359.out" 2>&1 || {
  cat "$im/pre359.out" >&2
  echo 'pre-#359 refresh-gateway-env failed' >&2
  exit 1
}
cmp -s "$im/units/setjoin-auth.service.pre359" "$im/units/setjoin-auth.service" || {
  echo 'pre-#359 refresh-gateway-env overwrote setjoin-auth.service without setjoin-auth binary' >&2
  exit 1
}
echo 'upgraded-host auth.env migration + posture check + rollback: PASS'
