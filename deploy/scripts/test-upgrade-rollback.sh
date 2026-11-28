#!/usr/bin/env bash
# Exercise the flat upgrade command against isolated installations:
#   A. post-#142 Rust-only flat host: a failed migration restores setjoin-server,
#      setjoin-auth, mailctl, and webmail from their *.prev copies;
#   B. pre-#142 cutover host (mailserverd + setjoin-gateway + setjoin.service):
#      - failed cutover rolls back binaries AND unit files (including restoring
#        setjoin.service and removing the newly installed setjoin-server),
#      - successful cutover retires setjoin.service and installs setjoin-server
#        + updated setjoin-gateway.service;
#   C. upgraded-host auth.env migration + posture refusal + rollback (#359b).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UPGRADE_SCRIPT="${UPGRADE_SCRIPT:-$ROOT/deploy/scripts/upgrade.sh}"
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

# ── A. Post-#142 Rust-only flat upgrade rollback on failed migration ─────────
printf 'old server\n' >"$tmp/install/setjoin-server"
printf 'old setjoin-auth\n' >"$tmp/install/setjoin-auth"
printf 'old mailctl\n' >"$tmp/install/mailctl"
printf 'old webmail\n' >"$tmp/install/webmail/index.html"
printf 'new server\n' >"$tmp/new/setjoin-server"
printf 'new setjoin-auth\n' >"$tmp/new/setjoin-auth"
printf 'new webmail\n' >"$tmp/new/webmail/index.html"
cat >"$tmp/new/mailctl" <<'MOCK'
#!/usr/bin/env bash
if [ "$1" = "schema" ] && [ "$2" = "preflight" ]; then
  exit 0
fi
printf '%s\n' "$*" > "$UPGRADE_TEST_MIGRATION"
exit 1
MOCK
chmod 755 "$tmp/new/mailctl"
printf 'DB_DSN=postgres://fixture/only\n' >"$tmp/config/config.env"

if PATH="$tmp/bin:$PATH" INSTALL_DIR="$tmp/install" SETJOIN_CONFIG_DIR="$tmp/config" \
  SYSTEMD_DIR="$tmp/units" UPGRADE_TEST_LOG="$tmp/systemctl.log" UPGRADE_TEST_MIGRATION="$tmp/migration.log" \
  bash "$UPGRADE_SCRIPT" "$tmp/new/setjoin-server" "$tmp/new/mailctl" \
  "$tmp/new/webmail" "$tmp/new/setjoin-auth" >"$tmp/output" 2>&1; then
  echo 'failed migration was reported as a successful upgrade' >&2
  exit 1
fi
[ "$(cat "$tmp/migration.log")" = 'schema apply --yes' ] || {
  echo 'migration was not attempted' >&2
  exit 1
}
for artifact in setjoin-server setjoin-auth mailctl; do
  case "$artifact" in
    setjoin-server) expected='old server' ;;
    setjoin-auth) expected='old setjoin-auth' ;;
    mailctl) expected='old mailctl' ;;
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
expected=$'stop setjoin-gateway\nstop setjoin-federation.socket\nstop setjoin-https.socket\ndisable setjoin-https.socket\nstop setjoin-imap.socket\ndisable setjoin-imap.socket\nstop setjoin-imaps.socket\ndisable setjoin-imaps.socket\nstop setjoin-smtp.socket\ndisable setjoin-smtp.socket\nstop setjoin-smtps.socket\ndisable setjoin-smtps.socket\nstop setjoin-submission.socket\ndisable setjoin-submission.socket\nis-active --quiet setjoin-auth\nstop setjoin-auth\ndaemon-reload\nstart setjoin-auth\nstart setjoin-gateway'
[ "$(cat "$tmp/systemctl.log")" = "$expected" ] || {
  echo 'unexpected stop/restart actions' >&2
  cat "$tmp/systemctl.log" >&2
  exit 1
}
echo 'Rust-only flat upgrade rollback (*.prev): PASS'

# ── B. Pre-#142 cutover host (setjoin-gateway + setjoin.service) ─────────────
real_tmp="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$tmp")"
owner="$(id -un)"
group="$(id -gn)"
for cutover_health in fail ok; do
  pre="$real_tmp/pre142-$cutover_health"
  mkdir -p "$pre/bin" "$pre/install/webmail" "$pre/new/webmail" "$pre/config/db-credentials.d" "$pre/units"
  cp "$tmp/bin/systemctl" "$tmp/bin/chown" "$pre/bin/"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$pre/bin/sleep"
  if [ "$cutover_health" = ok ]; then
    printf '#!/usr/bin/env bash\nexit 0\n' >"$pre/bin/curl"
  else
    printf '#!/usr/bin/env bash\nexit 1\n' >"$pre/bin/curl"
  fi
  chmod 755 "$pre/bin/curl" "$pre/bin/sleep"
  printf 'old mailserverd\n' >"$pre/install/mailserverd"
  printf 'old authserverd\n' >"$pre/install/authserverd"
  printf 'old setjoin-gateway\n' >"$pre/install/setjoin-gateway"
  printf 'old mailctl\n' >"$pre/install/mailctl"
  printf 'old webmail\n' >"$pre/install/webmail/index.html"
  printf 'new setjoin-server\n' >"$pre/new/setjoin-server"
  printf 'new setjoin-auth\n' >"$pre/new/setjoin-auth"
  printf 'new webmail\n' >"$pre/new/webmail/index.html"
  chmod 755 "$pre/new/setjoin-server" "$pre/new/setjoin-auth"
  printf '#!/bin/sh\nexit 0\n' >"$pre/new/mailctl"
  chmod 755 "$pre/new/mailctl"
  cat >"$pre/config/config.env" <<'ENV'
DB_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
DB_DIRECT_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
AUTHSERVER_URL=http://127.0.0.1:8443
ENV
  cat >"$pre/config/db-credentials.d/db-credentials.env" <<'ENV'
DB_WORKER_DSN=postgres://setjoin_worker:workerpw@127.0.0.1:5432/mailserver
DB_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
DB_DIRECT_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
ENV
  printf 'GATEWAY_LISTEN=127.0.0.1:18090\n' >"$pre/config/gateway.env"
  printf '[Unit]\nDescription=Legacy Go mailserverd\n[Service]\nExecStart=%s/install/mailserverd\n' "$pre" >"$pre/units/setjoin.service"
  printf '[Unit]\nAfter=setjoin.service\n[Service]\nExecStart=%s/install/setjoin-gateway\n' "$pre" >"$pre/units/setjoin-gateway.service"
  printf '[Socket]\nListenStream=127.0.0.1:18090\n' >"$pre/units/setjoin-gateway.socket"
  printf '[Service]\nExecStart=%s/install/authserverd\n' "$pre" >"$pre/units/setjoin-auth.service"
  chgrp "$group" "$pre/config" "$pre/config/db-credentials.d" "$pre/config/db-credentials.d/db-credentials.env"
  chmod 755 "$pre/config"
  chmod 750 "$pre/config/db-credentials.d"
  chmod 600 "$pre/config/db-credentials.d/db-credentials.env" "$pre/config/config.env"
  cp "$pre/units/setjoin.service" "$pre/setjoin.service.before"
  cp "$pre/units/setjoin-gateway.service" "$pre/setjoin-gateway.service.before"

  rc=0
  PATH="$pre/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$pre/install" SETJOIN_CONFIG_DIR="$pre/config" \
    SYSTEMD_DIR="$pre/units" TLS_AUTOCERT_CACHE_DIR="$pre/autocert" UPGRADE_TEST_LOG="$pre/systemctl.log" \
    DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
    bash "$UPGRADE_SCRIPT" "$pre/new/setjoin-server" "$pre/new/mailctl" \
    "$pre/new/webmail" "$pre/new/setjoin-auth" >"$pre/out" 2>&1 || rc=$?
  if [ "$cutover_health" = ok ]; then
    [ "$rc" = 0 ] || {
      cat "$pre/out" >&2
      echo 'pre-#142 cutover failed unexpectedly' >&2
      exit 1
    }
    [ ! -e "$pre/units/setjoin.service" ] || {
      echo 'pre-#142 cutover did not remove setjoin.service' >&2
      exit 1
    }
    [ "$(cat "$pre/install/setjoin-server")" = 'new setjoin-server' ] || {
      echo 'setjoin-server not installed' >&2
      exit 1
    }
    [ "$(cat "$pre/install/setjoin-gateway.prev")" = 'old setjoin-gateway' ] || {
      echo 'setjoin-gateway.prev missing' >&2
      exit 1
    }
    [ "$(cat "$pre/install/mailserverd.prev")" = 'old mailserverd' ] || {
      echo 'mailserverd.prev missing' >&2
      exit 1
    }
    grep -qx "ExecStart=$pre/install/setjoin-server" "$pre/units/setjoin-gateway.service"
    grep -qx 'stop setjoin' "$pre/systemctl.log"
    grep -qx 'disable setjoin' "$pre/systemctl.log"
    ! grep -qx 'start setjoin' "$pre/systemctl.log" || {
      echo 'cutover started retired setjoin.service' >&2
      exit 1
    }
  else
    [ "$rc" != 0 ] || {
      echo 'failed pre-#142 cutover reported success' >&2
      exit 1
    }
    [ ! -e "$pre/install/setjoin-server" ] || {
      echo 'failed cutover left setjoin-server behind' >&2
      exit 1
    }
    [ "$(cat "$pre/install/setjoin-gateway")" = 'old setjoin-gateway' ] || {
      echo 'setjoin-gateway not restored' >&2
      exit 1
    }
    [ "$(cat "$pre/install/mailserverd")" = 'old mailserverd' ] || {
      echo 'mailserverd not restored' >&2
      exit 1
    }
    [ "$(cat "$pre/install/authserverd")" = 'old authserverd' ] || {
      echo 'authserverd not restored' >&2
      exit 1
    }
    cmp -s "$pre/setjoin.service.before" "$pre/units/setjoin.service" || {
      echo 'setjoin.service not restored on rollback' >&2
      exit 1
    }
    cmp -s "$pre/setjoin-gateway.service.before" "$pre/units/setjoin-gateway.service" || {
      echo 'setjoin-gateway.service not restored on rollback' >&2
      exit 1
    }
    grep -qx 'start setjoin' "$pre/systemctl.log"
    grep -qx 'start setjoin-gateway' "$pre/systemctl.log"
  fi
done
echo 'pre-#142 cutover (retire setjoin.service + rollback): PASS'

# ── C. Upgraded-host auth.env migration + posture refusal + rollback (#359b) ─
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

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
printf 'old setjoin-auth\n' >"$fl/install/setjoin-auth"
printf 'old server\n' >"$fl/install/setjoin-server"
printf 'new setjoin-auth\n' >"$fl/new/setjoin-auth"
printf 'new server\n' >"$fl/new/setjoin-server"
chmod 755 "$fl/install/setjoin-auth" "$fl/new/setjoin-auth" "$fl/install/setjoin-server" "$fl/new/setjoin-server"
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
printf '# old auth unit\n[Service]\nExecStart=%s/install/setjoin-auth\n' "$fl" >"$fl/units/setjoin-auth.service"
chgrp "$group" "$fl/config" "$fl/config/db-credentials.d" "$fl/config/db-credentials.d/db-credentials.env"
chmod 755 "$fl/config"
chmod 750 "$fl/config/db-credentials.d"
chmod 600 "$fl/config/db-credentials.d/db-credentials.env" "$fl/config/config.env" "$fl/config/auth.env"
cp "$fl/config/auth.env" "$fl/auth.env.before"
cp "$fl/units/setjoin-auth.service" "$fl/setjoin-auth.service.before"

if PATH="$fl/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$fl/install" SETJOIN_CONFIG_DIR="$fl/config" \
  SYSTEMD_DIR="$fl/units" TLS_AUTOCERT_CACHE_DIR="$fl/autocert" UPGRADE_TEST_LOG="$fl/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  bash "$UPGRADE_SCRIPT" "$fl/new/setjoin-server" "$fl/new/mailctl" '' "$fl/new/setjoin-auth" >"$fl/out" 2>&1; then
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
[ "$(cat "$fl/install/setjoin-server")" = 'old server' ] || {
  echo 'setjoin-server binary was not rolled back' >&2
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

# ── D. Release N shim refusal & Release N+1 setjoind cutover/rollback (#544) ─
# 1. Flat upgrade refuses a Release N shim binary when setjoind is missing.
sh_dir="$real_tmp/shim-refuse"
mkdir -p "$sh_dir/install" "$sh_dir/new" "$sh_dir/config" "$sh_dir/units"
printf 'SETJOIND_SHIM_V1\n' >"$sh_dir/new/setjoin-server"
printf 'SETJOIND_SHIM_V1\n' >"$sh_dir/new/setjoin-auth"
chmod 755 "$sh_dir/new/setjoin-server" "$sh_dir/new/setjoin-auth"
if PATH="$tmp/bin:$PATH" INSTALL_DIR="$sh_dir/install" SETJOIN_CONFIG_DIR="$sh_dir/config" \
  SYSTEMD_DIR="$sh_dir/units" UPGRADE_TEST_LOG="$sh_dir/systemctl.log" \
  bash "$UPGRADE_SCRIPT" "$sh_dir/new/setjoin-server" '' '' "$sh_dir/new/setjoin-auth" >"$sh_dir/out" 2>&1; then
  echo 'shim without setjoind was accepted' >&2
  exit 1
fi
grep -q 'without a companion setjoind' "$sh_dir/out" || {
  cat "$sh_dir/out" >&2
  echo 'expected shim-without-setjoind refusal message' >&2
  exit 1
}

# 2. migrate-to-setjoind preconditions, atomic cutover, refresh-gateway-env, and rollback-to-split-units.
cu="$real_tmp/cutover"
mkdir -p "$cu/bin" "$cu/install/releases/r1" "$cu/install/releases/r2" \
  "$cu/config/db-credentials.d" "$cu/units" "$cu/updater-journal"
cp "$tmp/bin/systemctl" "$tmp/bin/chown" "$cu/bin/"
printf '#!/usr/bin/env bash\nexit 0\n' >"$cu/bin/sleep"
cat >"$cu/bin/curl" <<'MOCK'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    *jwks.json*)
      if [ "${CUTOVER_FAIL_READY:-0}" = "1" ]; then exit 1; fi
      printf '{"keys":[{"kty":"EC"}]}\n'
      exit 0
      ;;
    */ready*|*/health*)
      if [ "${CUTOVER_FAIL_READY:-0}" = "1" ]; then exit 1; fi
      printf '{"status":"ok"}\n'
      exit 0
      ;;
  esac
done
exit 0
MOCK
cat >"$cu/bin/setjoin-recovery" <<'MOCK'
#!/usr/bin/env bash
if [ "${CUTOVER_RECOVERY_REQUIRED:-0}" = "1" ]; then
  printf '{"current":"r2","previous":"r1","intent_id":"1","intent_state":"recovery_required","recovery_required":true,"database_reconciliation_required":false}\n'
else
  printf '{"current":"r2","previous":"r1","intent_id":"1","intent_state":"verified","recovery_required":false,"database_reconciliation_required":false}\n'
fi
MOCK
chmod 755 "$cu/bin/curl" "$cu/bin/sleep" "$cu/bin/setjoin-recovery"
if ! command -v flock >/dev/null 2>&1; then
  cat >"$cu/bin/flock" <<'MOCK'
#!/usr/bin/env bash
if [ "${1:-}" = "-n" ] && [ -n "${2:-}" ]; then
  exec python3 -c 'import fcntl, sys
try:
    fcntl.flock(int(sys.argv[1]), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(1)
' "$2"
fi
exit 1
MOCK
  chmod 755 "$cu/bin/flock"
fi

for rel in r1 r2; do
  printf '#!/bin/sh\nexit 0\n' >"$cu/install/releases/$rel/setjoind"
  printf '#!/bin/sh\nexit 0\n' >"$cu/install/releases/$rel/setjoin-server"
  printf '#!/bin/sh\nexit 0\n' >"$cu/install/releases/$rel/setjoin-auth"
  chmod 755 "$cu/install/releases/$rel/"*
done
ln -s "$cu/install/releases/r1" "$cu/install/previous"
ln -s "$cu/install/releases/r2" "$cu/install/current"

cat >"$cu/config/config.env" <<'ENV'
HOSTNAME=mail.example.test
DB_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
DB_DIRECT_DSN=postgres://setjoin_app:apppw@127.0.0.1:5432/mailserver
AUTHSERVER_URL=http://127.0.0.1:8443
TLS_CERT=/etc/setjoin/certs/server.pem
TLS_KEY=/etc/setjoin/certs/server-key.pem
ENV
cat >"$cu/config/db-credentials.d/db-credentials.env" <<'ENV'
DB_WORKER_DSN=postgres://setjoin_worker:workerpw@127.0.0.1:5432/mailserver
DB_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
DB_DIRECT_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver
ENV
printf 'GATEWAY_LISTEN=127.0.0.1:18090\nGATEWAY_RUST_AUTH_UPSTREAM=http://127.0.0.1:8443\nWORM_MODE=\n' >"$cu/config/gateway.env"
printf 'LISTEN_ADDR=127.0.0.1:8443\nTLS_CERT=\nTLS_KEY=\n' >"$cu/config/auth.env"
chgrp "$group" "$cu/config" "$cu/config/db-credentials.d" "$cu/config/db-credentials.d/db-credentials.env"
chmod 755 "$cu/config"
chmod 750 "$cu/config/db-credentials.d"
chmod 600 "$cu/config/db-credentials.d/db-credentials.env" "$cu/config/config.env" "$cu/config/auth.env"

printf '[Service]\nExecStart=%s/install/current/setjoin-server\n' "$cu" >"$cu/units/setjoin-gateway.service"
printf '[Service]\nExecStart=%s/install/current/setjoin-auth\n' "$cu" >"$cu/units/setjoin-auth.service"
for sock in setjoin-gateway.socket setjoin-https.socket setjoin-acme.socket \
  setjoin-federation.socket setjoin-imap.socket setjoin-imaps.socket \
  setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
  printf '[Socket]\nService=setjoin-gateway.service\n' >"$cu/units/$sock"
done

run_cu() {
  PATH="$cu/bin:$PATH" TMPDIR="$real_tmp" INSTALL_DIR="$cu/install" \
    SETJOIN_CONFIG_DIR="$cu/config" SYSTEMD_DIR="$cu/units" \
    TLS_AUTOCERT_CACHE_DIR="$cu/autocert" UPDATER_STATE_DIR="$cu/updater-journal" \
    SETJOIN_RECOVERY_BIN="$cu/bin/setjoin-recovery" UPGRADE_TEST_LOG="$cu/systemctl.log" \
    DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
    bash "$UPGRADE_SCRIPT" "$@"
}

# 2a. Active executor.lock held by updater MUST refuse cutover.
python3 - "$cu/updater-journal/executor.lock" "$cu/lock.ready" <<'PY' &
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(30)
PY
lock_pid=$!
for _ in $(seq 1 50); do
  [ -f "$cu/lock.ready" ] && break
  sleep 0.05
done
if run_cu migrate-to-setjoind >"$cu/lock-refuse.out" 2>&1; then
  kill "$lock_pid" 2>/dev/null || true
  wait "$lock_pid" 2>/dev/null || true
  echo 'migrate-to-setjoind succeeded while executor.lock was held' >&2
  exit 1
fi
kill "$lock_pid" 2>/dev/null || true
wait "$lock_pid" 2>/dev/null || true

# 2a2. Non-terminal/recovery_required updater journal MUST refuse cutover.
if CUTOVER_RECOVERY_REQUIRED=1 run_cu migrate-to-setjoind >"$cu/journal-refuse.out" 2>&1; then
  echo 'migrate-to-setjoind succeeded while updater journal required recovery' >&2
  exit 1
fi

# 2b. DB_OWNER_DSN in config.env MUST refuse cutover.
printf 'DB_OWNER_DSN=postgres://mail:ownerpw@127.0.0.1:5432/mailserver\n' >>"$cu/config/config.env"
if run_cu migrate-to-setjoind >"$cu/owner-refuse.out" 2>&1; then
  echo 'migrate-to-setjoind accepted DB_OWNER_DSN inside config.env' >&2
  exit 1
fi
grep -v '^DB_OWNER_DSN=' "$cu/config/config.env" >"$cu/config/config.env.tmp"
mv "$cu/config/config.env.tmp" "$cu/config/config.env"
chmod 600 "$cu/config/config.env"

# 2c. Missing previous/setjoind MUST refuse cutover without --allow-single-cohort.
rm -f "$cu/install/releases/r1/setjoind"
if run_cu migrate-to-setjoind >"$cu/prev-refuse.out" 2>&1; then
  echo 'migrate-to-setjoind accepted previous cohort lacking setjoind' >&2
  exit 1
fi
printf '#!/bin/sh\nexit 0\n' >"$cu/install/releases/r1/setjoind"
chmod 755 "$cu/install/releases/r1/setjoind"

# 2d. Failed readiness during migrate-to-setjoind MUST roll back cleanly to split units.
: >"$cu/systemctl.log"
if CUTOVER_FAIL_READY=1 run_cu migrate-to-setjoind >"$cu/fail-cutover.out" 2>&1; then
  echo 'migrate-to-setjoind succeeded despite failing readiness' >&2
  exit 1
fi
[ ! -e "$cu/units/setjoind.service" ] || {
  echo 'failed cutover retained setjoind.service' >&2
  exit 1
}
[ -f "$cu/units/setjoin-gateway.service" ] && [ -f "$cu/units/setjoin-auth.service" ] && [ -f "$cu/units/setjoin-acme.socket" ] || {
  echo 'failed cutover did not restore split units and legacy acme socket' >&2
  exit 1
}
[ ! -e "$cu/install/setjoind-cutover.prev" ] || {
  echo 'failed cutover retained snapshot directory' >&2
  exit 1
}

# 2e. Successful migrate-to-setjoind stops all 9 sockets first, renders unified unit/env, and purges snapshot secrets.
: >"$cu/systemctl.log"
run_cu migrate-to-setjoind >"$cu/ok-cutover.out" 2>&1 || {
  cat "$cu/ok-cutover.out" >&2
  echo 'migrate-to-setjoind failed unexpectedly' >&2
  exit 1
}
stop_gw_line="$(grep -n '^stop setjoin-gateway$' "$cu/systemctl.log" | head -1 | cut -d: -f1)"
for sock in setjoin-gateway.socket setjoin-https.socket setjoin-acme.socket \
  setjoin-federation.socket setjoin-imap.socket setjoin-imaps.socket \
  setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
  sock_line="$(grep -n "^stop $sock$" "$cu/systemctl.log" | head -1 | cut -d: -f1)"
  [ -n "$sock_line" ] && [ "$sock_line" -lt "$stop_gw_line" ] || {
    echo "migrate-to-setjoind did not stop $sock before setjoin-gateway" >&2
    exit 1
  }
done
[ ! -e "$cu/units/setjoin-acme.socket" ] || {
  echo 'migrate-to-setjoind retained retired setjoin-acme.socket' >&2
  exit 1
}
grep -qx 'disable setjoin-acme.socket' "$cu/systemctl.log" || {
  echo 'migrate-to-setjoind did not disable retired setjoin-acme.socket' >&2
  exit 1
}
[ -f "$cu/units/setjoind.service" ] || {
  echo 'setjoind.service missing after cutover' >&2
  exit 1
}
[ ! -e "$cu/units/setjoin-gateway.service" ] && [ ! -e "$cu/units/setjoin-auth.service" ] || {
  echo 'split units retained after cutover' >&2
  exit 1
}
grep -qx 'Type=notify' "$cu/units/setjoind.service"
grep -qx "ExecStart=$cu/install/current/setjoind --subsystems=all" "$cu/units/setjoind.service"
grep -qx 'Service=setjoind.service' "$cu/units/setjoin-gateway.socket"
grep -qx 'LISTEN_ADDR=127.0.0.1:0' "$cu/config/setjoind.env"
! grep -q 'GATEWAY_RUST_AUTH_UPSTREAM' "$cu/config/setjoind.env"
! grep -Eq '^TLS_CERT=' "$cu/config/setjoind-auth.env"
grep -qx 'DB_WORKER_DSN=postgres://setjoin_worker:workerpw@127.0.0.1:5432/mailserver' "$cu/config/setjoind-auth.env"
[ ! -e "$cu/install/setjoind-cutover.prev/config" ] || {
  echo 'cutover left secret env copies behind after success' >&2
  exit 1
}

# 2f. Topology-aware refresh-gateway-env on unified host MUST NOT recreate split units.
run_cu refresh-gateway-env >"$cu/uni-refresh.out" 2>&1 || {
  cat "$cu/uni-refresh.out" >&2
  echo 'unified refresh-gateway-env failed' >&2
  exit 1
}
[ -f "$cu/units/setjoind.service" ] && [ ! -e "$cu/units/setjoin-gateway.service" ] && [ ! -e "$cu/units/setjoin-auth.service" ] || {
  echo 'unified refresh-gateway-env created split-brain topology' >&2
  exit 1
}

# 2g. Rotate DB_WORKER_DSN in live db-credentials.env, verify retired ACME refuses
#     rollback-to-split-units BEFORE stopping setjoind, then rollback-to-split-units:
#     re-rendered auth.env MUST carry the rotated live secret (never stale snapshot).
printf 'ACME_DOMAINS=mail.example.test\n' >>"$cu/config/config.env"
: >"$cu/systemctl.log"
if run_cu rollback-to-split-units >"$cu/rb-acme-refuse.out" 2>&1; then
  echo 'rollback-to-split-units accepted retired ACME_DOMAINS' >&2
  exit 1
fi
[ -f "$cu/units/setjoind.service" ] && [ ! -s "$cu/systemctl.log" ] || {
  echo 'rollback-to-split-units stopped or removed setjoind before ACME preflight' >&2
  exit 1
}
grep -v '^ACME_DOMAINS=' "$cu/config/config.env" >"$cu/config/config.env.tmp"
mv "$cu/config/config.env.tmp" "$cu/config/config.env"
chmod 600 "$cu/config/config.env"

sed 's/workerpw/rotatedpw/' "$cu/config/db-credentials.d/db-credentials.env" >"$cu/config/db-credentials.d/db-credentials.env.new"
mv "$cu/config/db-credentials.d/db-credentials.env.new" "$cu/config/db-credentials.d/db-credentials.env"
chmod 600 "$cu/config/db-credentials.d/db-credentials.env"
run_cu rollback-to-split-units >"$cu/rb-split.out" 2>&1 || {
  cat "$cu/rb-split.out" >&2
  echo 'rollback-to-split-units failed' >&2
  exit 1
}
[ ! -e "$cu/units/setjoind.service" ] && [ -f "$cu/units/setjoin-gateway.service" ] && [ -f "$cu/units/setjoin-auth.service" ] || {
  echo 'rollback-to-split-units did not restore split topology' >&2
  exit 1
}
grep -qx 'DB_WORKER_DSN=postgres://setjoin_worker:rotatedpw@127.0.0.1:5432/mailserver' "$cu/config/auth.env" || {
  echo 'rollback-to-split-units did not re-render live rotated DB_WORKER_DSN' >&2
  exit 1
}
echo 'Release N shim refusal + Release N+1 setjoind cutover/refresh/rollback: PASS'

# ── E. Wave 1.9 (#547) fail-closed RLS preflight gates & env propagation ─────
# D1. Pre-stop preflight refusal aborts BEFORE stopping services or swapping binaries.
d1="$real_tmp/prestop-refuse"
mkdir -p "$d1/bin" "$d1/install" "$d1/new" "$d1/config" "$d1/units"
cp "$tmp/bin/systemctl" "$tmp/bin/chown" "$d1/bin/"
printf 'old server\n' >"$d1/install/setjoin-server"
printf 'old mailctl\n' >"$d1/install/mailctl"
printf 'new server\n' >"$d1/new/setjoin-server"
cat >"$d1/new/mailctl" <<'MOCK'
#!/usr/bin/env bash
if [ "$1" = "schema" ] && [ "$2" = "preflight" ]; then
  echo "mock pre-stop preflight failure" >&2
  exit 1
fi
exit 0
MOCK
chmod 755 "$d1/new/mailctl" "$d1/new/setjoin-server"
printf 'DB_DSN="postgres://setjoin_app:pw@127.0.0.1:5432/mailserver"\n' >"$d1/config/config.env"
if PATH="$d1/bin:$PATH" INSTALL_DIR="$d1/install" SETJOIN_CONFIG_DIR="$d1/config" \
  SYSTEMD_DIR="$d1/units" UPGRADE_TEST_LOG="$d1/systemctl.log" \
  bash "$UPGRADE_SCRIPT" "$d1/new/setjoin-server" "$d1/new/mailctl" >"$d1/out" 2>&1; then
  echo 'pre-stop preflight failure was reported as success' >&2
  exit 1
fi
[ ! -s "$d1/systemctl.log" ] || {
  echo 'pre-stop preflight failure still stopped services!' >&2
  cat "$d1/systemctl.log" >&2
  exit 1
}
[ "$(cat "$d1/install/setjoin-server")" = 'old server' ] || {
  echo 'pre-stop preflight failure swapped setjoin-server binary!' >&2
  exit 1
}

# D2. Quoted env propagation (DB_DSN from config.env, DB_WORKER_DSN from
#     db-credentials.env; never falls back to config.env when db-credentials.env
#     exists) + legacy pre-DEPLOY-004 fallback when db-credentials.env is absent.
d2="$real_tmp/quoted-env"
mkdir -p "$d2/bin" "$d2/install" "$d2/new" "$d2/config/db-credentials.d" "$d2/units"
cp "$tmp/bin/systemctl" "$tmp/bin/chown" "$d2/bin/"
printf 'old server\n' >"$d2/install/setjoin-server"
printf 'new server\n' >"$d2/new/setjoin-server"
cat >"$d2/new/mailctl" <<'MOCK'
#!/usr/bin/env bash
printf 'ARGS=%s\nDB_DSN=%s\nDB_WORKER_DSN=%s\nDB_OWNER_DSN=%s\n' \
  "$*" "${DB_DSN:-}" "${DB_WORKER_DSN:-}" "${DB_OWNER_DSN:-}" >"$PREFLIGHT_CAPTURE"
exit 1
MOCK
chmod 755 "$d2/new/mailctl" "$d2/new/setjoin-server"
cat >"$d2/config/config.env" <<'ENV'
DB_DSN="postgres://setjoin_app:quoted_app_pw@127.0.0.1:5432/mailserver"
DB_WORKER_DSN="postgres://wrong_fallback:bad@127.0.0.1:5432/mailserver"
ENV
cat >"$d2/config/db-credentials.d/db-credentials.env" <<'ENV'
DB_WORKER_DSN='postgres://setjoin_worker:quoted_worker_pw@127.0.0.1:5432/mailserver'
DB_OWNER_DSN="postgres://setjoin_owner:quoted_owner_pw@127.0.0.1:5432/mailserver"
ENV
chgrp "$group" "$d2/config" "$d2/config/db-credentials.d" "$d2/config/db-credentials.d/db-credentials.env"
chmod 755 "$d2/config"
chmod 750 "$d2/config/db-credentials.d"
chmod 600 "$d2/config/db-credentials.d/db-credentials.env" "$d2/config/config.env"
! PATH="$d2/bin:$PATH" INSTALL_DIR="$d2/install" SETJOIN_CONFIG_DIR="$d2/config" \
  SYSTEMD_DIR="$d2/units" UPGRADE_TEST_LOG="$d2/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  PREFLIGHT_CAPTURE="$d2/capture-split.txt" \
  bash "$UPGRADE_SCRIPT" "$d2/new/setjoin-server" "$d2/new/mailctl" >"$d2/out" 2>&1
grep -qx 'ARGS=schema preflight' "$d2/capture-split.txt" || {
  cat "$d2/capture-split.txt" >&2
  echo 'mailctl argv leaked or differed from schema preflight' >&2
  exit 1
}
grep -qx 'DB_DSN=postgres://setjoin_app:quoted_app_pw@127.0.0.1:5432/mailserver' "$d2/capture-split.txt"
grep -qx 'DB_WORKER_DSN=postgres://setjoin_worker:quoted_worker_pw@127.0.0.1:5432/mailserver' "$d2/capture-split.txt"
grep -qx 'DB_OWNER_DSN=postgres://setjoin_owner:quoted_owner_pw@127.0.0.1:5432/mailserver' "$d2/capture-split.txt"
! grep -Fq 'quoted_app_pw' "$d2/out" && ! grep -Fq 'quoted_worker_pw' "$d2/out" || {
  echo 'DSN passwords echoed to upgrade.sh output!' >&2
  exit 1
}

# When db-credentials.env exists WITHOUT DB_WORKER_DSN, must NOT fall back to config.env.
cat >"$d2/config/db-credentials.d/db-credentials.env" <<'ENV'
DB_OWNER_DSN="postgres://setjoin_owner:quoted_owner_pw@127.0.0.1:5432/mailserver"
ENV
chmod 600 "$d2/config/db-credentials.d/db-credentials.env"
! PATH="$d2/bin:$PATH" INSTALL_DIR="$d2/install" SETJOIN_CONFIG_DIR="$d2/config" \
  SYSTEMD_DIR="$d2/units" UPGRADE_TEST_LOG="$d2/systemctl.log" \
  DB_CRED_WANT_OWNER="$owner" DB_CRED_WANT_GROUP="$group" DB_CRED_RUNTIME_GROUP="$group" \
  PREFLIGHT_CAPTURE="$d2/capture-nofallback.txt" \
  bash "$UPGRADE_SCRIPT" "$d2/new/setjoin-server" "$d2/new/mailctl" >"$d2/out2" 2>&1
grep -qx 'DB_WORKER_DSN=' "$d2/capture-nofallback.txt" || {
  cat "$d2/capture-nofallback.txt" >&2
  echo 'upgrade.sh fell back to config.env DB_WORKER_DSN even though db-credentials.env existed' >&2
  exit 1
}

# Legacy pre-DEPLOY-004 host (db-credentials.env absent): falls back to config.env DB_WORKER_DSN.
rm -f "$d2/config/db-credentials.d/db-credentials.env"
! PATH="$d2/bin:$PATH" INSTALL_DIR="$d2/install" SETJOIN_CONFIG_DIR="$d2/config" \
  SYSTEMD_DIR="$d2/units" UPGRADE_TEST_LOG="$d2/systemctl.log" \
  PREFLIGHT_CAPTURE="$d2/capture-legacy.txt" \
  bash "$UPGRADE_SCRIPT" "$d2/new/setjoin-server" "$d2/new/mailctl" >"$d2/out3" 2>&1
grep -qx 'DB_WORKER_DSN=postgres://wrong_fallback:bad@127.0.0.1:5432/mailserver' "$d2/capture-legacy.txt" || {
  cat "$d2/capture-legacy.txt" >&2
  echo 'legacy pre-DEPLOY-004 fallback did not read DB_WORKER_DSN from config.env' >&2
  exit 1
}

# D3. Post-apply preflight exit 2 (legacy Release N warning code) triggers rollback.
d3="$real_tmp/postapply-exit2"
mkdir -p "$d3/bin" "$d3/install" "$d3/new" "$d3/config" "$d3/units"
cp "$tmp/bin/systemctl" "$tmp/bin/chown" "$d3/bin/"
printf 'old server\n' >"$d3/install/setjoin-server"
printf 'old mailctl\n' >"$d3/install/mailctl"
printf 'new server\n' >"$d3/new/setjoin-server"
cat >"$d3/new/mailctl" <<'MOCK'
#!/usr/bin/env bash
if [ "$1" = "schema" ] && [ "$2" = "preflight" ]; then
  if [ -f "$POST_APPLY_MARKER" ]; then
    exit 2
  fi
  exit 0
fi
if [ "$1" = "schema" ] && [ "$2" = "apply" ]; then
  touch "$POST_APPLY_MARKER"
  exit 0
fi
exit 0
MOCK
chmod 755 "$d3/new/mailctl" "$d3/new/setjoin-server"
printf 'DB_DSN=postgres://setjoin_app:pw@127.0.0.1:5432/mailserver\n' >"$d3/config/config.env"
if PATH="$d3/bin:$PATH" INSTALL_DIR="$d3/install" SETJOIN_CONFIG_DIR="$d3/config" \
  SYSTEMD_DIR="$d3/units" UPGRADE_TEST_LOG="$d3/systemctl.log" \
  POST_APPLY_MARKER="$d3/applied.flag" \
  bash "$UPGRADE_SCRIPT" "$d3/new/setjoin-server" "$d3/new/mailctl" >"$d3/out" 2>&1; then
  echo 'post-apply preflight exit 2 was treated as advisory instead of rolling back' >&2
  exit 1
fi
[ "$(cat "$d3/install/setjoin-server")" = 'old server' ] || {
  echo 'post-apply preflight exit 2 did not roll back setjoin-server' >&2
  exit 1
}
grep -q 'native-RLS preflight FAILED (exit 2)' "$d3/out" || {
  cat "$d3/out" >&2
  echo 'expected post-apply exit 2 rollback message' >&2
  exit 1
}
echo 'Wave 1.9 (#547) fail-closed preflight gates & env propagation: PASS'
