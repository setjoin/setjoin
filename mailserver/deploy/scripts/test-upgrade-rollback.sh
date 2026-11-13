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
expected=$'stop setjoin-gateway\nstop setjoin-federation.socket\nstop setjoin-https.socket\ndisable setjoin-https.socket\nstop setjoin-acme.socket\ndisable setjoin-acme.socket\nstop setjoin-imap.socket\ndisable setjoin-imap.socket\nstop setjoin-imaps.socket\ndisable setjoin-imaps.socket\nstop setjoin-smtp.socket\ndisable setjoin-smtp.socket\nstop setjoin-smtps.socket\ndisable setjoin-smtps.socket\nstop setjoin-submission.socket\ndisable setjoin-submission.socket\nstop setjoin\nis-active --quiet setjoin-auth\nstop setjoin-auth\nstop setjoin-gateway\nstop setjoin-federation.socket\ndisable setjoin-federation.socket\nstop setjoin-https.socket\ndisable setjoin-https.socket\nstop setjoin-acme.socket\ndisable setjoin-acme.socket\nstop setjoin-imap.socket\ndisable setjoin-imap.socket\nstop setjoin-imaps.socket\ndisable setjoin-imaps.socket\nstop setjoin-smtp.socket\ndisable setjoin-smtp.socket\nstop setjoin-smtps.socket\ndisable setjoin-smtps.socket\nstop setjoin-submission.socket\ndisable setjoin-submission.socket\ndaemon-reload\nstart setjoin-auth\nstart setjoin\nstart setjoin-gateway'
[ "$(cat "$tmp/systemctl.log")" = "$expected" ] || {
  echo 'unexpected stop/restart actions' >&2
  cat "$tmp/systemctl.log" >&2
  exit 1
}
echo 'legacy upgrade rollback (Go + Rust *.prev): PASS'
