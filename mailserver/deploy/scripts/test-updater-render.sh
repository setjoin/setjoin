#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
UPDATER_DATA_DIR=/var/lib/setjoin-updater
UPDATER_DSN_FILE=/etc/setjoin-updater/updater-dsn
INSTALL_DIR=/opt/setjoin
UPDATER_EXECUTION_CONFIG=/etc/setjoin-updater/execution.json
UPDATER_OWNER_DSN_FILE=/etc/setjoin-updater/owner-dsn
UPDATER_RECOVERY_ACCESS_FILE=/etc/setjoin-updater/recovery-access-key
UPDATER_RECOVERY_SECRET_FILE=/etc/setjoin-updater/recovery-secret-key
UPDATER_RECOVERY_HMAC_FILE=/etc/setjoin-updater/recovery-hmac-key
UPDATER_PROBE_CREDENTIAL_FILE=/etc/setjoin-updater/probe-credential.json
UPDATER_APP_WORKER_DSN_FILE=/etc/setjoin-updater/app-worker-dsn
OFFICE_APP_MANIFEST=/etc/setjoin/office-managed-app-v1.json
OFFICE_APP_STATE_DIR=/var/lib/setjoin-updater/appmarket/collabora-code
render_updater_unit \
  "$ROOT/mailserver/deploy/setjoin-updater.service.template" \
  "$tmp/setjoin-updater.service"

grep -Fq 'ExecStart=/usr/libexec/setjoin-updater run --state-dir=/var/lib/setjoin-updater/journal --release-store=/var/lib/setjoin-updater/releases --dsn-file=/etc/setjoin-updater/updater-dsn --execution-config=/etc/setjoin-updater/execution.json --owner-dsn-file=/etc/setjoin-updater/owner-dsn' "$tmp/setjoin-updater.service"
! grep -Fq 'LoadCredential=' "$tmp/setjoin-updater.service"
grep -Fq 'ReadWritePaths=/var/lib/setjoin-updater/journal /opt/setjoin /var/lib/setjoin-updater/appmarket/collabora-code' "$tmp/setjoin-updater.service"
grep -Fq 'ReadOnlyPaths=/var/lib/setjoin-updater/releases' "$tmp/setjoin-updater.service"
grep -Fq -- '--office-app-execution --office-app-worker-dsn-file=/etc/setjoin-updater/app-worker-dsn --office-app-manifest=/etc/setjoin/office-managed-app-v1.json --office-app-state-dir=/var/lib/setjoin-updater/appmarket/collabora-code' "$tmp/setjoin-updater.service"
grep -Fq 'CapabilityBoundingSet=' "$tmp/setjoin-updater.service"
! grep -Eq 'Environment(File)?=.*(OWNER|UPDATER).*DSN|DB_OWNER_DSN|DB_UPDATER_DSN' "$tmp/setjoin-updater.service"
! grep -q '{{' "$tmp/setjoin-updater.service"

if command -v systemd-analyze >/dev/null 2>&1; then
  # verify fails on hosts without the installed binaries (dev/CI): ExecStart
  # paths like /usr/libexec/setjoin-updater exist only on a real install, which
  # the G0-002 fresh-install smoke exercises. Unit validity is what THIS test
  # owns — accept the missing-staged-binary class, fail on anything else.
  verify_log="$tmp/verify.log"
  if ! systemd-analyze verify "$tmp/setjoin-updater.service" >"$verify_log" 2>&1; then
    non_staged="$(grep -v 'is not executable: No such file or directory' "$verify_log" | grep -Ei 'error|invalid|not executable|missing' || true)"
    staged_only="$(grep -c 'is not executable: No such file or directory' "$verify_log" || true)"
    if [[ -n "$non_staged" ]]; then
      echo "updater unit render: systemd-analyze reported real unit errors:" >&2
      cat "$verify_log" >&2
      exit 1
    fi
    echo "updater unit render: verify clean apart from $staged_only not-yet-installed staged path(s) (expected off-host)"
  fi
fi

echo "updater unit render: PASS"
