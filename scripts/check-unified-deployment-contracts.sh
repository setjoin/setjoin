#!/usr/bin/env bash
# Structural guard for the reusable three-stack deployment-readiness scripts.
# These checks encode failures found during the 2026-07-29 Ubuntu rehearsal:
# closed docker-exec stdin, stale Federation SRV ports, unbounded journal
# windows, and accidental weakening of the real 7-sync/24-hour identity gate.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOYMENT_SCRIPTS_DIR="${DEPLOYMENT_SCRIPTS_DIR:-$ROOT/scripts}"
UPGRADE_SCRIPT="${UPGRADE_SCRIPT:-$ROOT/mailserver/deploy/scripts/upgrade.sh}"
fail=0

report() {
  printf '  [UNIFIED-DEPLOYMENT] %s\n' "$*" >&2
  fail=1
}

required=(
  unified-deployment-readiness.sh
  unified-deployment-d2.sh
  unified-deployment-d3.sh
  unified-deployment-d4.sh
  unified-deployment-d4-oidc-flow.sh
  unified-deployment-d4-auth-observer.sh
  unified-deployment-d5.sh
  unified-deployment-d6.sh
)

printf '==> Unified deployment contract guard\n'
for name in "${required[@]}"; do
  file="$DEPLOYMENT_SCRIPTS_DIR/$name"
  if [ ! -f "$file" ]; then
    report "missing required script: $file"
    continue
  fi
  bash -n "$file" || report "$name is not valid Bash"
done

# A heredoc or piped script reaches `bash -s` only when docker exec keeps
# stdin open. Without -i, bash exits successfully without running the body.
while IFS=: read -r file line content; do
  [ -z "$file" ] && continue
  case "$content" in
    (*"docker exec"*"bash -s"*)
      case "$content" in
        (*"docker exec -i "*) ;;
        (*) report "$(basename "$file"):$line invokes bash -s without docker exec -i" ;;
      esac
      ;;
  esac
done < <(grep -Hn 'docker exec.*bash -s' "$DEPLOYMENT_SCRIPTS_DIR"/unified-deployment-*.sh 2>/dev/null)

ga_smoke="$DEPLOYMENT_SCRIPTS_DIR/ga-fresh-install-smoke.sh"
if [ -f "$ga_smoke" ]; then
  grep -Fq 'docker exec -e RESUME_INSTALL="$RESUME_INSTALL"' "$ga_smoke" ||
    report "GA smoke does not carry the install-resume boundary into the container"
  grep -Fq "grep -q '^DB_ENCRYPTION_KEY=' /etc/setjoin/config.env" "$ga_smoke" ||
    report "GA smoke install resume can replace encryption secrets"
  grep -Fq 'S3_ACCESS_KEY=$SMOKE_S3_USER' "$ga_smoke" ||
    report "GA smoke does not seed the disposable MinIO access identity before install"
  grep -Fq 'S3_SECRET_KEY=$SMOKE_S3_PASS' "$ga_smoke" ||
    report "GA smoke does not seed the disposable MinIO secret before install"
  grep -Fq 'MINIO_ROOT_USER="$SMOKE_S3_USER"' "$ga_smoke" ||
    report "GA smoke MinIO sidecar does not run the seeded access identity"
  grep -Fq 'MINIO_ROOT_PASSWORD="$SMOKE_S3_PASS"' "$ga_smoke" ||
    report "GA smoke MinIO sidecar does not run the seeded secret"
  grep -Fq 'export S3_ACCESS_KEY="$SMOKE_S3_USER"' "$ga_smoke" ||
    report "GA smoke installer env does not pin the seeded access identity"
  grep -Fq 'export S3_SECRET_KEY="$SMOKE_S3_PASS"' "$ga_smoke" ||
    report "GA smoke installer env does not pin the seeded secret"
else
  report "missing GA fresh-install smoke: $ga_smoke"
fi

readiness="$DEPLOYMENT_SCRIPTS_DIR/unified-deployment-readiness.sh"
if [ -f "$readiness" ]; then
  grep -Fq 'PROVISION_ENVS="${PROVISION_ENVS:-a b c}"' "$readiness" ||
    report "readiness lost its three-stack default provisioning set"
  grep -Fq 'for env in $PROVISION_ENVS' "$readiness" ||
    report "readiness cannot run the bounded A/B updater rehearsal subset"
  grep -Fq '_setjoin-im._tcp IN SRV 0 0 7443 ' "$readiness" ||
    report "readiness DNS does not publish the production Federation port 7443"
  if grep -Fq '_setjoin-im._tcp IN SRV 0 0 443 ' "$readiness"; then
    report "readiness DNS still publishes the HTTPS port 443 for Federation"
  fi
fi

auth_observer="$DEPLOYMENT_SCRIPTS_DIR/unified-deployment-d4-auth-observer.sh"
if [ -f "$auth_observer" ]; then
  grep -Fq 'INTERVAL_SECONDS="${INTERVAL_SECONDS:-14400}"' "$auth_observer" ||
    report "D4 auth observer lost its four-hour real-flow cadence"
  grep -Fq 'get("eligible") is True' "$auth_observer" ||
    report "D4 auth observer no longer delegates eligibility to the database gate"
  grep -Fq 'sleep "$INTERVAL_SECONDS"' "$auth_observer" ||
    report "D4 auth observer no longer spreads real authentication observations"
  grep -Fq '[ "$INTERVAL_SECONDS" -le 14400 ]' "$auth_observer" ||
    report "D4 auth observer can no longer finish seven observations within 24 hours"
  grep -Fq 'source_ready ||' "$auth_observer" ||
    report "D4 auth observer changes the test account without a shadow-source precheck"
  grep -Fq '[ "$current_start" = "$recorded_start" ]' "$auth_observer" ||
    report "D4 auth observer trusts a recyclable PID without its process start identity"
fi

d6="$DEPLOYMENT_SCRIPTS_DIR/unified-deployment-d6.sh"
if [ -f "$d6" ]; then
  grep -Fq "WHEN SQLSTATE 'BZ216'" "$d6" ||
    report "D6 lost the exact Guest-to-Federation refusal assertion"
  grep -Fq 'guest_identity_links=0' "$d6" ||
    report "D6 lost the Guest identity-boundary assertion"
fi

d4="$DEPLOYMENT_SCRIPTS_DIR/unified-deployment-d4.sh"
if [ -f "$d4" ]; then
  grep -Fq 'sleep 900' "$d4" ||
    report "D4 resumable observer lost its bounded 15-minute cadence"
  grep -Fq '"${completed:-0}" -ge 7' "$d4" ||
    report "D4 observer no longer requires seven completed source syncs"
  grep -Fq 'h >= 24' "$d4" ||
    report "D4 observer no longer requires a real 24-hour span"
fi

if [ -f "$UPGRADE_SCRIPT" ]; then
  bash -n "$UPGRADE_SCRIPT" || report "upgrade.sh is not valid Bash"
  grep -Fq 'NEW_AUTH="${4:-}"' "$UPGRADE_SCRIPT" ||
    report "upgrade.sh does not accept a matching authserverd"
  grep -Fq 'systemctl stop setjoin-auth' "$UPGRADE_SCRIPT" ||
    report "upgrade.sh does not stop authserverd for a supplied binary"
  grep -Fq 'authserverd.prev' "$UPGRADE_SCRIPT" ||
    report "upgrade.sh does not retain an authserver rollback binary"
  grep -Fq 'AUTH_HEALTHY=0' "$UPGRADE_SCRIPT" ||
    report "upgrade.sh does not fail closed on authserver health"
  grep -Fq 'for attempt in $(seq 1 30)' "$UPGRADE_SCRIPT" ||
    report "upgrade.sh does not use a bounded readiness retry"
else
  report "missing upgrade script: $UPGRADE_SCRIPT"
fi

d5="$DEPLOYMENT_SCRIPTS_DIR/unified-deployment-d5.sh"
if [ -f "$d5" ]; then
  grep -Fq -- '--after-cursor=' "$d5" ||
    report "D5 evidence is not segmented by a journal cursor"
  grep -Fq 'wrong_anchor_refused=PASS' "$d5" ||
    report "D5 lost the wrong-anchor refusal assertion"
  grep -Fq 'hub_partition_queue=PASS' "$d5" ||
    report "D5 lost the real partition/reconnect queue assertion"
  grep -Fq 'old_anchor_rejected=PASS' "$d5" ||
    report "D5 lost the certificate-rotation refusal assertion"
  grep -Fq 'straggler_poison=PASS' "$d5" ||
    report "D5 lost the kicked-member straggler-poison assertion"
  grep -Fq 'transport_rows_after_delete=0' "$d5" ||
    report "D5 lost the bilateral peer-delete full-reap assertion"
  grep -Fq 'depth_warn_before_park=PASS' "$d5" ||
    report "D5 lost the backpressure pre-cap warning assertion"
fi

if [ "$fail" -ne 0 ]; then
  printf 'Unified deployment contract guard FAILED.\n' >&2
  exit 1
fi
printf 'Unified deployment contract guard: clean.\n'
