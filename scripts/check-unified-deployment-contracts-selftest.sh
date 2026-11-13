#!/usr/bin/env bash
# Red-first proof for check-unified-deployment-contracts.sh.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-unified-deployment-contracts.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok() { printf '  ok: %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL: %s\n' "$1"; fail=$((fail + 1)); }

seed() {
  rm -rf "$TMP/case"
  mkdir -p "$TMP/case"
  cp "$ROOT"/scripts/unified-deployment-{readiness,d2,d3,d4,d4-oidc-flow,d4-auth-observer,d5,d6}.sh "$TMP/case/"
  cp "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$TMP/case/upgrade.sh"
  cp "$ROOT"/scripts/ga-fresh-install-smoke.sh "$TMP/case/"
}

expect_failure() {
  local label="$1" needle="$2"
  local out rc
  out="$(DEPLOYMENT_SCRIPTS_DIR="$TMP/case" UPGRADE_SCRIPT="$TMP/case/upgrade.sh" bash "$GUARD" 2>&1)"
  rc=$?
  if [ "$rc" -ne 0 ]; then ok "$label fails"; else bad "$label did not fail"; fi
  if grep -Fq "$needle" <<<"$out"; then
    ok "$label names the violated contract"
  else
    bad "$label output omitted '$needle':"$'\n'"$out"
  fi
}

seed
sed -i.bak 's/docker exec -i /docker exec /' \
  "$TMP/case/unified-deployment-d3.sh"
rm -f "$TMP/case/unified-deployment-d3.sh.bak"
expect_failure "closed docker-exec stdin" "without docker exec -i"

seed
sed -i.bak 's/_setjoin-im._tcp IN SRV 0 0 7443 /_setjoin-im._tcp IN SRV 0 0 443 /' \
  "$TMP/case/unified-deployment-readiness.sh"
rm -f "$TMP/case/unified-deployment-readiness.sh.bak"
expect_failure "Federation SRV port drift" "production Federation port 7443"

seed
sed -i.bak 's/--after-cursor=/--since=/' \
  "$TMP/case/unified-deployment-d5.sh"
rm -f "$TMP/case/unified-deployment-d5.sh.bak"
expect_failure "unbounded journal evidence" "not segmented by a journal cursor"

seed
sed -i.bak '/AUTH_HEALTHY=0/d' "$TMP/case/upgrade.sh"
rm -f "$TMP/case/upgrade.sh.bak"
expect_failure "authserver health omission" "fail closed on authserver health"

seed
sed -i.bak 's/for attempt in $(seq 1 30)/for attempt in $(seq 1 2)/' \
  "$TMP/case/upgrade.sh"
rm -f "$TMP/case/upgrade.sh.bak"
expect_failure "readiness retry truncation" "bounded readiness retry"

seed
sed -i.bak 's/INTERVAL_SECONDS:-14400/INTERVAL_SECONDS:-900/' \
  "$TMP/case/unified-deployment-d4-auth-observer.sh"
rm -f "$TMP/case/unified-deployment-d4-auth-observer.sh.bak"
expect_failure "auth observation cadence compression" "four-hour real-flow cadence"

seed
sed -i.bak '/INTERVAL_SECONDS" -le 14400/d' \
  "$TMP/case/unified-deployment-d4-auth-observer.sh"
rm -f "$TMP/case/unified-deployment-d4-auth-observer.sh.bak"
expect_failure "auth observation cadence extension" "within 24 hours"

seed
sed -i.bak 's/source_ready ||/true ||/' \
  "$TMP/case/unified-deployment-d4-auth-observer.sh"
rm -f "$TMP/case/unified-deployment-d4-auth-observer.sh.bak"
expect_failure "auth source precheck removal" "without a shadow-source precheck"

seed
sed -i.bak '/current_start.*recorded_start/c\
  true' \
  "$TMP/case/unified-deployment-d4-auth-observer.sh"
rm -f "$TMP/case/unified-deployment-d4-auth-observer.sh.bak"
expect_failure "auth observer PID identity removal" "recyclable PID"

seed
sed -i.bak '/^S3_ACCESS_KEY=\$SMOKE_S3_USER$/d' \
  "$TMP/case/ga-fresh-install-smoke.sh"
rm -f "$TMP/case/ga-fresh-install-smoke.sh.bak"
expect_failure "GA smoke S3 access seeding removal" "does not seed the disposable MinIO access identity"

seed
sed -i.bak '/MINIO_ROOT_USER="\$SMOKE_S3_USER"/d' \
  "$TMP/case/ga-fresh-install-smoke.sh"
rm -f "$TMP/case/ga-fresh-install-smoke.sh.bak"
expect_failure "GA smoke sidecar identity drift" "sidecar does not run the seeded access identity"

seed
sed -i.bak '/^export S3_SECRET_KEY="\$SMOKE_S3_PASS"$/d' \
  "$TMP/case/ga-fresh-install-smoke.sh"
rm -f "$TMP/case/ga-fresh-install-smoke.sh.bak"
expect_failure "GA smoke installer secret pin removal" "installer env does not pin the seeded secret"

out="$(bash "$GUARD" 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
  ok "real deployment scripts pass"
else
  bad "real deployment scripts fail:"$'\n'"$out"
fi

if [ "$fail" -ne 0 ]; then
  printf 'check-unified-deployment-contracts selftest FAILED (%s failures).\n' "$fail"
  exit 1
fi
printf 'check-unified-deployment-contracts selftest: all %s checks passed.\n' "$pass"
