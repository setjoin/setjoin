#!/usr/bin/env bash
# U5-U8 continuity controller. Reuses the exact-prefix production-shaped
# Ubuntu stack controller and records resumable deterministic checkpoints.
# Physical-device gates are verified, never fabricated or silently skipped.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="${1:-deterministic}"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
REWIND_ATTEMPT="${REWIND_ATTEMPT:-base}"
FORCE="${FORCE:-0}"
EVIDENCE=""

die() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

validate_prefix() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  [ "${#RUN_PREFIX}" -le 32 ] || die "RUN_PREFIX must be at most 32 characters"
  case "$REWIND_ATTEMPT" in
    (*[!a-z0-9-]*|'') die "REWIND_ATTEMPT must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  [ "${#REWIND_ATTEMPT}" -le 16 ] || die "REWIND_ATTEMPT must be at most 16 characters"
  case "$FORCE" in 0|1) ;; *) die "FORCE must be exactly 0 or 1" ;; esac
  EVIDENCE="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/u5-u8"
}

run_phase() {
  local name="$1"; shift
  local checkpoint="$EVIDENCE/$name.pass"
  if [ "$FORCE" = "0" ] && [ -f "$checkpoint" ]; then
    printf 'SKIP %s: checkpoint already passed (%s)\n' "$name" "$checkpoint"
    return
  fi
  printf '\n=== %s ===\n' "$name"
  "$@" 2>&1 | tee "$EVIDENCE/$name.log"
  printf 'phase=%s\nstatus=PASS\ncompleted_at=%s\n' \
    "$name" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$checkpoint"
}

go_continuity() {
  (cd "$ROOT/shared" && go test ./continuity/...)
  (cd "$ROOT/mailserver" && go test ./internal/continuity/... ./internal/mailrecovery/... ./internal/jmap/... ./cmd/mailserverd/... ./api/...)
}

database_continuity() {
  bash "$ROOT/scripts/load-test-schema.sh"
  pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test \
    "$ROOT/mailserver/sql/tests/mail_recovery_continuity.pg"
}

native_continuity() {
  (cd "$ROOT/clients" && cargo test -p offline-core --test blob_test)
  (cd "$ROOT/clients" && cargo check -p desktop-native)
  (cd "$ROOT/clients/desktop/src-tauri" && cargo test --lib)
  (cd "$ROOT/clients/desktop/electron" && npx vitest run \
    src/handlers/recoveryBlob.test.ts src/bridge.test.ts src/main.test.ts)
}

web_continuity() {
  (cd "$ROOT/mailserver/webmail" && npx vitest run \
    src/lib/offline/recovery.test.ts \
    src/lib/offline/recovery-upload.test.ts \
    src/lib/native/types.test.ts \
    src/lib/admin/client.test.ts)
  (cd "$ROOT/mailserver/webmail" && npm run check)
}

contracts() {
  bash "$ROOT/scripts/check-upgrade-contracts.sh"
  bash "$ROOT/scripts/check-agent-context-budget.sh"
}

deterministic() {
  install -d -m 0700 "$EVIDENCE"
  run_phase go-continuity go_continuity
  run_phase database-continuity database_continuity
  run_phase native-continuity native_continuity
  run_phase web-continuity web_continuity
  run_phase contracts contracts
  printf 'deterministic=PASS\nphysical_device_gate=OPEN\nfeatures=OFF\n' >"$EVIDENCE/result.txt"
}

hardware_gate() {
  local record="$ROOT/docs/verification/2026-08-02-transactional-continuity-u5-u8.md"
  [ -f "$record" ] || die "structured U5-U8 verification record is missing"
  if grep -Eq '^\| Physical (iOS|Android) device \| OPEN \|' "$record"; then
    die "physical iOS/Android evidence is still OPEN; continuity flags must remain OFF"
  fi
  grep -Eq '^\| Physical iOS device \| CLOSED \|' "$record" || die "physical iOS gate row is missing"
  grep -Eq '^\| Physical Android device \| CLOSED \|' "$record" || die "physical Android gate row is missing"
  printf 'hardware_gate=PASS\n'
}

validate_prefix
case "$ACTION" in
  full)
    PROVISION_ENVS="a b" RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" provision
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/transactional-updater-rehearsal.sh" prepare
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/transactional-continuity-rewind.sh" prepare
    deterministic
    hardware_gate
    ;;
  provision)
    PROVISION_ENVS="a b" RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" provision
    ;;
  resume-provision)
    PROVISION_ENVS="a b" RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" resume-provision
    ;;
  updater)
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/transactional-updater-rehearsal.sh" prepare
    ;;
  rewind)
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/transactional-continuity-rewind.sh" prepare
    ;;
  deterministic) deterministic ;;
  hardware-gate) hardware_gate ;;
  status)
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" status
    find "$EVIDENCE" -maxdepth 1 -name '*.pass' -print 2>/dev/null | sort || true
    if [ -f "$EVIDENCE/ubuntu-rewind/$REWIND_ATTEMPT/result.txt" ]; then
      sed -n '1,40p' "$EVIDENCE/ubuntu-rewind/$REWIND_ATTEMPT/result.txt"
    fi
    ;;
  cleanup)
    if command -v docker >/dev/null 2>&1 && docker inspect "$RUN_PREFIX-a" >/dev/null 2>&1; then
      RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
        bash "$ROOT/scripts/transactional-continuity-rewind.sh" terminal-off
    fi
    if command -v docker >/dev/null 2>&1 && docker inspect "$RUN_PREFIX-a" >/dev/null 2>&1; then
      RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
        bash "$ROOT/scripts/transactional-updater-rehearsal.sh" cleanup
    fi
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" cleanup
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/transactional-continuity-rewind.sh" cleanup-resources
    ;;
  self-test)
    bash -n "$0"
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/unified-deployment-readiness.sh" self-test >/dev/null
    RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
      bash "$ROOT/scripts/transactional-continuity-rewind.sh" self-test >/dev/null
    grep -Fq 'physical_device_gate=OPEN' "$0" || die "OFF-gate result contract drifted"
    grep -Fq 'full)' "$0" || die "full rehearsal action drifted"
    grep -Fq 'rewind)' "$0" || die "rewind rehearsal action drifted"
    grep -Fq 'scripts/unified-deployment-readiness.sh" cleanup' "$0" || die "exact-prefix cleanup delegation drifted"
    masked_cleanup='bash "$ROOT/scripts/transactional-updater-rehearsal.sh" cleanup'
    masked_cleanup="$masked_cleanup || true"
    ! grep -F "$masked_cleanup" "$0" >/dev/null || die "updater cleanup failure became masked"
    printf 'SELF_TEST_PASS prefix=%s\n' "$RUN_PREFIX"
    ;;
  *) die "usage: $0 full|provision|resume-provision|updater|rewind|deterministic|hardware-gate|status|cleanup|self-test" ;;
esac
