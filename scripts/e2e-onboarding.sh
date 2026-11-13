#!/usr/bin/env bash
# Disposable first-boot browser journey. The input/output boundary is local:
# one explicit loopback origin and one dedicated database, both destroyed or
# overwritten by the ordinary E2E harness on its next run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${E2E_ONBOARDING_PORT:-18081}"
AUTH_PORT="${E2E_ONBOARDING_AUTH_PORT:-18444}"
S3_PORT="${E2E_ONBOARDING_S3_PORT:-19001}"
SMTP_INBOUND_PORT="${E2E_ONBOARDING_SMTP_INBOUND_PORT:-11025}"
SMTP_SUBMISSION_PORT="${E2E_ONBOARDING_SMTP_SUBMISSION_PORT:-11587}"
IMAP_PORT="${E2E_ONBOARDING_IMAP_PORT:-11143}"
DB_NAME="${E2E_ONBOARDING_DB_NAME:-mailserver_onboarding_e2e}"
BASE="http://127.0.0.1:${PORT}"
INSTANCE_DIR="${TMPDIR:-/tmp}/setjoin-e2e-${DB_NAME}-${PORT}"
CONTROL_SOCKET="${E2E_ONBOARDING_CONTROL_SOCKET:-/tmp/sj-onboard-${PORT}-$$.sock}"
MAILCTL_BIN="$INSTANCE_DIR/mailctl"
OWNER_DSN="user=${E2E_PGUSER:-mail} host=${E2E_PGHOST:-127.0.0.1} port=${E2E_PGPORT:-5432} dbname=${DB_NAME} sslmode=disable"
STACK_LOG="${TMPDIR:-/tmp}/setjoin-onboarding-stack.log"
READY_TIMEOUT_SEC="${E2E_ONBOARDING_READY_TIMEOUT_SEC:-240}"

case "$PORT:$AUTH_PORT:$S3_PORT:$SMTP_INBOUND_PORT:$SMTP_SUBMISSION_PORT:$IMAP_PORT:$READY_TIMEOUT_SEC" in
  *[!0-9:]*) echo "onboarding-e2e: ports must be decimal integers" >&2; exit 2 ;;
esac
case "$DB_NAME" in
  *[!A-Za-z0-9_]*) echo "onboarding-e2e: database name must match [A-Za-z0-9_]+" >&2; exit 2 ;;
esac

cleanup() {
  if [ -n "${STACK_PID:-}" ]; then
    kill "$STACK_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$STACK_PID" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$STACK_PID" 2>/dev/null; then
      kill -9 "$STACK_PID" 2>/dev/null || true
    fi
    wait "$STACK_PID" 2>/dev/null || true
  fi
  if [ -S "$CONTROL_SOCKET" ]; then
    rm -f "$CONTROL_SOCKET"
  fi
}
trap cleanup EXIT INT TERM

E2E_SKIP_WEBMAIL_BUILD="${E2E_SKIP_WEBMAIL_BUILD:-0}" \
E2E_SKIP_SEED=1 \
E2E_GATEWAY_PORT="$PORT" \
E2E_AUTH_PORT="$AUTH_PORT" \
E2E_S3_PORT="$S3_PORT" \
E2E_SMTP_INBOUND_PORT="$SMTP_INBOUND_PORT" \
E2E_SMTP_SUBMISSION_PORT="$SMTP_SUBMISSION_PORT" \
E2E_IMAP_PORT="$IMAP_PORT" \
E2E_DB_NAME="$DB_NAME" \
E2E_CONTROL_SOCKET="$CONTROL_SOCKET" \
bash "$ROOT/mailserver/webmail/e2e/scripts/start-test-stack.sh" >"$STACK_LOG" 2>&1 &
STACK_PID=$!

for _ in $(seq 1 "$READY_TIMEOUT_SEC"); do
  if curl -fsS "$BASE/setup/status" 2>/dev/null | grep -q '"initialized":false'; then
    break
  fi
  if ! kill -0 "$STACK_PID" 2>/dev/null; then
    echo "onboarding-e2e: stack exited before becoming ready" >&2
    tail -80 "$STACK_LOG" >&2
    exit 1
  fi
  sleep 1
done

curl -fsS "$BASE/setup/status" | grep -q '"initialized":false' || {
  echo "onboarding-e2e: no uninitialized stack after ${READY_TIMEOUT_SEC}s" >&2
  tail -80 "$STACK_LOG" >&2
  exit 1
}

(cd "$ROOT/mailserver/webmail" && \
  E2E_ONBOARDING=1 E2E_BASE_URL="$BASE" MAILCTL_BIN="$MAILCTL_BIN" \
  PGPASSWORD="${E2E_PGPASSWORD:-mail}" DB_DIRECT_OWNER_DSN="$OWNER_DSN" \
  SETJOIN_CONTROL_SOCKET="$CONTROL_SOCKET" \
  bash "$ROOT/scripts/playwright-supported.sh" -- \
    npx playwright test --config playwright.onboarding.config.ts)
