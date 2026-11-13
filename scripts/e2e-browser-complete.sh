#!/usr/bin/env bash
# Complete, source-bound browser matrix: ordinary product UI, CA/device gates,
# strict CSP, first-boot onboarding, and a real LiveKit-backed meeting journey.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBMAIL="$ROOT/mailserver/webmail"
STACK="$WEBMAIL/e2e/scripts/start-test-stack.sh"
RESULTS="$WEBMAIL/test-results/browser-complete"
DB_NAME="${E2E_DB_NAME:-mailserver_e2e}"
GATEWAY_PORT="${E2E_GATEWAY_PORT:-8080}"
BASE="${E2E_SERVER:-http://127.0.0.1:${GATEWAY_PORT}}"
CSP_PORT="${E2E_CSP_PORT:-8199}"
MAILCTL_BIN="${TMPDIR:-/tmp}/setjoin-e2e-${DB_NAME}-${GATEWAY_PORT}/mailctl"
STACK_PID=""
MANIFEST="$WEBMAIL/e2e/browser-complete-coverage.json"

# This front door creates and mutates its own disposable stack. A caller may
# choose an isolated loopback port/database, but cannot redirect the run to a
# remote or stale service. verify-all.sh has the same policy for its browser
# lane; keep this direct entry point equally fail-closed.
E2E_SERVER_VALUE="$BASE" E2E_GATEWAY_PORT_VALUE="$GATEWAY_PORT" DB_NAME_VALUE="$DB_NAME" CSP_PORT_VALUE="$CSP_PORT" node -e '
  const origin = process.env.E2E_SERVER_VALUE;
  const gatewayPort = Number(process.env.E2E_GATEWAY_PORT_VALUE);
  const dbName = process.env.DB_NAME_VALUE;
  const cspPort = Number(process.env.CSP_PORT_VALUE);
  let url;
  try { url = new URL(origin); } catch { throw new Error("E2E_SERVER must be a valid URL"); }
  if (!["http:", "https:"].includes(url.protocol) || url.origin !== origin ||
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
      url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
      Number(url.port) !== gatewayPort) {
    throw new Error("browser-complete requires an exact loopback E2E_SERVER origin whose port matches E2E_GATEWAY_PORT");
  }
  if (!Number.isInteger(gatewayPort) || gatewayPort < 1024 || gatewayPort > 65535 ||
      !Number.isInteger(cspPort) || cspPort < 1024 || cspPort > 65535) {
    throw new Error("E2E_GATEWAY_PORT and E2E_CSP_PORT must be decimal ports from 1024 through 65535");
  }
  if (!/^[A-Za-z0-9_]+$/.test(dbName) || !/(?:_e2e|_test)$/.test(dbName)) {
    throw new Error("E2E_DB_NAME must be an alphanumeric disposable *_e2e or *_test database");
  }
' || { echo "complete-browser-e2e: invalid local stack boundary" >&2; exit 2; }

mkdir -p "$RESULTS"

verify_reports() {
  node "$WEBMAIL/e2e/scripts/check-complete-browser-evidence.mjs" \
    "$RESULTS/main.json" "$RESULTS/ca.json" "$RESULTS/meet.json" \
    "$RESULTS/onboarding.json" "$RESULTS/csp.json" "$RESULTS/verdict.json" "$MANIFEST"
}

case "${1:-}" in
  --verify-existing) verify_reports; exit ;;
  "") ;;
  *) echo "usage: $0 [--verify-existing]" >&2; exit 2 ;;
esac

stop_stack() {
  if [ -z "$STACK_PID" ]; then return; fi
  kill -TERM "$STACK_PID" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$STACK_PID" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$STACK_PID" 2>/dev/null; then
    kill -9 "$STACK_PID" 2>/dev/null || true
  fi
  wait "$STACK_PID" 2>/dev/null || true
  STACK_PID=""
}
trap stop_stack EXIT INT TERM

start_stack() {
  local mode="$1" log="$RESULTS/stack-${1}.log"
  if [ "$mode" = "meet" ]; then
    E2E_SERVER="$BASE" E2E_GATEWAY_PORT="$GATEWAY_PORT" E2E_DB_NAME="$DB_NAME" \
      E2E_SKIP_WEBMAIL_BUILD=1 E2E_MEET_LIVE=1 bash "$STACK" >"$log" 2>&1 &
  else
    E2E_SERVER="$BASE" E2E_GATEWAY_PORT="$GATEWAY_PORT" E2E_DB_NAME="$DB_NAME" \
      E2E_MEET_LIVE=0 bash "$STACK" >"$log" 2>&1 &
  fi
  STACK_PID=$!
  for _ in $(seq 1 240); do
    if curl -fsS "$BASE/health" >/dev/null 2>&1; then return; fi
    if ! kill -0 "$STACK_PID" 2>/dev/null; then
      echo "complete-browser-e2e: $mode stack exited during startup" >&2
      tail -100 "$log" >&2
      exit 1
    fi
    sleep 1
  done
  echo "complete-browser-e2e: $mode stack readiness timeout" >&2
  tail -100 "$log" >&2
  exit 1
}

run_pw() {
  (cd "$WEBMAIL" && bash "$ROOT/scripts/playwright-supported.sh" -- "$@")
}

echo "==> [browser-complete] ordinary stack + default matrix"
start_stack ordinary
E2E_SERVER="$BASE" E2E_CSP_REQUIRE_GATEWAY_HEADER=1 PLAYWRIGHT_JSON_OUTPUT_FILE="$RESULTS/main.json" \
  run_pw npx playwright test

echo "==> [browser-complete] conditional-access/device live matrix"
E2E_SERVER="$BASE" E2E_CA_LIVE=1 MAILCTL_BIN="$MAILCTL_BIN" \
PLAYWRIGHT_JSON_OUTPUT_FILE="$RESULTS/ca.json" \
  run_pw npx playwright test \
    e2e/cert-status.spec.ts \
    e2e/conditional-access-quickstart.spec.ts \
    e2e/device-lockdown.spec.ts \
    e2e/offline-storage.spec.ts \
    e2e/risk-remediation.spec.ts \
    e2e/signin-activity-enduser.spec.ts \
    e2e/terms-of-use.spec.ts \
    --project=chromium

echo "==> [browser-complete] strict static CSP"
(cd "$WEBMAIL" && \
  E2E_CSP_PORT="$CSP_PORT" E2E_CSP_REQUIRE_GATEWAY_HEADER=0 \
  PLAYWRIGHT_JSON_OUTPUT_FILE="$RESULTS/csp.json" \
  bash "$ROOT/scripts/playwright-supported.sh" -- npm run test:e2e:csp)
stop_stack

echo "==> [browser-complete] uninitialized first boot"
PLAYWRIGHT_JSON_OUTPUT_FILE="$RESULTS/onboarding.json" E2E_SKIP_WEBMAIL_BUILD=1 \
  bash "$ROOT/scripts/e2e-onboarding.sh"

echo "==> [browser-complete] real LiveKit meeting"
start_stack meet
MEET_LIVE_UI=1 MEET_LIVE_UI_BASE="$BASE" \
MEET_LIVE_UI_DSN="postgres://mail:mail@127.0.0.1:5432/${DB_NAME}?sslmode=disable" \
PLAYWRIGHT_JSON_OUTPUT_FILE="$RESULTS/meet.json" \
  run_pw npx playwright test e2e/meet-live-ui.spec.ts --project=chromium
stop_stack

verify_reports
echo "==> [browser-complete] PASS — $RESULTS/verdict.json"
