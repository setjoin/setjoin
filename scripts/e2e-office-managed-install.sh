#!/usr/bin/env bash
# Disposable browser-to-reducer-to-updater-to-Docker Collabora install lane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBMAIL="$ROOT/mailserver/webmail"
STACK="$WEBMAIL/e2e/scripts/start-test-stack.sh"
DB_NAME="${E2E_DB_NAME:-mailserver_office_install_e2e}"
GATEWAY_PORT="${E2E_GATEWAY_PORT:-8188}"
BASE="http://127.0.0.1:${GATEWAY_PORT}"
RESULTS="$WEBMAIL/test-results/office-managed-install"
UPDATER_BIN="${TMPDIR:-/tmp}/setjoin-e2e-${DB_NAME}-${GATEWAY_PORT}/setjoin-updater"
STACK_PID=""

cleanup() {
  docker container rm --force setjoin-collabora-code >/dev/null 2>&1 || true
  docker network rm setjoin-office >/dev/null 2>&1 || true
  docker volume rm setjoin-collabora-config >/dev/null 2>&1 || true
  if [ -n "$STACK_PID" ]; then
    kill -TERM "$STACK_PID" 2>/dev/null || true
    wait "$STACK_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null 2>&1 || { echo "office-managed-install-e2e: Docker is required" >&2; exit 1; }
mkdir -p "$RESULTS"
cleanup
E2E_MANAGED_OFFICE=1 E2E_SKIP_WEBMAIL_BUILD="${E2E_SKIP_WEBMAIL_BUILD:-0}" \
  E2E_DB_NAME="$DB_NAME" E2E_GATEWAY_PORT="$GATEWAY_PORT" \
  bash "$STACK" >"$RESULTS/stack.log" 2>&1 &
STACK_PID=$!
for _ in $(seq 1 240); do
  if curl -fsS "$BASE/health" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$STACK_PID" 2>/dev/null; then
    tail -120 "$RESULTS/stack.log" >&2
    exit 1
  fi
  sleep 1
done
curl -fsS "$BASE/health" >/dev/null
psql "postgres://mail@127.0.0.1:5432/${DB_NAME}?sslmode=disable" -X -v ON_ERROR_STOP=1 \
  -c "SELECT set_system_config('office.insecure_test_transport','true'::jsonb)" >/dev/null

(cd "$WEBMAIL" && \
  E2E_MANAGED_OFFICE=1 E2E_SERVER="$BASE" E2E_DB_NAME="$DB_NAME" E2E_GATEWAY_PORT="$GATEWAY_PORT" \
  E2E_DB_DSN="postgres://mail@127.0.0.1:5432/${DB_NAME}?sslmode=disable" \
  SETJOIN_UPDATER_BIN="$UPDATER_BIN" PLAYWRIGHT_JSON_OUTPUT_FILE="$RESULTS/playwright.json" \
  bash "$ROOT/scripts/playwright-supported.sh" -- npx playwright test \
    e2e/office-managed-install.spec.ts --project=admin-chromium)

echo "office-managed-install-e2e: PASS — $RESULTS/playwright.json"
