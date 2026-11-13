#!/usr/bin/env bash
# xinchuang-smoke-test.sh — Integration smoke test on Xinchuang hardware.
# Expects authserver and gateway binaries in PATH or $BIN_DIR.
# Requires: curl, jq
set -euo pipefail

BIN_DIR="${BIN_DIR:-.}"
AUTHSERVER="${AUTHSERVER:-$BIN_DIR/authserver}"
GATEWAY="${GATEWAY:-$BIN_DIR/gateway}"
AUTHSERVER_PORT="${AUTHSERVER_PORT:-18443}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
TEST_DB_DSN="${TEST_DB_DSN:-postgres://mail:test@127.0.0.1:5432/mailserver?sslmode=disable}"

PASS=0
FAIL=0
check() {
    local desc="$1"
    local cmd="$2"
    echo -n "  $desc ... "
    if eval "$cmd" &>/dev/null; then
        echo "PASS"
        ((PASS++))
    else
        echo "FAIL"
        ((FAIL++))
    fi
}

echo "=== Xinchuang Smoke Test ==="
echo "Platform: $(uname -m) / $(uname -o 2>/dev/null || uname -s)"
echo "Authserver: $AUTHSERVER"
echo "Gateway: $GATEWAY"
echo ""

# --- Authserver smoke ---
echo "--- Authserver ---"

# Start authserver in background
JWT_SECRET="test-secret-at-least-32-characters-long" \
INTERNAL_API_KEY="test-api-key-for-gateway" \
LISTEN_ADDR=":${AUTHSERVER_PORT}" \
DB_DSN="$TEST_DB_DSN" \
"$AUTHSERVER" &
AUTH_PID=$!
trap 'kill "$AUTH_PID" 2>/dev/null; exit' EXIT

sleep 2

check "authserver /health" \
    "curl -sf http://127.0.0.1:${AUTHSERVER_PORT}/health"

check "authserver /ready" \
    "curl -sf http://127.0.0.1:${AUTHSERVER_PORT}/ready"

check "authserver /health returns JSON" \
    "curl -sf http://127.0.0.1:${AUTHSERVER_PORT}/health | jq -e '.status'"

# --- Gateway smoke ---
echo "--- Gateway ---"

JWT_SECRET="test-secret-at-least-32-characters-long" \
AUTHSERVER_URL="http://127.0.0.1:${AUTHSERVER_PORT}" \
INTERNAL_API_KEY="test-api-key-for-gateway" \
LISTEN_ADDR=":${GATEWAY_PORT}" \
DB_DSN="$TEST_DB_DSN" \
S3_ENDPOINT="127.0.0.1:9000" \
S3_ACCESS_KEY="test" \
S3_SECRET_KEY="testsecret" \
S3_BUCKET="mailblobs" \
"$GATEWAY" &
GW_PID=$!
trap 'kill "$AUTH_PID" "$GW_PID" 2>/dev/null; exit' EXIT

sleep 3

check "gateway /health" \
    "curl -sf http://127.0.0.1:${GATEWAY_PORT}/health"

check "gateway /ready" \
    "curl -sf http://127.0.0.1:${GATEWAY_PORT}/ready"

check "gateway JMAP session fetch" \
    "curl -sf http://127.0.0.1:${GATEWAY_PORT}/jmap/session | jq -e '.capabilities'"

# --- Xinchuang-specific checks ---
echo "--- Xinchuang Checks ---"

check "binary ELF architecture matches host" \
    "file '$AUTHSERVER' | grep -q '$(uname -m)'"

check "authserver binary is statically linked" \
    "file '$AUTHSERVER' | grep -q 'statically linked'"

check "gateway binary is statically linked" \
    "file '$GATEWAY' | grep -q 'statically linked'"

# --- Results ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
echo "Smoke test PASSED."
