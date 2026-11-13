#!/usr/bin/env bash
# shellcheck source=scripts/_base.sh
source "$(dirname "$0")/_base.sh"

MODE="${1:-all}"
if [ "$#" -gt 1 ]; then
    echo "Usage: bash scripts/e2e.sh [all|imap|smtp|ldap|link-protect|link-protect-local|ews|m365|marketplace]" >&2
    exit 2
fi

if [ "$MODE" != "marketplace" ]; then
    if [ "$MODE" = "link-protect-local" ]; then
        echo "=== Running local link-protect token-flow contract (no external Safe Browsing credentials) ==="
        (cd "$ROOT/mailserver" && \
            go test -tags e2e -run '^TestLinkProtectE2E_TokenFlow$' -count=1 -timeout 120s ./internal/smtp/...)
    else
        bash "$ROOT/mailserver/deploy/test.sh" "$MODE"
    fi
    exit 0
fi

# Marketplace smoke is a separate live-gateway lane. Requiring an explicit
# origin prevents protocol-only runs from probing whatever owns localhost:80.
: "${GATEWAY_URL:?GATEWAY_URL is required for marketplace smoke (for example http://127.0.0.1:18080)}"
case "$GATEWAY_URL" in
    http://*|https://*) ;;
    *) echo "GATEWAY_URL must use http:// or https://" >&2; exit 2 ;;
esac
GATEWAY_URL="${GATEWAY_URL%/}"
SMOKE_FAILS=0
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo ""
echo "=== Marketplace smoke tests ==="

# 1. Download manifest returns a bounded JSON platform list.
echo -n "  GET /downloads ... "
if curl -fsS --connect-timeout 3 --max-time 10 "$GATEWAY_URL/downloads" -o "$TMP_DIR/downloads.json" \
    && jq -e '.platforms | type == "array" and length > 0 and all(.[]; (.name|type)=="string" and (.slug|type)=="string")' "$TMP_DIR/downloads.json" >/dev/null; then
    echo "PASS"
else
    echo "FAIL (unreachable or invalid platform manifest)"
    SMOKE_FAILS=$((SMOKE_FAILS+1))
fi

# 2. Discovery response carries the stable client bootstrap fields.
echo -n "  GET /.well-known/setjoin ... "
if curl -fsS --connect-timeout 3 --max-time 10 "$GATEWAY_URL/.well-known/setjoin" -o "$TMP_DIR/wellknown.json" \
    && jq -e '.version == "1.0" and (.crypto_profile|type)=="string" and (.features|type)=="array" and (.features|index("jmap") != null)' "$TMP_DIR/wellknown.json" >/dev/null; then
    echo "PASS"
else
    echo "FAIL (unreachable or invalid discovery contract)"
    SMOKE_FAILS=$((SMOKE_FAILS+1))
fi

# 3. The legacy path redirects without consuming or changing the POST body. Do
# not ask curl to follow it: the redirect contract itself is compatibility.
echo -n "  POST /telemetry (legacy redirect) ... "
STATUS=$(curl -sS --connect-timeout 3 --max-time 10 -D "$TMP_DIR/telemetry-legacy.headers" \
    -o "$TMP_DIR/telemetry-legacy.body" -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" -d '{"device_id":1}' "$GATEWAY_URL/telemetry" 2>/dev/null || true)
LOCATION=$(awk 'BEGIN { IGNORECASE=1 } /^Location:/ { gsub("\r", "", $2); print $2 }' "$TMP_DIR/telemetry-legacy.headers")
if [ "$STATUS" = "308" ] && [ "$LOCATION" = "/api/telemetry" ] && [ ! -s "$TMP_DIR/telemetry-legacy.body" ]; then
    echo "PASS ($STATUS -> $LOCATION)"
else
    echo "FAIL (${STATUS:-unreachable}, location=${LOCATION:-missing})"
    SMOKE_FAILS=$((SMOKE_FAILS+1))
fi

# 4. The canonical disabled endpoint silently accepts the bounded payload with
# no response body and does not disclose whether telemetry is enabled.
echo -n "  POST /api/telemetry (disabled) ... "
STATUS=$(curl -sS --connect-timeout 3 --max-time 10 -o "$TMP_DIR/telemetry.body" -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" -d '{"device_id":1}' "$GATEWAY_URL/api/telemetry" 2>/dev/null || true)
if [ "$STATUS" = "204" ] && [ ! -s "$TMP_DIR/telemetry.body" ]; then
    echo "PASS ($STATUS)"
else
    echo "FAIL (${STATUS:-unreachable})"
    SMOKE_FAILS=$((SMOKE_FAILS+1))
fi

if [ "$SMOKE_FAILS" -gt 0 ]; then
    echo "Marketplace smoke tests: $SMOKE_FAILS FAILED."
    exit 1
fi
echo "Marketplace smoke tests complete."
