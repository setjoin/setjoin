#!/usr/bin/env bash
# SCIM Provisioning Integration Test
# Prerequisites: dev stack running (bash scripts/dev.sh)
# Usage: bash scripts/test-scim.sh [gateway_url] [scim_token]
#
# Creates a test user, verifies GET/PATCH/DELETE, tests group CRUD,
# filter queries, and validates error responses.

set -euo pipefail

GATEWAY="${1:-http://localhost:80}"
TOKEN="${2:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; exit 1; }

# ── Helpers ────────────────────────────────────────────────────────────────

scim_get() {
    curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" -H "Accept: application/scim+json" "$GATEWAY$1"
}

scim_get_body() {
    curl -s -H "Authorization: Bearer $TOKEN" -H "Accept: application/scim+json" "$GATEWAY$1"
}

scim_post() {
    curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json" -H "Accept: application/scim+json" -d "$2" "$GATEWAY$1"
}

scim_post_body() {
    curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json" -H "Accept: application/scim+json" -d "$2" "$GATEWAY$1"
}

scim_patch() {
    curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json" -H "Accept: application/scim+json" -X PATCH -d "$2" "$GATEWAY$1"
}

scim_delete() {
    curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$GATEWAY$1"
}

# ── Prerequisites ───────────────────────────────────────────────────────────

echo "=== SCIM Provisioning Integration Test ==="
echo "Gateway: $GATEWAY"

if [ -z "$TOKEN" ]; then
    echo ""
    echo "No SCIM token provided. Create one with:"
    echo "  DB_DSN=\"\$DB_DSN\" go run ./cmd/mailctl scim create-token --name test-scim-integration"
    echo ""
    echo "Then pass it as the second argument:"
    echo "  bash scripts/test-scim.sh http://localhost:80 <token>"
    echo ""
    echo "Skipping integration tests."
    exit 0
fi

# Wait for gateway
for _ in $(seq 1 10); do
    if curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/health" 2>/dev/null | grep -q 200; then
        break
    fi
    sleep 1
done

# ── ServiceProviderConfig ───────────────────────────────────────────────────

echo ""
echo "--- ServiceProviderConfig ---"
CODE=$(scim_get "/scim/v2/ServiceProviderConfig")
[ "$CODE" = "200" ] && pass "GET ServiceProviderConfig → 200" || fail "GET ServiceProviderConfig → $CODE (expected 200)"

# ── Users CRUD ──────────────────────────────────────────────────────────────

echo ""
echo "--- Users ---"

TEST_EXT_ID="scim-integration-test-$(date +%s)"

# Create user
USER_BODY=$(cat <<EOF
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
  "externalId": "$TEST_EXT_ID",
  "userName": "scimtest@example.com",
  "name": {
    "givenName": "Integration",
    "familyName": "Test"
  },
  "displayName": "Integration Test User",
  "emails": [{"value": "scimtest@example.com", "type": "work", "primary": true}],
  "title": "QA Engineer",
  "active": true
}
EOF
)

CODE=$(scim_post "/scim/v2/Users" "$USER_BODY")
[ "$CODE" = "201" ] && pass "POST /Users → 201" || fail "POST /Users → $CODE (expected 201)"

# Get the user ID from the response
RESP=$(scim_post_body "/scim/v2/Users" "$USER_BODY")
USER_ID=$(echo "$RESP" | grep -o '"id":"[0-9]*"' | head -1 | sed 's/"id":"//;s/"//')
echo "  User ID: $USER_ID"

# GET user
CODE=$(scim_get "/scim/v2/Users/$USER_ID")
[ "$CODE" = "200" ] && pass "GET /Users/$USER_ID → 200" || fail "GET /Users/$USER_ID → $CODE (expected 200)"

# GET user by filter
CODE=$(scim_get "/scim/v2/Users?filter=userName%20eq%20%22scimtest@example.com%22")
[ "$CODE" = "200" ] && pass "GET /Users?filter=userName eq → 200" || fail "GET /Users?filter → $CODE (expected 200)"

# PATCH user — change displayName
PATCH_BODY='{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Integration Test Updated"}]}'
CODE=$(scim_patch "/scim/v2/Users/$USER_ID" "$PATCH_BODY")
[ "$CODE" = "200" ] && pass "PATCH /Users/$USER_ID displayName → 200" || fail "PATCH /Users/$USER_ID → $CODE (expected 200)"

# PUT user — full replacement
PUT_BODY=$(cat <<EOF
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "externalId": "$TEST_EXT_ID",
  "userName": "scimtest2@example.com",
  "displayName": "Integration Test Replaced"
}
EOF
)
CODE=$(scim_post "/scim/v2/Users/$USER_ID" "$PUT_BODY")
echo "  PUT /Users/$USER_ID → $CODE (idempotent via externalId)"

# GET users list
CODE=$(scim_get "/scim/v2/Users")
[ "$CODE" = "200" ] && pass "GET /Users → 200" || fail "GET /Users → $CODE (expected 200)"

# ── Groups CRUD ─────────────────────────────────────────────────────────────

echo ""
echo "--- Groups ---"

GROUP_EXT_ID="scim-integration-group-$(date +%s)"

GROUP_BODY=$(cat <<EOF
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "externalId": "$GROUP_EXT_ID",
  "displayName": "Integration Test Group"
}
EOF
)

CODE=$(scim_post "/scim/v2/Groups" "$GROUP_BODY")
[ "$CODE" = "201" ] && pass "POST /Groups → 201" || fail "POST /Groups → $CODE (expected 201)"

RESP=$(scim_post_body "/scim/v2/Groups" "$GROUP_BODY")
GROUP_ID=$(echo "$RESP" | grep -o '"id":"[0-9]*"' | head -1 | sed 's/"id":"//;s/"//')
echo "  Group ID: $GROUP_ID"

CODE=$(scim_get "/scim/v2/Groups/$GROUP_ID")
[ "$CODE" = "200" ] && pass "GET /Groups/$GROUP_ID → 200" || fail "GET /Groups/$GROUP_ID → $CODE (expected 200)"

# PATCH group — rename
PATCH_GROUP='{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Integration Test Group Renamed"}]}'
CODE=$(scim_patch "/scim/v2/Groups/$GROUP_ID" "$PATCH_GROUP")
[ "$CODE" = "200" ] && pass "PATCH /Groups/$GROUP_ID displayName → 200" || fail "PATCH /Groups/$GROUP_ID → $CODE (expected 200)"

# ── Cleanup ─────────────────────────────────────────────────────────────────

echo ""
echo "--- Cleanup ---"

# Delete test user
CODE=$(scim_delete "/scim/v2/Users/$USER_ID" -X DELETE)
[ "$CODE" = "204" ] && pass "DELETE /Users/$USER_ID → 204" || fail "DELETE /Users/$USER_ID → $CODE (expected 204)"

# Delete test group
CODE=$(scim_delete "/scim/v2/Groups/$GROUP_ID" -X DELETE)
[ "$CODE" = "204" ] && pass "DELETE /Groups/$GROUP_ID → 204" || fail "DELETE /Groups/$GROUP_ID → $CODE (expected 204)"

# Verify deleted
CODE=$(scim_get "/scim/v2/Users/$USER_ID")
[ "$CODE" = "404" ] && pass "GET deleted user → 404" || fail "GET deleted user → $CODE (expected 404)"

CODE=$(scim_get "/scim/v2/Groups/$GROUP_ID")
[ "$CODE" = "404" ] && pass "GET deleted group → 404" || fail "GET deleted group → $CODE (expected 404)"

# ── Error Handling ──────────────────────────────────────────────────────────

echo ""
echo "--- Error Handling ---"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid-token" -H "Accept: application/scim+json" "$GATEWAY/scim/v2/Users")
[ "$CODE" = "401" ] && pass "Invalid token → 401" || fail "Invalid token → $CODE (expected 401)"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Accept: application/scim+json" "$GATEWAY/scim/v2/Users")
[ "$CODE" = "401" ] && pass "Missing token → 401" || fail "Missing token → $CODE (expected 401)"

echo ""
echo "=== SCIM Integration Tests Complete ==="
