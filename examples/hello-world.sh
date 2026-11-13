#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# hello-world.sh — copy-pasteable end-to-end integration walk-through.
#
# Runs the 10 flows documented in docs/guides/INTEGRATION_EXAMPLES.md against a
# live setjoin server: discovery → login → JMAP session → list mailboxes → query
# + fetch a message → send a message → CalDAV/CardDAV PROPFIND.
#
# Every endpoint here is verified against the real handlers (mailserver/internal/
# jmap, the authserver login handler, internal/discovery, internal/caldav,
# internal/carddav) — no invented paths.
#
# Usage:
#   BASE=https://mail.example.com EMAIL=you@example.com PASSWORD=secret \
#     bash examples/hello-world.sh
#
#   # self-signed cert in dev? trust the dev CA explicitly (preferred):
#   CACERT=/path/to/dev-ca.pem BASE=https://localhost:443 EMAIL=admin@local PASSWORD=... \
#     bash examples/hello-world.sh
#
# Requires: curl and jq. Request bodies and URL query parameters are built with
# jq templating / --data-urlencode so every interpolated value is encoded —
# never hand-concatenated into JSON or URLs (output encoding by construction).
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail

BASE="${BASE:-https://localhost:443}"
EMAIL="${EMAIL:-admin@example.com}"
PASSWORD="${PASSWORD:-}"
CURL=(curl -sS)

have_jq() { command -v jq >/dev/null 2>&1; }
if ! have_jq; then
  echo "jq is required: this example builds every request body with 'jq -n --arg' so" >&2
  echo "interpolated values are always JSON-encoded (never raw shell interpolation)." >&2
  exit 1
fi
pp() { jq .; }
step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

# ── TLS posture ──────────────────────────────────────────────────────────────
# The default flow VALIDATES certificates. For a self-signed dev CA, pass
# CACERT=/path/to/ca.pem — that is the taught pattern. INSECURE=1 disables
# verification (-k) and is accepted ONLY for loopback BASE values: a
# copy-pasteable verification bypass against a remote host is one typo away
# from a MITM, so non-loopback INSECURE=1 is refused (fail closed).
if [ -n "${CACERT:-}" ]; then
  CURL+=("--cacert" "${CACERT}")
fi
if [ "${INSECURE:-0}" = "1" ]; then
  base_host="${BASE#*://}"
  base_host="${base_host%%[:/]*}"
  case "$base_host" in
    localhost|127.0.0.1|::1)
      echo "WARNING: INSECURE=1 disables TLS certificate verification — loopback/dev use only." >&2
      CURL+=(-k)
      ;;
    *)
      echo "INSECURE=1 ignored: BASE is not loopback. Trust your dev CA instead: CACERT=<ca.pem>" >&2
      ;;
  esac
fi

[ -n "$PASSWORD" ] || { echo "Set PASSWORD (and EMAIL, BASE). See header." >&2; exit 1; }

# ── 1. Client auto-discovery (no auth) ──────────────────────────────────────
# GET /api/discover?domain=<d> → {url, login_field, discovered_via}
# The domain is URL-encoded by curl (--data-urlencode), never concatenated.
step "1. GET /api/discover (client bootstrap, no auth)"
DOMAIN="${EMAIL#*@}"
"${CURL[@]}" --get "$BASE/api/discover" --data-urlencode "domain=$DOMAIN" | pp || true

# ── 2. JMAP well-known (RFC 8620 §2.2) — requires auth, so just show the 401 ──
# The authenticated session is fetched in step 4; here we confirm the endpoint
# exists and enforces auth (401 without a token is the correct response).
step "2. GET /.well-known/jmap (auth-gated; expect 401 unauthenticated)"
"${CURL[@]}" -o /dev/null -w "HTTP %{http_code}\n" "$BASE/.well-known/jmap" || true

# ── 3. Login → JWT (POST /auth/login) ───────────────────────────────────────
# Response: {access_token, refresh_token, expires_in}. MFA-enabled accounts get
# {mfa_required:true,...} instead — out of scope for this hello-world.
# Body is built with jq so EMAIL/PASSWORD are always JSON-encoded.
step "3. POST /auth/login"
LOGIN_BODY="$(jq -n --arg email "$EMAIL" --arg password "$PASSWORD" \
  '{email: $email, password: $password}')"
LOGIN_JSON="$("${CURL[@]}" -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  --data "$LOGIN_BODY")"
echo "$LOGIN_JSON" | pp
TOKEN="$(echo "$LOGIN_JSON" | jq -r '.access_token // empty')"
[ -n "$TOKEN" ] || { echo "No access_token (MFA required, or bad credentials). Stopping." >&2; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")

# ── 4. JMAP session (GET /.well-known/jmap, authed) ─────────────────────────
# Returns capabilities, accounts, primaryAccounts, apiUrl, and the accountId
# you pass to every method call below.
step "4. GET /.well-known/jmap (authenticated session)"
SESSION="$("${CURL[@]}" "${AUTH[@]}" "$BASE/.well-known/jmap")"
echo "$SESSION" | pp
ACCOUNT_ID="$(echo "$SESSION" | jq -r '.primaryAccounts["urn:ietf:params:jmap:mail"]')"
echo "accountId = $ACCOUNT_ID"

jmap() { # jmap <json-body> — POST a JMAP request to /jmap
  "${CURL[@]}" "${AUTH[@]}" -X POST "$BASE/jmap" -H 'Content-Type: application/json' --data "$1"
}

# ── 5. Mailbox/query — list mailbox ids ─────────────────────────────────────
step "5. POST /jmap — Mailbox/query"
JMAP_BODY="$(jq -n --arg account "$ACCOUNT_ID" '{
  using: ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
  methodCalls: [["Mailbox/query", {accountId: $account}, "c0"]]
}')"
jmap "$JMAP_BODY" | pp

# ── 6. Email/query — most-recent messages in the account ────────────────────
step "6. POST /jmap — Email/query (10 most recent)"
JMAP_BODY="$(jq -n --arg account "$ACCOUNT_ID" '{
  using: ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
  methodCalls: [["Email/query", {
     accountId: $account,
     sort: [{property: "receivedAt", isAscending: false}],
     limit: 10
  }, "c0"]]
}')"
QUERY_RESP="$(jmap "$JMAP_BODY")"
echo "$QUERY_RESP" | pp
EMAIL_ID="$(echo "$QUERY_RESP" | jq -r '.methodResponses[0][1].ids[0] // empty')"

# ── 7. Email/get — fetch headers of the first result ────────────────────────
step "7. POST /jmap — Email/get (first message)"
if [ -n "${EMAIL_ID:-}" ]; then
  JMAP_BODY="$(jq -n --arg account "$ACCOUNT_ID" --arg id "$EMAIL_ID" '{
    using: ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
    methodCalls: [["Email/get", {
       accountId: $account,
       ids: [$id],
       properties: ["id","subject","from","receivedAt","preview"]
    }, "c0"]]
  }')"
  jmap "$JMAP_BODY" | pp
else
  echo "(mailbox empty — skipping Email/get)"
fi

# ── 8. Send — Email/set (draft) then EmailSubmission/set, one request ────────
# JMAP send is two chained method calls: create a draft Email, then submit it.
# #ref back-references the created draft's id (RFC 8620 result references).
step "8. POST /jmap — Email/set (draft) + EmailSubmission/set (send)"
JMAP_BODY="$(jq -n --arg account "$ACCOUNT_ID" --arg email "$EMAIL" '{
  using: ["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],
  methodCalls: [
    ["Email/set", {
      accountId: $account,
      create: {draft1: {
        from: [{email: $email}],
        to:   [{email: $email}],
        subject: "hello-world from setjoin",
        bodyValues: {b: {value: "Sent by examples/hello-world.sh"}},
        textBody: [{partId: "b", type: "text/plain"}]
      }}
    }, "c0"],
    ["EmailSubmission/set", {
      accountId: $account,
      create: {sub1: {emailId: "#draft1"}}
    }, "c1"]
  ]
}')"
jmap "$JMAP_BODY" | pp

# ── 9. CalDAV PROPFIND — discover the calendar principal ────────────────────
# WebDAV PROPFIND for current-user-principal (RFC 5397). Returns 207 Multistatus.
step "9. PROPFIND /caldav/ — current-user-principal"
"${CURL[@]}" "${AUTH[@]}" -X PROPFIND "$BASE/caldav/" \
  -H 'Depth: 0' -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>' || true
echo

# ── 10. CardDAV PROPFIND — discover the addressbook principal ───────────────
step "10. PROPFIND /carddav/ — current-user-principal"
"${CURL[@]}" "${AUTH[@]}" -X PROPFIND "$BASE/carddav/" \
  -H 'Depth: 0' -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>' || true
echo

step "Done."
echo "All 10 flows attempted. CalDAV/CardDAV require the calendar/contacts apps"
echo "to be enabled (feature.caldav / feature.carddav toggles) and entitled."
