# Integration Examples

Ten runnable `curl` flows for integrating with a setjoin server, end to end:
client discovery → login → JMAP session → list mailboxes → query + fetch a
message → send → CalDAV/CardDAV discovery. Each flow shows the **request**, an
**anonymized response**, and a **success / failure check**.

> **Machine-readable reference:** the gateway serves the OpenAPI 3.1 contract for
> the core surface at **`GET /api/openapi.yaml`** (and `/api/openapi.json`), with a
> rendered **Redoc** reference at **`GET /api/docs`**. Point your client generator
> at the spec; the flows below are the worked examples behind it.

Every endpoint here is verified against the real handlers:

| Surface                | Source of truth                                  |
|------------------------|--------------------------------------------------|
| `/api/discover`        | `mailserver/internal/discovery`                  |
| `/auth/login`          | `authserver/internal/handlers/auth.go` (`Login`) |
| `/.well-known/jmap`, `/jmap` | `mailserver/internal/jmap` (`Session`, `Request`) |
| `/caldav/`             | `mailserver/internal/caldav`                     |
| `/carddav/`            | `mailserver/internal/carddav`                    |
| route wiring           | `mailserver/cmd/mailserverd/main.go`             |

For identity-source automation, use the admin-only full OpenAPI document and
the bounded examples in
[Identity API automation](IDENTITY_API_AUTOMATION.md). Identity mutations
require `X-Audit-Reason`, a matching body reason, and the operation-specific
generation, digest, or idempotency value. Never automate a link from email or
UPN evidence.

**Copy-pasteable runner:** [`examples/hello-world.sh`](../../examples/hello-world.sh)
runs all ten in sequence:

```bash
BASE=https://mail.example.com EMAIL=you@example.com PASSWORD=secret \
  bash examples/hello-world.sh
# dev with a self-signed cert? add INSECURE=1 (passes -k to curl)
```

Conventions below: `$BASE` = `https://mail.example.com`, `$TOKEN` = the JWT from
flow 3, `$ACCT` = the `accountId` from flow 4. Add `-k` to `curl` for a
self-signed dev cert.

---

## 1. Client auto-discovery — `GET /api/discover`

Unauthenticated. A client bootstraps from an email domain (DNS SRV/MX +
`.well-known/setjoin`).

**Request**
```bash
curl -s "$BASE/api/discover?domain=example.com"
```

**Response** (`200`)
```json
{
  "url": "https://mail.example.com",
  "login_field": "email",
  "discovered_via": "srv"
}
```

**Check:** HTTP `200` with a `url`. Failure: `404 {"error":"no server found for
domain example.com"}` (no SRV/MX/well-known) or `400` (missing `domain`).

---

## 2. JMAP session endpoint exists & is auth-gated — `GET /.well-known/jmap`

The session document (flow 4) requires a Bearer token. Unauthenticated it must
return `401` — a quick liveness + auth-enforcement probe.

**Request**
```bash
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/.well-known/jmap"
```

**Response:** `401`.

**Check:** `401` (auth enforced). A `200` here would mean auth is misconfigured;
connection-refused means the gateway is down.

---

## 3. Log in — `POST /auth/login`

Proxied to the auth server. Returns a JWT access token (+ refresh token).

**Request**
```bash
curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"••••••••"}'
```

**Response** (`200`)
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0Mi...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJyZf...",
  "expires_in": 3600
}
```

**Check:** `access_token` present → save it as `$TOKEN`. If the account has MFA,
the response is `{"mfa_required":true,...}` (complete `/auth/totp/*` or
`/auth/push/*` first). `401 {"detail":"invalid credentials"}` = bad email/password.

```bash
TOKEN=$(curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"••••••••"}' | jq -r .access_token)
```

---

## 4. JMAP session — `GET /.well-known/jmap` (authenticated)

The capabilities + accounts document (RFC 8620 §2). The `accountId` you use in
every method call is `primaryAccounts["urn:ietf:params:jmap:mail"]`.

**Request**
```bash
curl -s "$BASE/.well-known/jmap" -H "Authorization: Bearer $TOKEN"
```

**Response** (`200`, abridged)
```json
{
  "capabilities": {
    "urn:ietf:params:jmap:core": { "maxSizeUpload": 26214400, "maxCallsInRequest": 32 },
    "urn:ietf:params:jmap:mail": {},
    "urn:ietf:params:jmap:submission": {},
    "urn:ietf:params:jmap:blob": {}
  },
  "accounts": {
    "42": { "name": "you@example.com", "isPersonal": true, "isReadOnly": false }
  },
  "primaryAccounts": {
    "urn:ietf:params:jmap:mail": "42",
    "urn:ietf:params:jmap:calendars": "42",
    "urn:ietf:params:jmap:contacts": "42"
  },
  "username": "you@example.com",
  "apiUrl": "https://mail.example.com/jmap",
  "uploadUrl": "https://mail.example.com/jmap/upload/{accountId}",
  "downloadUrl": "https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}?type={type}",
  "state": "0"
}
```

**Check:** `primaryAccounts["urn:ietf:params:jmap:mail"]` is your `$ACCT`. The
account id is the integer mailbox id, surfaced as a string.

```bash
ACCT=$(curl -s "$BASE/.well-known/jmap" -H "Authorization: Bearer $TOKEN" \
  | jq -r '.primaryAccounts["urn:ietf:params:jmap:mail"]')
```

---

## 5. List mailboxes — `POST /jmap` · `Mailbox/query`

All method calls go to `POST /jmap` with a `using` array + `methodCalls`
triples `[name, args, callId]` (RFC 8620 §3.2). The empty `using` array is
rejected (Errata 6606).

**Request**
```bash
curl -s -X POST "$BASE/jmap" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{
    \"using\": [\"urn:ietf:params:jmap:core\",\"urn:ietf:params:jmap:mail\"],
    \"methodCalls\": [[\"Mailbox/query\", {\"accountId\": \"$ACCT\"}, \"c0\"]]
  }"
```

**Response** (`200`)
```json
{
  "methodResponses": [
    ["Mailbox/query", { "accountId": "42", "ids": ["1001","1002","1003"], "total": 3 }, "c0"]
  ]
}
```

**Check:** `methodResponses[0][0] == "Mailbox/query"` and `ids` is non-empty. An
unknown capability in `using` → request-level error; a per-method failure comes
back as `["error", {...}, "c0"]`.

---

## 6. Query recent messages — `POST /jmap` · `Email/query`

**Request**
```bash
curl -s -X POST "$BASE/jmap" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{
    \"using\": [\"urn:ietf:params:jmap:core\",\"urn:ietf:params:jmap:mail\"],
    \"methodCalls\": [[\"Email/query\", {
       \"accountId\": \"$ACCT\",
       \"sort\": [{\"property\": \"receivedAt\", \"isAscending\": false}],
       \"limit\": 10
    }, \"c0\"]]
  }"
```

**Response** (`200`)
```json
{
  "methodResponses": [
    ["Email/query", { "accountId": "42", "ids": ["55021","55019","55003"],
      "position": 0, "total": 3, "queryState": "0" }, "c0"]
  ]
}
```

**Check:** `ids` holds message ids most-recent-first. Empty `ids` = empty
mailbox (not an error).

---

## 7. Fetch a message — `POST /jmap` · `Email/get`

**Request**
```bash
curl -s -X POST "$BASE/jmap" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{
    \"using\": [\"urn:ietf:params:jmap:core\",\"urn:ietf:params:jmap:mail\"],
    \"methodCalls\": [[\"Email/get\", {
       \"accountId\": \"$ACCT\",
       \"ids\": [\"55021\"],
       \"properties\": [\"id\",\"subject\",\"from\",\"receivedAt\",\"preview\"]
    }, \"c0\"]]
  }"
```

**Response** (`200`)
```json
{
  "methodResponses": [
    ["Email/get", {
      "accountId": "42",
      "state": "0",
      "list": [{
        "id": "55021",
        "subject": "Q3 planning",
        "from": [{ "name": "Dana Example", "email": "dana@example.com" }],
        "receivedAt": "2026-06-18T14:02:51Z",
        "preview": "Here is the draft agenda for…"
      }],
      "notFound": []
    }, "c0"]
  ]
}
```

**Check:** the requested id is in `list` (not `notFound`). An id you don't own
lands in `notFound` (ownership is enforced server-side, ARCH-003).

---

## 8. Send a message — `POST /jmap` · `Email/set` + `EmailSubmission/set`

JMAP send is two chained calls in one request: create a draft `Email`, then
`EmailSubmission/set` it. `#draft1` is a back-reference (RFC 8620 result
reference) to the created draft's id.

**Request**
```bash
curl -s -X POST "$BASE/jmap" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{
    \"using\": [\"urn:ietf:params:jmap:core\",\"urn:ietf:params:jmap:mail\",\"urn:ietf:params:jmap:submission\"],
    \"methodCalls\": [
      [\"Email/set\", { \"accountId\": \"$ACCT\", \"create\": { \"draft1\": {
        \"from\": [{\"email\": \"you@example.com\"}],
        \"to\":   [{\"email\": \"friend@example.com\"}],
        \"subject\": \"Hello from JMAP\",
        \"bodyValues\": {\"b\": {\"value\": \"Sent via the setjoin gateway.\"}},
        \"textBody\": [{\"partId\": \"b\", \"type\": \"text/plain\"}]
      }}}, \"c0\"],
      [\"EmailSubmission/set\", { \"accountId\": \"$ACCT\",
        \"create\": { \"sub1\": { \"emailId\": \"#draft1\" } } }, \"c1\"]
    ]
  }"
```

**Response** (`200`)
```json
{
  "methodResponses": [
    ["Email/set", { "accountId": "42", "created": { "draft1": { "id": "55022" } } }, "c0"],
    ["EmailSubmission/set", { "accountId": "42",
      "created": { "sub1": { "id": "9001", "sendAt": "2026-06-18T14:05:00Z" } } }, "c1"]
  ]
}
```

**Check:** both calls report under `created` (not `notCreated`). To **schedule**
a send, add `"sendAt": "2026-06-18T18:00:00Z"` to the submission create (vendor
extension `sendAtOnEmailSubmissionSet`); cancel with `EmailSubmission/cancel`.

---

## 9. CalDAV discovery — `PROPFIND /caldav/`

Standard WebDAV `current-user-principal` discovery (RFC 5397). Requires the
**calendar** app to be enabled (`feature.caldav`) and entitled to the user.

**Request**
```bash
curl -s -X PROPFIND "$BASE/caldav/" -H "Authorization: Bearer $TOKEN" \
  -H 'Depth: 0' -H 'Content-Type: application/xml' --data '<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>'
```

**Response** (`207 Multistatus`)
```xml
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/caldav/</d:href>
    <d:propstat>
      <d:prop><d:current-user-principal><d:href>/principals/42</d:href></d:current-user-principal></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>
```

**Check:** `207` with a `<current-user-principal>` href. `404`/`405` means the
calendar feature toggle is off; `401` means a missing/expired token.

---

## 10. CardDAV discovery — `PROPFIND /carddav/`

Same WebDAV discovery for contacts. Requires the **contacts** app
(`feature.carddav`).

**Request**
```bash
curl -s -X PROPFIND "$BASE/carddav/" -H "Authorization: Bearer $TOKEN" \
  -H 'Depth: 0' -H 'Content-Type: application/xml' --data '<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>'
```

**Response** (`207 Multistatus`)
```xml
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/carddav/</d:href>
    <d:propstat>
      <d:prop><d:current-user-principal><d:href>/principals/42</d:href></d:current-user-principal></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>
```

**Check:** `207` with the principal href. From the principal you PROPFIND the
`addressbook-home-set` to enumerate address books.

---

## Notes

- **Auth on every protected call:** `Authorization: Bearer $TOKEN`. The webmail
  SPA also accepts the token via an `access_token` HttpOnly cookie; API
  integrations use the header.
- **Account id:** a string-encoded integer mailbox id from the session's
  `primaryAccounts`. Passing another user's id is rejected (`accountNotFound`).
- **Errors:** request-level problems use RFC 8620 error URNs
  (`urn:ietf:params:jmap:error:*`); per-method failures appear as an `["error",
  {...}, callId]` entry in `methodResponses`.
- **Feature toggles:** CalDAV/CardDAV are gated by `feature.caldav` /
  `feature.carddav` and per-user app entitlement (see `mailserver/AGENTS.md`).
