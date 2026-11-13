# API error shape: RFC 7807 Problem Details

Every app-JSON-API error response (webmail SPA, admin console, mobile/desktop
clients — anything served under `/api` or a pinned JSON prefix, see
`scripts/api-pinned-prefixes.txt`) uses the same wire shape: RFC 7807
(`application/problem+json`).

## The rule

- **Write errors with `httputil.WriteProblem(w, r, problem)`** (has `r` — sets
  `Instance` to the request path and resolves `Content-Language`) or
  **`httputil.WriteProblemStatus(w, code, detail)`** (no `r` — for middleware
  and deep call sites that don't hold the request). Both live in
  `shared/httputil/problem.go`.
- **`httputil.WriteError(w, code, msg)` is a deprecated alias.** It forwards
  to `WriteProblemStatus` under the hood, so it already emits
  `application/problem+json` — but it produces only a minimal Problem (no
  typed `type` URI, no `Instance`). Prefer `WriteProblem`/`WriteProblemStatus`
  directly in new code; don't add new `WriteError` call sites.
- **`http.Error(w, msg, code)` (the stdlib plain-text emitter) is banned**
  outside a narrow allowlist. It writes `text/plain` with no machine-readable
  `type`/`detail`/`instance` — every client-side error handler that expects a
  `Problem` breaks silently against it. Enforced by
  `scripts/check-http-error-shape.sh` (see below) — that guard is the source
  of truth for exactly which files are exempt; do not hand-audit for new
  `http.Error(` sites, run the guard.

## The published contract

The wire shape is documented once, formally, at
`mailserver/api/openapi.yaml` → `#/components/schemas/Problem`. That schema
is what clients (and this doc) should treat as canonical; this file explains
the Go-side plumbing that produces it.

## Carve-outs (legitimate non-`Problem` responses)

Not everything the gateway serves is app JSON API. These are intentionally
**not** converted to `Problem`:

| Surface | Shape | Why |
|---|---|---|
| `writeThreatResponse` (`shared/threat/interceptor.go`) / login-threat responses | custom JSON (`{"error","captcha_prompt","captcha_token","retry_after"}` + `X-Threat-*` headers) | The threat interceptor's response carries CAPTCHA/tarpit-specific fields and headers a generic `Problem` doesn't model; it predates and sits outside the app-JSON-API surface this standard governs. |
| OAuth2 / OIDC endpoints (JWKS, discovery documents, token/authorize responses) | RFC 7517 / RFC 8414 / RFC 6749 shapes | These are interoperability contracts with external specs, not this app's API — they must match the RFC, not `Problem`. |
| WebDAV / CalDAV / CardDAV (`internal/webdav`, `internal/caldav`, `internal/carddav`) | RFC 4918/4791/6352 XML + HTTP status | Protocol responses to DAV clients (not the SPA); XML, not JSON. |
| IMAP / SMTP / LDAP | protocol-native error responses | Not HTTP at all. |
| Health / readiness / redirect handlers | plain text or empty body, or a `3xx` redirect | Infra probes (HAProxy, Kubernetes) and click-through redirect handlers (e.g. link-protect) don't parse JSON; a `Problem` body would be dead weight or, for a redirect, moot. |

Every carve-out that calls `http.Error(` directly is listed with its reason
in `scripts/http-error-allowlist.txt`, which the guard reads. If you're
adding a new non-JSON surface, add it there (narrowly — a file, or a
directory for a whole protocol package) rather than disabling the guard.

## The guard

`scripts/check-http-error-shape.sh` scans `authserver/`, `mailserver/`, and
`shared/` for `http.Error(` call sites (excluding `_test.go`), fails the
build if any are found outside `scripts/http-error-allowlist.txt`, and names
`file:line` for each. It runs as part of the structural-guard manifest
(`scripts/run-guards.sh`, invoked by `scripts/test.sh` and CI) — dropping the
file into `scripts/` was enough to wire it in, no orchestrator edit needed.
Self-test: `scripts/check-http-error-shape.sh --self-test` (proves the guard
fires on a planted non-allowlisted site and stays silent on an allowlisted
one).
