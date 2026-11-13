---
source_urls:
  - https://www.rfc-editor.org/rfc/rfc9700.txt   # OAuth 2.0 Security Best Current Practice (BCP 240), Jan 2025
  - https://www.rfc-editor.org/rfc/rfc8725.txt   # JSON Web Token Best Current Practices (BCP 225), Feb 2020
fetched: 2026-06-10
applies_to: authserver/  (and shared/jwtutil, mailserver gateway JWT validation)
---

# RFC 9700 + RFC 8725 — Requirements relevant to the SetJoin authserver

Local copies: `docs/ref/rfc/rfc9700.txt` (2569 lines), `docs/ref/rfc/rfc8725.txt` (680 lines).

This note distills the normative requirements from these two BCPs that bear on the
authserver's design: HMAC-SHA256 access/refresh JWTs (`token/jwt.go`), refresh
rotation with theft detection (`token/refresh.go`), the OIDC IdP/RP built on
zitadel/oidc (`federation/oidc_op.go`, `oidc_rp.go`), RFC 7662 token introspection
(`token/introspect.go`, `handlers/introspect_handler.go`), and WebAuthn
(`authn/webauthn.go`). Each item cites the RFC section and is paired with what to
verify in the code.

The two RFCs split cleanly:
- **RFC 8725** governs how we mint and validate the JWTs themselves (signing alg,
  claim validation, key entropy, cross-JWT confusion).
- **RFC 9700** governs the OAuth/OIDC protocol flows around those tokens (refresh
  rotation/theft detection, audience restriction, PKCE, no ROPC, client auth).

---

## A. JWT issuance & validation (RFC 8725)

### A1 — Pin the signing algorithm; never trust `alg` from the token (8725 §3.1, §2.1)
**Requirement (MUST):** the verifier must specify the allowed algorithm set and
must not use any other. The library must ensure the `alg` header matches the
algorithm actually used, and each key is bound to exactly one algorithm. This
blocks the `alg:none` bypass and the RS256→HS256 key-confusion attack (§2.1).

**Verify in code:**
- [x] `token/jwt.go:Validate` rejects unexpected methods: it type-asserts
      `t.Method.(*jwt.SigningMethodHMAC)` on the HS256 path and only returns the
      SM2 public key when `alg == "SM2"`. Confirm there is **no** path that returns
      `p.secret` (HMAC key) for an asymmetric `alg` — i.e. an attacker cannot send
      `alg:RS256`/`alg:none` and have it accepted. (Currently safe.)
- [ ] Confirm the `golang-jwt/jwt/v5` parser is never called with a key-func that
      returns a key without checking `t.Method`/`alg` anywhere else in the tree
      (grep `ParseWithClaims`, `Parse(` across authserver + mailserver gateway).
- [ ] Confirm the `kid` header is validated against a known set (`kidHMAC`,
      `kidSM2`) before key selection — done in `Validate`; flag any verifier that
      ignores `kid`.

### A2 — Reject `alg:none` unless explicitly requested (8725 §3.2)
**Requirement (SHOULD NOT):** libraries should not consume JWTs using `none`
unless the caller explicitly asks. Our tokens are always integrity-protected, so
`none` must never be accepted.
**Verify:** [ ] No verifier accepts `none`; golang-jwt/v5 rejects `none` by default
unless `UnsafeAllowNoneSignatureType` is used — grep to confirm it is absent.

### A3 — Sufficient key entropy; no human passwords as HMAC keys (8725 §3.5, §2.2)
**Requirement (MUST):** for `HS256`, the symmetric key must have sufficient
entropy; a human-memorizable password MUST NOT be used directly as the HMAC key
(§2.2 warns weak HS256 keys fall to offline brute force once a token leaks).
**Verify in code:**
- [ ] `JWT_SECRET` is enforced to be ≥ 32 bytes of high-entropy material at
      startup (CLAUDE.md documents "≥ 32 chars"). Confirm config validation
      rejects short/empty secrets rather than silently running. Prefer a randomly
      generated secret, not an operator-typed passphrase.
- [ ] The same `JWT_SECRET` is shared gateway↔authserver — ensure it is delivered
      via secret store/env, never committed, and rotated on compromise.

### A4 — Validate issuer (`iss`) (8725 §3.8)
**Requirement (MUST):** when a JWT carries `iss`, validate that the keys used to
verify it belong to that issuer, and reject otherwise.
**Verify:** [x] `Validate` passes `jwt.WithIssuer(p.issuer)`. Confirm the gateway's
verifier asserts the **same** issuer string (`JWT_ISSUER`, default `mailserver`)
that the authserver signs with — a mismatch silently breaks auth, a missing check
allows foreign-issuer tokens.

### A5 — Use and validate audience (`aud`) (8725 §3.9; reinforced by 9700 §2.3)
**Requirement (MUST):** if one issuer can mint tokens for more than one relying
party, tokens MUST carry `aud`, and each RP MUST validate it and reject if the
audience is absent or not associated with that RP.
**Verify in code:**
- [x] All issuance paths in `token/jwt.go` set `Audience: jwt.ClaimStrings{audience}`
      where `audience = "mailserver-gateway"`; `Validate` enforces
      `jwt.WithAudience(audience)`.
- [ ] Confirm the mailserver gateway's `RequireAuth` verifier also enforces
      `aud == "mailserver-gateway"`. If any other resource server (future Drive /
      Chat apps) consumes these tokens, give them distinct `aud` values and
      validate per-RP (9700 §2.3 audience restriction).

### A6 — Prevent cross-JWT confusion: mutually exclusive validation per token kind (8725 §2.8, §3.11, §3.12)
**Requirement (MUST):** the same issuer mints many JWT kinds (access, refresh,
MFA-pending, force-password-change, password-reset, impersonation). Validation
rules MUST be written so a token of the wrong kind is rejected. Strategies (§3.12):
distinct required claims/values, distinct `typ` header, distinct keys, distinct `aud`.
**Verify in code:**
- [x] A private `Type` claim discriminates kinds (`TypeAccess`, `TypeRefresh`,
      `TypeMFAPending`, `TypeForcePasswordChange`, `TypePasswordReset`).
- [x] `RefreshTokens` rejects `claims.Type != TypeRefresh`; the auth chain rejects
      `TypeMFAPending`/`TypeRefresh` on the bearer path, and `RequireAuth` rejects
      non-`TypeAccess` (defense-in-depth, per CLAUDE.md).
- [ ] **Gap to confirm:** these tokens currently share one `aud`
      (`mailserver-gateway`) and one HMAC key, so isolation rests entirely on the
      `Type` claim being checked at *every* consumption point. Audit every place a
      token is accepted (login, refresh, MFA verify, password change, password
      reset single-use, impersonation) and confirm each asserts the expected
      `Type`. Consider adding an explicit `typ` header (8725 §3.11 RECOMMENDED for
      new uses) for the short-lived/one-shot kinds.

### A7 — Validate all crypto operations; reject on any failure; UTF-8 only (8725 §3.3, §3.7)
**Verify:** [x] golang-jwt rejects the whole token on signature failure; JSON is
UTF-8 by Go default. No nested JWTs in use — confirm none are introduced without
validating inner+outer (§3.3).

### A8 — Don't trust received claims used for lookups; guard `kid`/`jku`/`x5u` (8725 §3.10)
**Requirement:** `kid` used for key lookup must be sanitized (no SQL/LDAP
injection); never follow attacker-supplied `jku`/`x5u` URLs (SSRF).
**Verify in code:**
- [x] `kid` is compared to fixed constants, not used in a DB/LDAP query — safe.
- [ ] Confirm neither authserver nor gateway honors `jku`/`x5u` headers. For the
      **OIDC RP** (`oidc_rp.go`), keys for *external* IdPs must come only from the
      IdP's discovery-document `jwks_uri` over TLS (8725 §3.8), never from a URL
      inside the token.

---

## B. Refresh tokens, rotation & theft detection (RFC 9700 §2.2.2, §4.14)

### B1 — Refresh tokens MUST be sender-constrained or rotated (9700 §2.2.2, §4.14.2)
**Requirement (MUST):** to detect refresh-token replay, the AS must use either
sender-constrained refresh tokens or **refresh token rotation**: issue a new
refresh token on every refresh, invalidate the previous one, and retain the
relationship. If a rotated (already-used) token is presented again, the AS cannot
tell attacker from client, so it MUST revoke the active token/chain. (§4.14.2)
**Verify in code:**
- [x] `token/refresh.go:RefreshTokens` implements rotation: marks the old row
      `rotated_at`, inserts a successor with `previous_token_hash`, and on reuse of
      an already-rotated token calls `RevokeAllTokens(...)` ("suspicious token reuse
      detected — all tokens revoked"). This matches §4.14.2's reuse-detection model.
- [x] Concurrency: `SELECT ... FOR UPDATE` serializes concurrent refreshes so at
      most one successor is created (prevents a benign race from looking like theft).
- [ ] Confirm the 30s `rotationGrace` window (client-retry tolerance) cannot be
      abused: within the grace window a replay still yields a token only from the
      *current* successor chain, and a replay *outside* the window revokes all.
      The grace window is an implementation nicety, not in the RFC; 30s is
      conservative — ensure it is not later widened in a way that meaningfully
      enlarges the replay window.

### B2 — Store refresh tokens hashed, not plaintext (9700 §4.14.1 confidentiality)
**Requirement:** refresh tokens must stay confidential in storage.
**Verify:** [x] `oauth_tokens.token_hash` stores `sha256(token)` via `tokenHash`;
the raw token is never persisted. `Introspect` and lookups all key on the hash.

### B3 — Bind refresh tokens to scope/resource (9700 §4.14.2)
**Requirement (MUST):** issued refresh tokens MUST be bound to the scope and
resource servers consented by the owner (prevents privilege escalation on refresh).
**Verify in code:**
- [x] On rotation, `issueAndStore` re-issues an access token with the user's
      *current* `is_admin`/`admin_role` looked up fresh from `users` — good (no
      stale privilege bleed-through).
- [ ] The INSERT in `issueAndStore` does **not** copy `scope` from the parent
      `oauth_tokens` row. If scoped refresh tokens are ever issued, propagate the
      parent's scope on rotation rather than dropping/widening it (§4.14.2).

### B4 — Revoke refresh tokens on security events (9700 §4.14.2)
**Requirement (MAY/SHOULD):** the AS may auto-revoke on password change or logout.
**Verify in code:**
- [x] Password change "revokes all tokens" (CLAUDE.md `/auth/password`); `/auth/logout`
      revokes all user tokens. Confirm both call `RevokeAllTokens`/`RevokeAllTokensTx`.
- [ ] Consider revoking on other high-risk events the threat pipeline already
      detects (spray lockout, geo-block, credential-stuffing) — §4.14.2 permits it.

### B5 — Refresh tokens SHOULD expire on inactivity (9700 §4.14.2)
**Verify:** [ ] Tokens have an absolute `expires_at` (`JWT_REFRESH_EXPIRY`, default
720h). The RFC additionally recommends *inactivity* expiry. Consider sliding/idle
expiry or capping chain age; currently only absolute TTL is enforced.

---

## C. Access tokens & privilege restriction (RFC 9700 §2.3)

### C1 — Least-privilege, audience-restricted access tokens (9700 §2.3)
**Requirement (SHOULD):** restrict token privileges to the minimum needed and
audience-restrict to a specific resource server; each RS MUST verify the token was
meant for it and refuse otherwise.
**Verify:** [x] `aud = mailserver-gateway` provides single-RS restriction today.
[ ] Before adding a second resource server (Drive/Chat/Meeting), introduce per-RS
`aud` values and per-RS validation rather than one shared audience (also satisfies
8725 §3.9 / A5). Keep access-token TTL short (`JWT_EXPIRY` default 1h) to bound
leakage impact.

### C2 — Impersonation token hygiene (8725 §2.8; 9700 §2.3)
**Verify:** [x] `IssueImpersonation` uses a 15-minute TTL and records the actor via
`AdminActorID` (RFC 8693 `act`-style). Confirm consumers can distinguish
impersonated tokens and that the short TTL is not extendable via refresh (no
refresh token should be minted for an impersonation session).

---

## D. OIDC IdP / RP via zitadel/oidc (RFC 9700 §2.1, §4.4, §4.5, §4.8)

These apply to the authserver's OP endpoints (`/authorize`, `/token`, `/jwks`,
`/.well-known/openid-configuration`) and RP flows (`/auth/oidc/login`, `/callback`).

### D1 — Exact-match redirect URI validation (9700 §2.1, §4.1.3)
**Requirement (MUST):** the AS MUST use exact string matching of redirect URIs
against pre-registered values (only localhost native-app ports may vary). No
wildcards, no prefix matching. Authorization responses MUST NOT go over `http`
except loopback native clients (§2.6).
**Verify:** [ ] Confirm the OP (`federation/oidc_op.go`) compares the incoming
`redirect_uri` to the registered client URI with exact string equality, and rejects
non-TLS redirect URIs.

### D2 — PKCE: AS MUST support S256 and enforce verifier; mitigate downgrade (9700 §2.1.1, §4.8.2)
**Requirement (MUST):** AS MUST support PKCE. If a `code_challenge` was sent, the
token endpoint MUST enforce `code_verifier`. AS MUST mitigate PKCE downgrade by
accepting a `code_verifier` at the token endpoint **only if** a `code_challenge`
was present in the authorization request. S256 is the only recommended method.
**Verify in code:**
- [ ] OP advertises `code_challenge_methods_supported` (`S256`) in discovery
      metadata.
- [ ] Token endpoint rejects an auth-code redemption that lacks a matching
      `code_verifier` when a challenge was registered, and rejects a `code_verifier`
      when no challenge was sent (downgrade guard).
- [ ] As an RP, send PKCE/`nonce` even for the confidential server-side flow
      (§2.1.1 note: this advice applies to web apps too, not just native apps).

### D3 — CSRF / mix-up / code-injection protection (9700 §2.1, §4.4, §4.5)
**Requirement (MUST):** clients MUST prevent CSRF on the redirect endpoint (PKCE,
OIDC `nonce`, or one-time `state` bound to the user agent). With multiple IdPs, a
mix-up defense is REQUIRED — process the `iss` authorization-response parameter
(RFC 9207) or the ID-Token `iss`. The `nonce`/PKCE challenge MUST be
transaction-specific and bound to the user agent that started the flow.
**Verify in code:**
- [x] CLAUDE.md states the OIDC callback does "state + nonce validation" — confirm
      `oidc_rp.go` (a) generates a single-use `state` bound to the user session,
      (b) validates `nonce` against the ID Token, and (c) validates the response
      `iss` (mix-up defense) since the deployment supports multiple external IdPs
      and SAML.
- [ ] Confirm `state`/`nonce` are high-entropy, single-use, and time-boxed.

### D4 — No implicit grant; no ROPC (9700 §2.1.2, §2.4)
**Requirement:** clients SHOULD NOT use the implicit grant (token in the
authorization response). The Resource Owner Password Credentials grant MUST NOT be
used.
**Verify:** [ ] Confirm the OP does not implement the implicit `response_type token`
or ROPC `grant_type=password`. Note: the authserver's own `/auth/login`
username+password endpoint is a *first-party* login (not the OAuth ROPC grant
delegated to third-party clients) — keep it first-party only; never expose it as an
OAuth grant for external clients (§2.4 rationale: don't train users to enter
credentials outside the AS, and ROPC can't do MFA/WebAuthn).

### D5 — ID Token / external-IdP token validation (8725 §3.8, §3.9; 9700)
**Verify:** [ ] As an RP, validate external ID Tokens for `iss`, `aud` (== our
client_id), `exp`, `nonce`, and signature against the IdP's `jwks_uri` (TLS, not a
token-supplied URL). zitadel/oidc handles most of this — confirm the RP wiring does
not disable any of these checks and uses certified defaults.

### D6 — Client authentication, prefer asymmetric (9700 §2.5)
**Requirement (SHOULD/RECOMMENDED):** the OP SHOULD enforce client authentication
where feasible; asymmetric (`private_key_jwt`, mTLS) is RECOMMENDED over shared
secrets, so the AS need not store sensitive symmetric keys.
**Verify:** [ ] Confirm confidential OIDC clients of our OP must authenticate at
`/token`; consider supporting `private_key_jwt` to avoid storing client secrets.

### D7 — Publish & consume AS metadata; metadata/CORS hygiene (9700 §2.6)
**Verify:** [ ] `/.well-known/openid-configuration` is published and accurate.
CORS MUST NOT be enabled on the authorization endpoint (§2.6); it MAY be on token /
jwks / metadata endpoints. Authorization responses MUST be over TLS only.

---

## E. Token introspection (RFC 7662) — `token/introspect.go`

RFC 7662 is not one of the two BCPs, but 8725/9700 constrain how the introspected
JWTs are validated. Key points to verify:
- [x] `Introspect` returns `{active:false}` (and nothing else) for unknown,
      revoked, or expired tokens — RFC 7662 §2.2 requires a non-revealing negative
      response. (Current code returns `Active:false` with no claims — good.)
- [x] Lookup excludes disabled users (`u.disabled = FALSE`) and revoked/expired
      tokens (`revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`).
- [ ] **Endpoint auth (RFC 7662 §2.1, MUST protect):** the introspection endpoint
      must require caller authentication (`INTERNAL_API_KEY` per CLAUDE.md). Verify
      `handlers/introspect_handler.go` rejects unauthenticated callers — an open
      introspection endpoint is a token-scanning oracle.
- [ ] If introspection ever returns `aud`/`scope`, callers must still enforce A5/C1
      (audience) before trusting the token for a given resource server.

---

## F. WebAuthn (RFC 9700 §2.4 rationale)

WebAuthn is not specified by these BCPs, but 9700 §2.4 cites it as the reason ROPC
is unfit (origin-bound cryptographic credentials can't flow through a password
grant). Relevant cross-checks for `authn/webauthn.go`:
- [ ] Confirm `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` are validated against the
      real deployment origin (prevents credential use from a wrong origin — the
      property §2.4 relies on).
- [ ] A successful WebAuthn assertion ultimately issues a first-party JWT (auth
      chain path 1). Ensure that JWT carries the same `aud`/`iss`/`Type=access`
      guarantees as A4/A5/A6 above — i.e. WebAuthn login is not a side door that
      mints tokens bypassing the standard claim set.

---

## Quick audit grep set

```bash
# Any JWT parse that might not pin alg/kid (review each hit):
grep -rn "ParseWithClaims\|jwt.Parse(" authserver mailserver/internal | grep -v _test

# Any use of the unsafe none type:
grep -rn "UnsafeAllowNoneSignatureType\|\"none\"" authserver mailserver

# Audience / issuer enforcement on the consuming side (gateway):
grep -rn "WithAudience\|WithIssuer\|mailserver-gateway" authserver mailserver/internal

# Refresh reuse / revoke-all theft response:
grep -rn "RevokeAllTokens\|previous_token_hash\|rotated_at\|suspicious token reuse" authserver

# Introspection endpoint must be authenticated:
grep -rn "INTERNAL_API_KEY\|Introspect" authserver/internal/handlers
```

## Status summary (from code read on 2026-06-10)

Confirmed-good (checked boxes above): alg/kid pinning in `Validate`; `iss`+`aud`
enforced on issue and verify; per-`Type` discrimination of token kinds; refresh
rotation with reuse-triggered revoke-all + `FOR UPDATE` serialization; hashed
refresh storage; non-revealing introspection for inactive tokens; disabled-user
exclusion; 15-min impersonation TTL with actor claim.

Open items to verify (unchecked boxes): JWT_SECRET entropy enforcement at startup;
that the *gateway-side* verifier enforces the same `aud`/`iss`/`Type=access`;
scope propagation on refresh rotation; inactivity-based refresh expiry; OP-side
PKCE S256 support + downgrade guard + exact redirect-URI matching; RP-side mix-up
(`iss`) defense; introspection endpoint authentication; no implicit/ROPC grant on
the OP; WebAuthn RP origin binding feeding the standard claim set.
