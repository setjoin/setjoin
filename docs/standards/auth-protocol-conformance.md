# Auth protocol conformance checklist

Conformance targets for `authserver`, distilled from the governing RFCs/specs (2026-06). Each line is an actionable requirement; the architecture review / refactor (`/improve-codebase-architecture` on authserver) tracks the gaps against this. **Sources:** OAuth 2.0 (RFC 6749), OAuth 2.1 draft, OAuth 2.0 Security BCP (RFC 9700), PKCE (RFC 7636), token introspection (RFC 7662), token revocation (RFC 7009), token exchange (RFC 8693), AS metadata (RFC 8414), dynamic client registration (RFC 7591), PAR (RFC 9126), DPoP (RFC 9449), mix-up `iss` (RFC 9207), JWT (RFC 7519) + JWT BCP (RFC 8725) + JWK (RFC 7517), OpenID Connect Core & Discovery 1.0, W3C WebAuthn L2, SCIM (RFC 7643/7644).

> Legend: **[M]** MUST · **[S]** SHOULD · **[F]** feature (standard endpoint/flow we may not yet have).

## OAuth 2.0/2.1 authorization server

- **[M]** Support PKCE; require `code_verifier` validation when `code_challenge` was sent; reject `code_verifier` when no challenge was present (downgrade defense). Public clients MUST use PKCE; prefer `S256`.
- **[M]** Exact-string redirect-URI matching against pre-registered URIs (except loopback ports). No pattern matching.
- **[M]** Single-use authorization codes; on a second redemption, revoke all tokens issued from that code (injection/replay defense).
- **[M]** No open redirector; no access tokens in the authorization response (code grant only).
- **[M]** (2.1) Remove the Implicit grant and the Resource-Owner-Password grant.
- **[M]** HTTPS for all protocol URLs except loopback redirects. Reject HTTP 307 for credential-bearing redirects (use 303).
- **[S]** Refresh-token rotation **with reuse detection** for public clients, or sender-constraining (DPoP/mTLS). Bind refresh tokens to scope + resource. Revoke on password change / logout.
- **[S]** Sender-constrained access tokens (DPoP RFC 9449 or mTLS) to neutralize stolen bearer tokens.
- **[S]** Audience-restrict access tokens to a resource (`aud` / `resource` param).
- **[S]** Mix-up defense: return the `iss` parameter (RFC 9207).
- **[F]** ✅ AS metadata document (RFC 8414, `GET /.well-known/oauth-authorization-server`) — issuer/authorize/token/introspection/revocation/jwks endpoints, `grant_types_supported` (no implicit/ROPC), `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported=[S256]`, `scopes_supported`, `acr_values_supported`, `claims_supported`. Issuer matches the OIDC OP `StaticIssuer`. `internal/handlers/oauth_metadata.go`.
- **[F]** ✅ Token introspection (RFC 7662) and revocation (RFC 7009) endpoints — both accept `INTERNAL_API_KEY` OR standard OAuth client auth (`client_id`+`client_secret` via Basic/POST, verified against `oidc_clients` with constant-failure timing). Introspection returns the full §2.2 field set with `token_type:"Bearer"` and `{active:false}` (never an oracle) for unknown/expired tokens; revocation (`POST /auth/revoke`, distinct from the OIDC OP `/revoke`) is idempotent (always 200, `token_type_hint` ignored). `internal/handlers/{introspect,revoke}_handler.go`, `internal/token/{introspect.go,refresh.go RevokeByToken}`.
- **[F]** Asymmetric client auth (`private_key_jwt` / mTLS) alongside `client_secret_*`.
- **[F]** (consider) PAR (RFC 9126), token exchange (RFC 8693), dynamic client registration (RFC 7591).

## JWT issuance & validation (RFC 8725)

- **[M]** ✅ Validate `alg` against an explicit allowlist; never accept `none`; verify the `alg` matches the key. Bind each key to exactly one algorithm. *(ARCH-005: `WithValidMethods` caps both verifiers to the known algs; every `kid` binds to exactly one alg in the keystore, enforced header-alg == registered-alg.)*
- **[M]** ✅ No alg confusion (HS vs RS): a verifier configured for RS/ES MUST NOT accept an HS token signed with the public key as the secret. *(ARCH-005: the ES256 branch returns an `*ecdsa.PublicKey` only after the method is asserted `*SigningMethodECDSA`; the HS256 branch returns the symmetric secret — a public key is never reachable as an HMAC key. `shared/jwtutil.ParseES256` + `TestKeySet_AlgConfusionRejected` pin it.)*
- **[M]** Validate `iss`, `aud`, `exp` (+ `nbf`/`iat`); reject untrusted issuer/audience; require `jti` for replay-sensitive tokens.
- **[S]** Explicit `typ` header (e.g. `at+jwt` for access tokens) to prevent cross-type confusion; mutually-exclusive validation per token type.
- **[S]** ✅ Sanitize/allowlist `kid`; allowlist `jku`/`x5u` hosts (SSRF). Symmetric keys: high entropy, never a password. *(ARCH-005: `kid` is a map lookup only; `jku`/`x5u`/embedded-jwk header fields are never read — keys come solely from the keystore / the configured JWKS URL.)*
- **[F]** ✅ Publish a JWKS (`jwks_uri`) with `kid`-keyed asymmetric signing keys + rotation, so resource servers verify without the shared secret. *(ARCH-005: first-party `/.well-known/jwks.json` (ES256, kid-keyed, active+retiring) advertised as the RFC 8414 `jwks_uri`; the mailserver gateway verifies offline via a cached JWKS client, no shared secret. DB keystore supports rotation; live hot-reload + a `mailctl rotate` command are noted operational follow-ups. `authserver/internal/token/keyset.go`, `handlers/jwks.go`, `mailserver/internal/auth/jwks.go`.)*

## OpenID Connect — OP / IdP mode

- **[M]** Authorization endpoint supports GET+POST, requires `openid` scope, validates all params.
- **[M]** ID Token is JWS-signed; required claims `iss`, `sub` (≤255 ASCII), `aud`=client_id, `exp`, `iat`; include `nonce` when sent; `auth_time` when `max_age`/essential; `at_hash`/`c_hash` for implicit/hybrid.
- **[M]** Honor `prompt=login` (force re-auth) and `prompt=none` (silent only, else `login_required`).
- **[F]** ✅ UserInfo endpoint; Discovery metadata (`/.well-known/openid-configuration`) listing authorization/token/userinfo endpoints, issuer, `jwks_uri`, supported scopes/claims/response_types/`code_challenge_methods`. `federation.OPDiscoveryWrapper` guarantees `scopes_supported`, `claims_supported`, `code_challenge_methods_supported=[S256]`, and `acr_values_supported` are present (injects any the OP omits, without clobbering).
- **[S]** Consent screen. ✅ `acr`/`amr` reflect the actual MFA/AAL performed: access tokens carry RFC 8176 `amr` (`pwd`/`otp`/`hwk`/`swk`+`user`/`mfa`) and NIST-AAL `acr` (`aal1`/`aal2`) derived from the session's factors (`shared/jwtutil.DeriveAuthContext`); the OIDC OP id_token reports them via `GetACR`/`GetAMR` and discovery advertises `acr_values_supported`.

## OpenID Connect / SAML — RP / SP mode (consuming an external IdP)

- **[M]** Validate the ID Token / SAML assertion: signature (issuer's published keys), `iss` exact match, `aud`=our client_id, `exp`/NotOnOrAfter + NotBefore, `nonce` match (OIDC), `state` bound to the user agent.
- **[M]** Replay protection: one-time `nonce`/assertion id (e.g. `used_saml_assertions`), audience restriction, recipient/destination check (SAML).
- **[M]** `state` CSRF binding; mix-up defense across multiple IdPs (per-IdP redirect or `iss`).
- **[M]** Identity matching resolves a person by ANY of their addresses (primary ∪ aliases ∪ UPN), not just primary email — see [ADR-004](../adr/ARCH-004-directory-org-scope.md); JIT-provision only when no address matches.
- **[S]** `azp` check when present; clock-skew bound; SAML signature-wrapping defenses (validate the signed element is the one consumed).

## WebAuthn (RP server) — L2

- **[M]** Registration: challenge match · origin match · RP-ID-hash = SHA-256(rpId) · `type="webauthn.create"` · UP flag set · UV flag if required · attestation-statement parse/verify · **alg allowlist** (ES256/RS256…) · store credential id + public key + sign count.
- **[M]** Authentication: challenge match · origin match · RP-ID-hash · `type="webauthn.get"` · UP flag · UV if required · **signature verify** with stored key · **sign-counter must not decrease** (clone detection) · credential id ↔ active user.
- **[M]** Challenges are CSPRNG-random, single-use, and expire (bounded window).
- **[F]** Discoverable credentials / resident keys (usernameless); `excludeCredentials` on register; multiple authenticators per user.

## SCIM provisioning (RFC 7643/7644) — if/where exposed

- **[F]** `/scim/v2/Users` + `/Groups` CRUD, filtering, PATCH, bulk; `meta`/`etag`; `externalId`; deprovisioning via `active=false`. (Inbound provisioning from the IdP complements the SP-mode JIT path.)

## TOTP / push / backup codes

- **[M]** TOTP (RFC 6238): 30s step, ±1 window skew, constant-time compare, per-user secret stored encrypted; rate-limit attempts.
- **[M]** Backup codes: single-use, hashed at rest, count-limited.
- **[M]** Push MFA: bound challenge with expiry + replay protection; number-matching to resist push-fatigue.
- **[S]** Step-up / AAL: ✅ a session records which factors were satisfied (threaded through `issueTokensWithFactors`); conditional access can require AAL2 via the `require_acr` policy action, enforced at login (step-up) and downstream (`PolicyEngine.EvaluateTokenACR` rejects an `aal1` token against an `aal2` requirement); reflected in `acr`/`amr`.
