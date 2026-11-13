# OIDC relying party (#340)

The RP switch (`OIDC_ENABLED` / `oidc.enabled`) is independent of the OP.
`rp::Registry` loads only deployment-owned `system_config` provider rows and
atomically replaces the complete healthy subset on every reload. A bad provider
never preserves its previous configuration or disables unrelated healthy rows.
Secrets open through the existing EK01 codec under the raw JWT master, never an
already-derived key. No request supplies a master key or provider configuration.

`openidconnect` 4.1.0 is unmodified, with default features disabled. Its client
owns authorization-code and S256 PKCE requests; its verifier owns ID-token
cryptography. The RP never invokes the crate's private-key signing or decryption
APIs. Its transitive RSA0.9 is public verification only, covered by the existing
Marvin applicability rationale; first-party signing remains in shared key custody.

`rp::Http` is an embedding boundary for external discovery/JWKS/token HTTPS I/O,
with no database or identity authority. Production `SafeHttp` has a ten-second
request bound, no ambient proxy or redirects, a post-DNS public-address resolver,
and a literal-IP check using the shared SSRF policy. The recorder/replay pins
only its synthetic HTTPS IdP and trusts its synthetic CA through this boundary;
requests cannot choose that transport. Discovery is eager and JWKS lazy, as Go.

The login adapter retains Go's 16-byte padded-base64 state/nonce, 32-byte PKCE
verifier, four ordered HttpOnly/SameSite=Lax cookies (Strict in Go; #548), 10-minute TTL and absent
cookie Path. Redirect query ordering and HTML bytes remain significant. No login
session or key is created at this stage. Detailed immutable observations and
recording inputs: [RP corpus](../../../tests/conformance/identity-rp/README.md).

Callback verification uses the unmodified openidconnect public-key verifier,
with Go issuer/audience/azp, exp/iat, lazy JWKS and at_hash semantics. The
provider caches the OAuth Basic/form authentication style after the first
accepted token response. State/verifier rejection precedes all IdP I/O; nonce
and verified-email checks follow signature verification, with Go cookie-clear
ordering. VerifiedClaims is sealed; it does not itself authorize user writes.

Account resolution accepts only a sealed nonce-bound, verified-email assertion.
The exact normalized source/link generations or frozen legacy issuer/subject
select the user; address/alias/UPN matches require explicit linking. The committed
profile/entitlement settlement precedes the separate fenced refresh anchor.
Independent auth-event/sign-in/session tails retain Go's ordering and pwd method.

`Registry::listen` owns one abort-on-drop task and direct LISTEN connection. It
subscribes before every authoritative reconciliation, filters Go's config keys,
and repairs the cache after reconnect. Explicit embeddings and process startup
require both named transfer attestations; ordinary library load starts no task.
The immutable worker seed/tick observation and real startup guard are in
`rp_oracle`; Go's only change is the named listener launch gate.

Explicit linking retains the fresh AAL2, exact live cookie/JTI/hash and one-use
V171 elevation. The encrypted root-path flow uses the existing CookieCipher;
request targets never choose the linked user. Verified callback identity,
strict mappings and normalized grants commit together; failure rolls back the
link, elevation consumption, events and NOTIFY. POST redirects have no HTML
representation, matching net/http. Go's normalized SSO success buffer replaced
prior Set-Cookie headers, dropping the four flow clears (fixed below, #530). Source/link fences cover normalized signing and its independent
pre-COMMIT login tail; local tails run after the separate anchor commit.

The process startup migration runs `reseal` even with RP disabled. It locks the Go
provider-row snapshot on DB_DSN through shared EK01 validation/sealing, then
calls one snapshot-checked apply reducer and waits for COMMIT. Any type/key
failure aborts all changes; main logs it and continues with healthy sealed
providers, as frozen Go main.go:693 does. Plaintext/corrupt providers stay
unavailable. AES/SM4, empty-secret and idempotence observations
are frozen in `secret-go.json`; library embeddings provision their own startup
boundary and load already-sealed rows. No active signing key changes at swap.

`catalog.py` qualifies exact auth registrations and the mixed gateway subtree
from the immutable Go wire inputs, retaining wire_method/wire_path. Its eight
suites replay body/header/cookie bytes and effect companions, with actual HTTP
status mutants. The bundled inventory is used unchanged in native replay;
recording alone selects frozen Go. CA/device prerequisites remain with the
existing #405/#420 owners before effects; SAML/shared identity-link list/delete
remain #341. The GET-link gateway alias keeps frozen POST-only 405.

Uncertain profile/mint/link COMMITs publish neither success nor a credential.
The actor-hashed opaque receipt can be inspected only under a fresh verified
IdP assertion for SSO, or a live, non-revoked verified session for linking.
Disabled/foreign authority is refused. Normalized mint keeps Go's independent
login/session tail before COMMIT; legacy mint runs that tail after its anchor
commit. `rp_faults` cuts the actual PG wire before/after every publishing command.

## Owner-approved security fixes (SECFIX8, #530, 2026-11-06)

Divergences from frozen Go, each pinned by `bins/auth/tests/rp_secfix8.rs` and a
restored-bug mutant (`scripts/test-secfix8-mutants.py`, env `SETJOIN_SECFIX8_MUTANT`):

- The first IdP group grant records provider provenance (`rust_identity_rp_map`
  inserts the membership and the provenance in two statements; Go's single CTE could
  not see its own insert), so a later IdP-driven removal attributes and revokes it.
- Every successful callback clears the four flow cookies (normalized or not).
- The discovered `token_endpoint` and `jwks_uri` must be https, or the provider is
  refused at load (Go forced https for the issuer only).
- IdP responses (discovery, JWKS, token) are capped at `MAX_IDP_BODY` (1 MiB): the
  production client streams with a cap and the transport wrapper enforces it for any
  `Http`.
- Only a verified `email` claim is an email (JIT and the per-login update);
  `preferred_username`/`upn` are never used.
- The ID-token algorithm is pinned to discovery's `id_token_signing_alg_values_supported`
  (RS256 when absent), asymmetric only: `HS*` and `none` are dropped, and a provider
  with nothing left is refused.
- An empty or missing nonce never matches (cookie or claim).

Goldens re-baselined under `tests/conformance/identity-rp/security/` with entries in
its `divergences.json`: groups-first (provenance) and normalized (flow clears), plus
their qualified companions.

## Follow-ups (#547, owner-approved security fixes 2026-11-05)

- Settlement never rewrites the account address to the IdP-asserted one
  (`rust_identity_rp_settle`); the SAML ACS already kept the current email.
- `feature.identity_model_v2` on: JIT creates user and authentication link together
  (`identity_auth_jit`) whatever the source's read mode, so settlement's normalized
  reconciliation finds its link; a serving source additionally keeps the mint fence. A blocked
  address collision is `409 explicit account linking is required`.
- Link completion is same-site: `Lax` flow cookies on `POST /auth/oidc/link`, a held assertion
  (`LinkFlow::hold`, `oidc_link_completions`, V282) and `GET /auth/oidc/link/complete`
  (`AuthorizedLink::take_held`). Owner of the pattern: [ACS.md](ACS.md).
- Login flow cookies are `SameSite=Lax` (#548, owner-approved functional fix 2026-11-09). Go set
  `oidc_state/nonce/provider/verifier` Strict, which a browser withholds on the IdP's cross-site
  redirect, so cross-site IdP login never worked. State, nonce and PKCE still bind the callback.
  The callback's four flow-cookie clears are Lax too, for consistency (browsers store a cookie of any
  SameSite value on a top-level navigation response). The session `access_token` stays Strict and is
  stored on that response. Test `rp_oidclax`; mutants `oidc-login-cookies-strict`, `oidc-clear-cookies-strict`
  (`SETJOIN_OIDCLAX_MUTANT`, `scripts/test-oidclax-mutants.py`).
