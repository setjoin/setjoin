# OIDC Provider (#339)

The OP is a separate RS256 token universe from Setjoin's first-party sessions.
Its issuer is startup-bound `https://HOSTNAME`; discovery ignores request Host
and identity fields. The two public metadata documents deliberately retain Go's
separate projections. The existing first-party PostgreSQL signing keys and
session formats are unchanged.

`OIDC_PROVIDER_ENABLED` / `oidc_provider.enabled` preserves Go's optional mount,
not a transfer rollback. Disabled OP routes return the Go mux response. The
private/public files default to `/opt/setjoin/oidc_key.pem` and `oidc_pub.pem`;
paths must be nonempty and distinct. Existing PKCS#8 RSA material is reused,
private permissions become0600, and SPKI public output becomes0644. Missing
private material is generated with the maintained RustCrypto RSA generator,
exclusive creation and2048 bits. ring performs RS256 for its supported key profile;
existing Go keys outside that profile use unmodified OpenSSL. RustCrypto never signs. The kid is base64url SHA-256(SPKI), identical to Go.
These files are distinct from first-party `signing_keys` in PostgreSQL.

HTTP transport and startup configuration live in `bins/auth`; the profile and
key codec live in `src/oidc`. No dependency on another family crate is added.
The public boundary is `bins/auth/tests/oidc_oracle.rs`, through the real Rust
front door; replay has both Go upstreams unset and checks zero Go hops. Synthetic
key material and immutable Go recordings live in `tests/conformance/identity-oidc`.
All 28 OP route/command suites are qualified and ON. Public gateway namespace
closures are local; RP#340 and SAML#341 retain their named ownership.

Discovery preserves the frozen GET-only wrapper: HEAD/POST retain the library's
uncorrected implicit/device advertisements (`oidc_op_discovery.go:86`), a known
functional Go defect. RFC8414 metadata stays public even when the OP is disabled,
uses its own field order/scopes/auth-method lists and has no-store. OP CORS allows
only the configured exact origins plus `https://HOSTNAME`, GET/HEAD/POST and the
six Go headers; credentials are never exposed. `OIDC_PROVIDER_ALLOWED_ORIGINS`
reads `oidc_provider.allowed_origins` and keeps the HTTPS/loopback config gate.

Authorization creates an unbound ten-minute request with one INSERT, matching
Go's complete transaction. A registered public client's metadata authorizes only
its redirect/scopes, never a user. The HTTP threat tail independently writes an
anonymous attempt;302 is a failure in frozen Go, even for a valid login handoff.
No OP session, mailbox state, device registration or audit is invented here.

Completion takes only a sealed first-party session, including Go's revocation
snapshot and DPoP handoff, and performs its one guarded UPDATE under that user's
transaction GUC. `done=false AND user_id IS NULL` prevents same/foreign takeover.
It retains exact auth_time/ACR/AMR and publishes no success after an unknown COMMIT.
The actor-bound `oidc-complete` receipt is infrastructure metadata, not a secret.

Callback reads a live completed request capability, rechecks the registered
client, encrypts its ID with Go's compact A256GCMKW/A256GCM profile and binds only
the SHA-256 code digest. The one UPDATE repeats the stored user and write-once
condition under user scope; `oidc-code` receipts withhold the code on uncertainty.
All AEAD, HKDF and randomness operations use ring. RS256 uses ring for the
normal profile and OpenSSL for valid pre-existing Go keys ring cannot load. Request IDs and codes
remain distinct; callbacks cannot issue from an uncompleted/expired request.

Code exchange consumes the exact live hash under its credential-derived user
scope through `rust_identity_oidc_consume` (SELECT FOR UPDATE + DELETE). Missing/
wrong verifier, wrong client/secret, redirect mismatch and replay retain Go's
order and error bytes; a failed PKCE attempt leaves the code consumed. User and
scopes come from this sealed stored capability, never form identity fields.

Fresh access INSERT and refresh-hash attachment are separate acknowledged user
transactions because Go uses two independent autocommits. A failed attachment
must leave the access row; it is not repaired into an atomic fresh grant. Tokens
publish only after every required write commits. RS256 JWTs retain Go's five-
minute access/ID profiles, approved-scope claims and at_hash/c_hash links; refresh
secrets remain hex32 with SHA-256 text hashes and a separate30-day lifetime.
The immutable corpus validates both signatures and all row/claim links before
normalizing randomness or clock fields. OP token responses retain Go's missing
cache-control headers; this security contract defect is recorded for follow-up.

Refresh rotation locks the hash-derived owned anchor and creates/attaches/revokes
in `rust_identity_oidc_rotate`; all effects share one acknowledged transaction.
Scope narrowing without offline_access follows Go's separate access-only mint
and leaves the predecessor active. Stored refresh anchors retain no auth context,
so the new ID token has the Go aal1/pwd fallback and absent auth_time/nonce.

Userinfo and introspection verify the configured RS256 key, issuer and expiry,
then consult the durable revocation record under the credential-derived user.
Revocation scopes its guarded UPDATE by verified credential user and authenticated
client; unknown/foreign tokens return idempotent success. Logout validates the
ID hint (expired hints remain usable), client/azp and registered logout redirect
policy, then revokes the owned client anchors. Go's caller-client introspection
projection is preserved. Every response/effect is compared to the frozen corpus.

Operation lookup re-verifies a current first-party access session, enabled user,
credential fence and durable revocations before taking the original user/operation
lock and reading the actor-bound receipt. Anonymous authorization lookup re-reads
the enabled registered client and uses its protocol scope/lock. Receipt observations
return only committed/absent; they never reconstruct or reissue a lost secret.

Marvin advisory re-evaluation: rsa0.10rc19 performs startup key generation,
PKCS#8/SPKI encoding/decoding and key validation only. No attacker-selected
request invokes an RSA private-key operation in that crate. OP signatures use ring, with OpenSSL compatibility for existing Go key profiles;
no RSA decryption exists. This does not expose the chosen-input timing
oracle of RUSTSEC-2023-0071. The existing advisory rationale is updated to cover
this additional consumer; request-driven RSA signing/decryption needs a new review.
New tokens use RS256 and new codes use ring AEAD. Go's unauthenticated CFB token
fallback is gone (see Security fixes below); the `aes`/`cfb-mode` crates are
optional and compiled only into `oracle-mutants` test builds.

Go accepted valid existing RSA 1024 and exponent 3 keys and signed them through
OpenSSL. Since #523 startup refuses them (see Security fixes); the OpenSSL
`Legacy` signer remains only for keys ring's parser rejects for other reasons.
New keys are RSA2048/e65537 and use ring. `legacy-key-goldens.json` remains as the
fixture of the refused profiles. No RustCrypto signing/decryption is enabled.

## Security fixes (#523, owner-approved 2026-11-05)

Divergences from frozen Go, each with a secure-behaviour test in
`bins/auth/tests/oidc_secfix7.rs` (or `oidc_config.rs`), a bug-restoring mutant
(`mutants.rs`, feature `oracle-mutants`, env `SETJOIN_SECFIX7_MUTANT`, runner
`scripts/test-secfix7-mutants.py`) and re-baselined goldens (`identity-oidc/divergences.json`
pins each Go capture by sha256 and names the authored `security/` expectation):

- Opaque/JWT access tokens are bound to the stored row: subject must equal the
  row's `user_id`, the row must be unrevoked and `expires_at>now()`. CFB tokens are rejected.
- `/oauth/introspect` answers only the client the token was issued to and reports
  that client's id; any other caller gets `{"active":false}`.
- `/oauth/token` responses (errors too) carry `Cache-Control: no-store`, `Pragma: no-cache`.
- Startup fails closed (operator rotate message, nothing written) for RSA keys under
  2048 bits or e<65537.
- `/auth/oidc/op/complete`: GET renders a consent page (no state change, `no-store`,
  frame-denied) holding an HMAC token (HKDF-separated from the code key; bound to the
  user, session family/jti and request id); the bind is a POST with the token plus the
  Origin/Referer check. The gateway inventory keeps the single Go `GET` registration;
  the POST is served by the same handler. `/authorize/callback` requires a session whose
  user is the request's bound user, otherwise 401/400 and no code is minted.
- Refresh tokens form families (V279 `refresh_family`, `refresh_family_expires_at`):
  reuse of a rotated/revoked token revokes the whole family
  (`rust_identity_oidc_reuse`) and rotation can never extend past a 90-day absolute
  lifetime from the original grant (each token still gets 30 days, capped).
  Pre-V279 rows are a family of one capped at `created_at+90 days`.

## oidc_tokens credential reducers (#525, owner-approved 2026-11-05)

Every credential-keyed read of `oidc_tokens` is a worker-owned DEFINER reducer in
`rust_identity_oidc_lookup.sql` that derives the user from the presented credential, after which the
caller repeats that user as its transaction scope: `rust_identity_oidc_refresh_anchor(hash)` (refresh
grant), `rust_identity_oidc_token_owner(id)` (UserInfo, introspection) and
`rust_identity_oidc_revoke_target(hash,id,client)` (revocation). The revocation pre-lookup of an active
refresh token by hash only found the row the revoke statement matches by that hash anyway, so it is gone.
Tests: `bins/auth/tests/oidc_secfix10.rs` (proves the reducer call: with EXECUTE revoked from the app role
the flow fails), `mailserver/sql/tests/rust_identity_oidc_lookup.pg`. Mutants
(`SETJOIN_SECFIX10_MUTANT`: `oidc-direct-refresh-anchor|token-owner|revoke-target`):
`scripts/test-secfix10-mutants.py`. Existing OIDC goldens are unchanged.

FORCE RLS on the table is STAGED, not live: `mailserver/sql/staged/oidc_tokens_force_rls.sql` (+ `.pg`).
The default install runs frozen `authserverd` as `setjoin_app` (NOBYPASSRLS, not the owner; fresh installs are
already flipped), and its OP token store uses the request pool without ever setting `app.current_user_id`, so
the policy would break Go's token INSERT, refresh/revoke/introspect lookups and token GC. Follow-up for the
Go-deletion ticket (DELETE): apply it as a migration once authserverd is gone (see the staged header).
