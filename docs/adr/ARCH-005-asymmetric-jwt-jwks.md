# ADR: ARCH-005 — First-party tokens are asymmetrically signed (ES256) and verified through a published JWKS

**Status:** Accepted
**Date:** 2026-06-17
**Source:** `/improve-codebase-architecture` on `authserver` (the auth-protocol-conformance refactor) + the JWT BCP (RFC 8725) gaps in `docs/standards/auth-protocol-conformance.md` (lines 27, 31) + the cross-service token-signing map (authserver issues, mailserver gateway verifies).

## Context

`authserver` mints six first-party token types — access, refresh, MFA-pending, force-password-change, password-reset, impersonation — and they all funnel through **one signing seam**, `JWTProvider.sign()` (`authserver/internal/token/jwt.go`), and **one verification seam**, `JWTProvider.Validate()`. Today `sign()` produces **HS256** (HMAC-SHA256) under a single static `kid` (`authserver-hmac-1`), keyed by the `JWT_SECRET` shared secret. The optional SMx profile swaps in an SM2 signature; the standard profile is HS256.

The `mailserver` gateway is the resource server. It verifies the access token in `RequireAuth` → `JWTProvider.Validate()` (`mailserver/internal/auth/jwt.go`), and to do so it **holds the same `JWT_SECRET`** (`shared/config/base.go:36` is read by both services). So the verifier possesses the signing key. This is the finding:

- **Symmetric secret distribution.** Every resource server that verifies a token must hold the secret that *mints* tokens. A leak anywhere (gateway host, config store, a future second resource server) is a forgery key for the whole org. RFC 8725 / OAuth BCP call for the AS to publish asymmetric public keys so resource servers verify **without** minting power.
- **No first-party JWKS.** A `/keys` JWKS endpoint exists, but it belongs to the zitadel OIDC OP (RS256, `OIDCKeyManager`) and publishes only the OIDC OP key — first-party HS256 tokens are not represented anywhere a verifier can fetch.
- **No rotation.** The single static `kid` cannot be rotated without a flag-day secret swap coordinated across both services.
- **alg-confusion exposure (RFC 8725 [M], line 27).** As long as the standard path is HS256, the door to HS-vs-RS confusion stays open by construction; the only robust closure is to make the verifier key an asymmetric **public** key bound to one algorithm.

The two seams already dispatch on the `alg`/`kid` headers, so the change is localized — but it is **cross-service** (a token the gateway can't verify is a login outage) and **security-critical**, which is why it is recorded here.

## Decision

1. **First-party tokens are signed with ES256 (ECDSA P-256).** `JWTProvider.sign()` signs with the active EC private key under that key's `kid`. ES256 over RS256: compact signatures (~64 B vs ~256 B on every token), modern default, and alignment with the project's existing P-256 usage (guard-core ECDH; ES256 is already in the WebAuthn alg allowlist). RS256 stays available for the OIDC OP (an external-RP compatibility surface); first-party is ES256.
2. **Signing keys live in a DB-backed, encrypted keystore** — a `signing_keys` table (`kid`, `alg`, `public_jwk`, `private_key_enc`, `status` ∈ {`active`,`retiring`,`retired`}, `created_at`, `rotated_at`). The private key is encrypted at rest with the existing `cryptokey.DeriveDBEncryptionKey` seam. The keystore is generated on first boot if empty (mirroring the OIDC OP's load-or-generate, but in the DB so multiple authserver instances share one source of truth). Exactly one key is `active` (signs); `retiring` keys still verify during overlap; `retired` keys are dropped from the JWKS.
3. **A first-party JWKS endpoint publishes the active + retiring public keys**, keyed by `kid`. The RFC 8414 AS-metadata `jwks_uri` (`oauth_metadata.go`) advertises it. Resource servers verify offline against the published keys — no shared secret, no per-request call to authserver.
4. **The KeySet is the seam.** A `KeySet` module owns: generate/load, the active signer, the `kid`→public-key verification map, JWKS marshaling, and rotation. `sign()` asks the KeySet for the active signer; `Validate()` asks it for the verifier by `kid`. Each `kid` binds to exactly one `alg` (RFC 8725 [M]); a `kid` whose header `alg` disagrees with its registered `alg` is rejected — this is the structural closure of alg-confusion.
5. **The gateway verifies via a cached JWKS client**, not the shared secret. It fetches the authserver JWKS, caches it (refresh on unknown-`kid`, bounded TTL), and verifies ES256 by `kid`. `jku`/`x5u` are ignored; only the configured authserver JWKS URL is trusted (SSRF closure, RFC 8725 [S]).
6. **Migration is dual-verify, never a flag day.** The gateway is deployed first with **both** paths live: HS256 under the old secret **and** ES256 via JWKS. Then authserver flips issuance to ES256. Because the gateway only verifies **access** tokens (1 h TTL) — refresh tokens are validated authserver-side, which holds the key either way — all in-flight HS256 access tokens drain within one access-token lifetime. A later release removes HS256 acceptance from the gateway. At no point is there a window where a freshly-issued token can't be verified.

## Considered options

- **Keep HS256, just publish nothing / share the secret more carefully.** Rejected: the verifier still holds minting power; no rotation; the BCP gap stays open. Operational hygiene can't substitute for asymmetry.
- **RS256 for first-party (reuse the OIDC OP key).** Rejected as the default: larger signatures on every first-party token, and coupling first-party token lifetime/rotation to the OIDC OP key's lifecycle. RS256 is retained only where it already lives (the OIDC OP, an external surface).
- **Reuse the SM2 asymmetric path as "the" asymmetric signer.** Rejected outside the SMx profile: SM2/SM3 is a GM/China-compliance cipher with niche tooling, the gateway can't verify it today, and it would make the *standard* profile depend on GM crypto. SM2 stays the SMx-profile choice; ES256 is the standard-profile choice. (A deployment on the SMx profile publishes its SM2 public key through the same KeySet/JWKS machinery.)
- **Disk-PEM keystore (like the OIDC OP).** Rejected: rotation and multi-instance HA require out-of-band file sync. A DB keystore makes rotation a transaction and gives every instance one source of truth, with the private key encrypted at rest by an existing seam.
- **Gateway calls authserver to introspect every token (online verification).** Rejected: re-introduces a hard runtime dependency and per-request latency the offline-JWKS model exists to avoid. (Introspection — RFC 7662 — already exists for the opaque-token / debugging case; it is not the bearer hot path.)

## Consequences

- New `signing_keys` table + migration. **The keystore is an authserver table, so the migration is `authserver/sql/migrations/V009__signing_keys.sql`** (the authserver V000–V008 sequence; V009 was next free) — NOT a mailserver migration. (An earlier draft of this ADR mis-filed it as mailserver V091; that slot stays the next free mailserver migration.) New `KeySet` module in `authserver/internal/token/keyset.go`; `JWTProvider.sign()`/`Validate()` route through it; the ES256 branch sits alongside the kept SM2/HS256 branches (dual-verify), each `kid` bound to exactly one `alg`.
- New first-party JWKS endpoint; `oauth_metadata.go` `jwks_uri` points at it. The OIDC OP `/keys` endpoint is unchanged (its own RS256 key).
- `mailserver` gains a JWKS client (fetch + cache + ES256 verify by `kid`) and a config value for the authserver JWKS URL. During migration it keeps the HS256 path; `JWT_SECRET` stays required until HS256 acceptance is removed.
- **The shared `JWT_SECRET` is no longer a token-forgery key once HS256 acceptance is removed from the gateway.** It remains in use for the derived cookie/OIDC/DB-encryption keys (`cryptokey.Derive*`), so it is not deleted — but its blast radius shrinks from "mint any token" to "those derivations."
- Rotation becomes an operational primitive: insert a new `active` key, mark the old `retiring`; the JWKS serves both; after one max-access-token-lifetime the old key goes `retired`. A `mailctl` rotate command is a natural follow-up (out of scope here).
- Conformance: closes `auth-protocol-conformance.md` line 31 ([F] publish a JWKS with kid-keyed asymmetric keys + rotation) and hardens line 27 ([M] no alg confusion) structurally. Mark both on landing.
- **Revocation-propagation bound (offline-verify tradeoff).** The gateway's JWKS client *serves stale* on a fetch error (favoring availability — a brief authserver outage must not break all ES256 logins). The cost: if a signing key is compromised and removed from the published JWKS but authserver then becomes unreachable, the gateway keeps honoring that key until it can re-fetch. This is bounded in practice by the ~1 h access-token TTL (a stolen *token* expires regardless) and is the standard offline-JWKS availability/revocation tradeoff. A hard ceiling (drop the cache after N×TTL of continuous fetch failure → fail closed) is a deliberate availability-vs-freshness knob left as a follow-up; the default favors availability for an on-prem deployment where authserver blips are expected.
- Glossary: add **KeySet / signing keystore** to `CONTEXT.md` (the asymmetric-signing seam + the dual-verify migration invariant), so a future change can't silently reintroduce a shared-secret verifier.

## Migration sequencing (the load-bearing safety property)

1. **Keystore + JWKS + gateway dual-verify** ship first (gateway accepts HS256 *and* ES256; authserver still *issues* HS256). No behavior change yet — purely additive.
2. **Authserver flips issuance to ES256** (one config/default change). New tokens are ES256; the gateway verifies them via JWKS; old HS256 access tokens (≤1 h) still verify on the legacy path.
3. **After ≥ one access-token lifetime, remove HS256 acceptance** from the gateway (a later release). The shared secret is no longer a forgery key.

Reverting step 2 is a one-line issuance flip back to HS256 (the gateway still accepts it), so the dangerous step is cheaply reversible until step 3.
