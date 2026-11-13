# WebAuthn (#335)

The seven concrete auth registrations and `/auth/webauthn/` front-door subtree
belong to this slice. Possession proof issuers, including their WebAuthn arms,
remain #336. Runtime threat/device interception remains #420; conditional-access
and DPoP completion remain #405; guest completion remains #406. Completed shapes
have no return-to-Go switch (owner decision 2026-11-04).

The frozen provider stores raw COSE bytes, attestation type and sign count.
Handles remain opaque bytes: persisted random handles and legacy decimal ASCII
must survive unchanged. The #330 facts receipt selects unmodified
`webauthn-rs-core`0.6 plus a Setjoin ceremony/profile implementation and
stored-key signature compatibility layer. This is broader than algorithm
adaptation: Setjoin owns the assertion ceremony and parts of registration.
Cryptographic primitives remain delegated to libraries, as detailed below.

## Profile and library boundaries

`src/webauthn.rs` implements Go's request/session profile: cookie and session
binding, expiry, credential allow-list and user-handle checks, clientData type,
challenge, origin/topOrigin, authenticator RP hash, presence/UV and backup flags,
and counter handling. It constructs the signed assertion message and invokes
the stored-key verifier; it does not use core's authentication ceremony API.
Registration likewise parses the envelope, extracts credential data and checks
the session, advertised algorithms and authenticator flags in Setjoin code.
The custom Serde CBOR visitor enforces Go's definite lengths, unique keys,
no tags and four-container depth limit; Serde supplies decoding, not that policy.

Core supplies the assertion authenticator-data framing parser and supported
COSE import/signature verification (ES256, ES384 and RS256 when importable).
For packed attestation with x5c, TPM, Android Key, FIDO U2F and Apple,
Setjoin calls core's `register_credential` and requires success. None attestation
retains Go's advertised-algorithm checks even when the key is unusable: core is
called when importable, but its result is deliberately non-authoritative there.
Packed self-attestation is implemented in Setjoin, including its algorithm match
and signed-message construction, using the same stored-key signature verifier.

The signature fallback delegates Ed25519 to ring, P-521 to p521, and RSA
PKCS#1 v1.5/PSS to rsa with library SHA-2 hashing. Setjoin chooses algorithms,
enforces Go's 1024-bit RSA minimum and permits Go's automatic PSS salt length;
it implements no signature primitive. SafetyNet is a Setjoin JWT/profile
verifier: x509-parser parses the leaf, webpki checks its hostname, and rsa
verifies RS256 after the same RSA minimum check. Setjoin checks JWT time claims,
nonce, CTS and timestamp, retaining Go's metadata-disabled trust/age behavior.
Ring also supplies cookie HKDF/AES-GCM and randomness; subtle supplies
constant-time comparisons where used.

These profile paths preserve Go's raw COSE storage, opaque/decimal handles,
UV-preferred policy, wire errors and recorded quirks. Core's authentication and
registration policies are not drop-in equivalents: the facts check found
missing EdDSA/PSS and unusable P-521 verification, while Go also accepts
SafetyNet, non-default PSS salts and none attestations that core rejects.
The frozen-Go HTTP/effect and stored-key corpora qualify this handwritten
profile; using core here does not imply that it validates the entire ceremony.

External seams: HTTP through the front door, committed credential/ceremony/grant/
audit/token effects, stored-key assertion verification, and cross-process JWT
verification. Goldens are recorded once from covered frozen Go; only generated
values whose relationships were checked may be normalized. The assigned
`gofree_e2e_idmfa2` database is disposable and isolated. Tests hold the shared
identity fixture advisory lock and remove only their own rows.

Owner-approved security fix 2026-11-05: frozen Go accepts counter regression
and repeated login assertions. Rust rechecks the live owned public key and
advancing counter under the canonical identity fence, then atomically records
the SHA-256 challenge claim and counter update. Counterless authenticators
remain supported but cannot replay the same challenge. Legacy signed cookies
have no expiry, so replay markers last until account deletion. Their dedicated
table has forced per-user RLS. Independent login/mint tails retain Go ordering.
Hash-pinned immutable captures, reviewed full security expectations and real
bug-restoring SQL mutants document and test this divergence.

Listing uses Go's live-only user predicate, descending creation order and struct
field order. Naming is Go's single UPDATE, including its successful no-op for a
foreign/missing/revoked target; it adds no audit, factor generation or notify.
The user executor waits for COMMIT and keeps only opaque actor-bound receipt
metadata. Unknown outcomes expose no success and require fresh authority.

## Verification-only RSA dependency

Core0.6.2 imports `crypto-glue`0.2.2 and `rsa`0.10.0-rc.19. The recorded
fallback also needs public PSS verification with automatic salt length (Go
accepts non-digest-sized salts; ring's profile cannot express this). The scoped
RustSec advisory exception in `server-rust/deny.toml` concerns
RUSTSEC-2023-0071, whose Marvin attack requires private-key operations.
This WebAuthn path uses only `RsaPublicKey::verify`, `COSEKey::verify_signature`
and core attestation verification. WebAuthn loads/generates no RSA private key
and performs no private-key signing/decryption. Core's crypto.rs imports only public RSA
key/signature/verifier types; crypto-glue's x509 modules verify certificate
signatures. Its private-key helpers are not called by these paths. First-party
JWT signing remains in the existing ring/SM2 infrastructure. Reassess this
exception before adding any request-driven RSA signing/decryption. #339 re-evaluated
startup key generation/decoding separately in [OIDC.md](OIDC.md); OP signatures
remain in ring and never use RustCrypto private-key operations.
Licences and source checks still cover all dependencies; MPL code is unmodified.

Login begin uses Go's address canonicalization and lazy conditional handle write.
Unknown/credential-less principals receive a per-process keyed stable decoy with
fresh challenges and encrypted uid0. Browser cookies are transport; no auth
identity field in the JSON request supplies authority. Login finish derives the
principal from the authenticated uid cookie, verifies session/handle/allow-list,
origin/RP/presence/UV and the stored key signature, then performs Go's independent
owned counter update before token completion. Go login challenge expiry is zero;
identical signed assertions can mint another family (recorded, not redesigned).
Tokens use existing signing custody, live scope/admission, refresh-anchor reducer
and independent sign-in/session tail. The anonymous failed-auth tail has its own
immutable `*-anonymous.json` companions. No worker transfer is introduced.

Registration begin runs the person/users/durable-revocation fence, full grant
peek, one-time target binding, handle initialization and ceremony replacement in
one reducer. A live prior binding returns status=bound without a second cookie;
a dead target is409. Proof issuers belong to#336; all effects consume sealed
Session identity and retain same-statement ownership.

Registration finish retains the person/users fence while Rust verifies the
attestation, then calls one reducer for ceremony/grant consumption, owned-key
upsert, one generation advance and checked audit. A dead proving factor rolls
back both consumes; an owned tuple mismatch preserves Go's committed ceremony
consumption and grant cleanup. A foreign credential-ID collision rolls everything
back. Revocation consumes the full target-bound tuple and commits revocation,
generation, proving-grant cleanup and audit together. Neither path changes
mailbox state or emits notifications. Error-body replay includes scoped statement
failures at the grant, key, generation and audit seams.

The low-level core verifies its supported attestation formats. Packed self
attestation uses the stored-key verifier for all recorded algorithms. SafetyNet
uses x509-parser, webpki's hostname checker and RustCrypto's public RSA verifier;
Go's absent trust-chain and stale-timestamp checks with metadata disabled are
preserved. None attestation preserves Go's acceptance of an advertised but
unusable COSE key. Authenticator extension bytes remain opaque as in Go. The
CBOR parsing uses an unmodified Serde decoder with a schema visitor enforcing
definite lengths, unique map keys, no tags and four nested containers. The
compound format's nested envelope exceeds Go's four-container CBOR limit and
is recorded as a refusal. Backup-eligible credentials register, but Go's normalized
loader drops backup flags and subsequently rejects their valid assertions.
These are parity caveats, not new authentication policy.

`Operation` selects a code-owned receipt category. Fresh session verification,
enabled identity, transition admission, credential fence and durable revocation
precede actor-bound lookup. Lookup returns only whether the transaction committed;
it cannot recover tokens/cookies or authorize a replay. The wire fault harness
arms on the specific receipt marker, skipping preceding scoped-read transactions,
and cuts before COMMIT or after PostgreSQL's commit response. Native replay uses
the bundled inventory unchanged with both Go upstreams absent. No worker changes.

Update 2026-11-05 (#504, owner-approved): android-safetynet registration is refused outright
(`Invalid attestation format`); the SafetyNet text above describes frozen Go only.
