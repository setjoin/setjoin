# SAML SP (#341)

`saml::Registry` is deployment configuration, with no authenticated-user
authority. It reads enabled registrations through DB_DSN, binds the trusted
startup encryption key to pgcrypto, validates the complete Go row shape, and
publishes the healthy subset atomically. Query, decryption or row-type failure
clears the whole snapshot. Invalid per-registration metadata or group mappings
excludes that registration. No HTTP input selects configuration or keys.

The SP certificate/private key are startup-bound existing files. Certificate
and RSA private key must match. They are neither generated nor rotated by the
server. AuthnRequest and tracking-JWT private operations use `ring` RSA-SHA256
for its supported key profile. Existing Go RSA keys outside that profile retain
the OP port's audited OpenSSL PKCS#1/SHA-256 fallback (Go's 1024-bit minimum);
no replacement key or private cryptographic primitive is implemented here.
Tracking claims retain Go's 90-second lifetime, root-URL issuer/audience,
request-ID and original-URI binding. Public login does not mint a first-party
credential or write user data; only a verified ACS response does (ACS.md).

Metadata may be inline XML or fetched from an HTTPS URL through the shared
`rp::Http` external-I/O seam. Production transport retains the shared literal
and post-DNS SSRF guard, ten-second bound, and disabled proxy/redirect behavior.
Metadata selects the first Redirect endpoint, otherwise the first POST endpoint.
The stored `idp_sso_url` and `sp_acs_url` are scanned but do not override the
middleware, as in Go.

Frozen Go's middleware paths do not match its registrations, so its ACS answered
every POST with a 404 and never verified anything; its metadata route is still 404 here.
The ACS is the one deliberate departure: since 2026-11-08 (#546, owner decision on
#534) Rust implements a verified ACS, specified in [ACS.md](ACS.md). It is a new
feature, not parity: nothing from the old 404 goldens is protection of any kind, and
those goldens are pinned as divergences.

New XML dependencies are pinned to unmodified `bergshamra-dsig`/keys 0.11.1
and `kryptering` 0.7.0, with default features disabled. The complete dependency
graph passes the repository's cargo-deny policy. The in-house reachable-profile review below accompanies the signed POST seam.

In-house profile/source review (2026-11-06): the outgoing POST template has one
new random `ID`, one same-document `Reference`, exclusive C14N without comments,
enveloped-signature transform and SHA-256 digest. `bergshamra-dsig::sign` checks
ID uniqueness and dispatches through its external `Signer` interface, including
an algorithm/URI cross-check (`src/sign.rs:273`). Our adapter reports only
RSA-PKCS1v1.5/SHA-256 and calls the startup-bound signer; the normal profile uses ring and existing
out-of-profile Go keys use the audited OpenSSL fallback. The KeysManager is empty and no RustCrypto
private-key loader/sign/decrypt API is called. The public certificate is copied
from the already matched startup pair. All variable XML text/attributes are
escaped before the library parses our generated document. Metadata parsing is
separate from signing; inbound assertion XML is never passed to either parser.
This review covers the outgoing AuthnRequest profile only. Inbound assertion XML never
reaches the signing path; it has its own parser gate, canonicalization and pinned-key
verification (ACS.md). Source:
[bergshamra 0.11.1](https://docs.rs/crate/bergshamra-dsig/0.11.1/source/src/sign.rs).

The immutable Go POST capture is checked with a trusted-key-only strict DSig
verifier, one locally verified root reference, and full normalized XML/HTML/CSP
comparison. Redirect captures independently check the original signed query and
the tracked-request JWT with the SP public key before masking random values.

Public adapter parity: percent-decoded IdP path segments select the registration;
Go's method table runs before registration lookup, retaining 405/Allow for the
GET link alias and wrong-method requests. A valid existing RS256 SP `token`
cookie can redirect login to `/`; issuer, scalar audience, session marker,
registered claim types/times and the SP signature are checked. It never supplies
a user principal. Malformed signatures, foreign audiences and ordinary
first-party cookies instead initiate SSO. Metadata keeps the frozen
404. The ACS verifies (ACS.md); login now advertises it: the AuthnRequest's
AssertionConsumerServiceURL is `{root}/auth/saml/{idp}/acs`, the tracking cookie's Path is
that endpoint, and the NameIDPolicy no longer demands a transient NameID (which cannot key a
link). Issuer and the other request fields are unchanged.

Shared link management: `identity_links::list` retains the verified session's
`user_id` predicate, Go's authenticate-purpose filter/order/limit and timestamp
encoding. It uses the explicit worker credential, as Go does, without accepting
an HTTP-owned user. A scan failure returns 503; late row-iteration failure keeps
Go's existing read semantics. Responses retain no-store and Go's map ordering.

SAML link begin reuses the RP's sealed `LinkFlow` with a separate `saml` kind
and registration-derived provider key. Fresh AAL2, the exact access cookie,
JTI/hash and the worker-owned live-session elevation remain required. The
existing elevation reducer and opaque receipt commit together; only a positive
COMMIT acknowledgement allows publication of the encrypted root-path flow and
signed AuthnRequest. An unknown outcome returns 503/operation ID with neither
cookie nor redirect. The OIDC callback still rejects a SAML-kind flow; the ACS completes it with
`open_saml` and `rust_identity_saml_link_finish`.

Shared unlink requires fresh AAL2 and CSRF admission before decoding the target
and the first JSON value (16KiB, Go field folding and trailing-value behavior).
`identity_links::unlink` uses the verified session owner and explicit worker
credential; the canonical reducer owns all effects. Its private receipt commits
with the detach/revocations/audit/notifications. Only acknowledged COMMIT returns
the unchanged PostgreSQL JSON body; UNKNOWN returns 503 and an operation ID.

Commit-cut conformance tests place a real PostgreSQL-wire proxy immediately
before/after COMMIT for both SAML elevation and shared unlink. Both cuts return
503 without cookies/redirect/success; actor-scoped receipt inspection requires
a freshly verified live session. Foreign, revoked and disabled authority cannot
inspect an outcome. Unlink requires a newly established session after its own
revocation boundary. Notifications and reducer effects share the receipt fence.

`saml_sp` is a retained Rust task, admitted only by matching comma-delimited
`RUST_WORKERS_ON` and `GO_WORKERS_OFF` names. Startup rejects a missing Go
retirement before database/config loading; library embeddings enforce the same
rule. The task subscribes through DB_DIRECT_DSN before authoritative reload,
handles `saml_sp`/`auth_methods`, reconciles missed notifications after reconnect,
and aborts on handle drop. Other Go process-local caches continue running.
The frozen-Go seed/tick corpus verifies removal of a disabled registration;
private-literal and private-DNS metadata tests observe zero TCP connections and
verify healthy-sibling publication after the failing entry.

SAML configuration JSON retains Go field folding (including Unicode folds into
ASCII), exact known-field types, unknown-field skipping and duplicate-null
no-op behavior. It uses serde visitors, never a separate JSON tokenizer. This
applies to the config-change `key` and group-mapping structs. The recorded
worker JSON case suppresses only its fixture update's notification trigger,
then sends the mixed-case key explicitly, so a table trigger cannot hide an
ignored notification. Mixed-case group fields remain valid after reload.

Legacy-key oracle: a synthetic existing RSA1024 SP fixture is loaded by frozen
Go, with independently ring-verified Redirect/tracking signatures and an
existing signed SP session. Native replay retains that key and session through
the swap. The default RSA2048 Redirect/POST oracle continues to verify ring
signatures and strict XML-DSig. Test certificates/private keys are synthetic,
untrusted fixtures; no runtime code generates or rewrites SP credentials.

A verified JWT preserves Go's raw `uid`; it does not prove the integer is
positive. Shared unlink checks that typed-command precondition without a panic.
A nonpositive owner gets the recorded Go BZ234 conflict and no command/receipt
or owned/foreign effects. The HTTP oracle signs that credential with the actual
fixture first-party key and compares frozen Go's response and full effects.

DPoP-bound management admission retains the existing common forwarding owner
#405. Ordinary unbound first-party access sessions are native here; the SAML
public flow never acquires a user principal from a request field or assertion.
