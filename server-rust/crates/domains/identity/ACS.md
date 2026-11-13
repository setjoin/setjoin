# SAML verified ACS (#546, owner-approved feature 2026-11-08, decision on #534)

New feature, not parity: frozen Go's ACS returned 404 and verified nothing. Go stays
frozen and keeps working; the Rust ACS is `POST /auth/saml/{idp}/acs`
(`bins/auth/src/saml.rs`), the verification is `src/saml_acs/` (pure, no I/O), the
registration side is `src/saml_flow.rs`. SP-initiated login and link; IdP-initiated SSO
only for a registration with `allow_idp_initiated` (V281, default false).

## Trust rule

A claim is read only from canonical bytes whose digest and signature were verified
against the registration's **pinned** certificate(s) (`idp_cert_enc`, PEM or bundle;
RSA at least 2048 bits, ECDSA P-256/P-384). `KeyInfo` in a message is ignored. The
canonical bytes of the element the signature references are re-parsed and are the only
thing the assertion checks see, so a rearranged document cannot make the consumed
element differ from the signed one.

- **Parser gate** (`xml.rs`): 1 MiB decoded cap, element nesting cap 32, 20,000 nodes,
  roxmltree with DTD refused (hence no entities), comments and processing instructions
  refused anywhere (CVE-2017-11427 class), every `ID`/`Id`/`id` unique across the message.
  uppsala (the parser bergshamra-c14n canonicalizes) must agree element for element with
  roxmltree (name, namespace, attributes) or the message is refused.
- **Signature** (`sig.rs`): root must be a samlp:Response with exactly one Assertion that is
  its child and no encrypted elements. A Signature may be a child of the Response or of that
  Assertion and must reference its own parent by `#ID` with exactly
  `[enveloped-signature, exclusive-c14n]`; SHA-256/384/512, RSA PKCS#1 v1.5 (ring, 2048 bit
  minimum) or ECDSA (ring, fixed r||s). SHA-1 digest or signature is refused. Every present
  signature must verify. Signed Response (Assertion inside) and signed Assertion are both
  accepted. XSW1-8 and append/nesting shapes are refused structurally; the digest check
  and consumed-bytes rule back that up.
- **SignedInfo** is read twice: structurally to choose the algorithm and key, then from the
  canonical SignedInfo bytes the signature verified; algorithms, Reference and digest value
  must agree and the *covered* values are the ones used.
- **Canonicalization** is bergshamra-c14n 0.11.1 exclusive C14N (no comments), the one
  `canonical_of` call; `tests/saml_acs_c14n.rs` pins it to the W3C Exclusive C14N
  Recommendation examples (2.1, 2.2) and the section 3 rules for the C14N 1.0 section 3.3
  document, character escaping, PrefixList and `#default`.
- **Assertion** (`assertion.rs`): Issuer = registration IdP entity ID; Audience = the SP's
  Issuer string or entity ID in every AudienceRestriction; a signed Response's Destination
  = the ACS URL (an unsigned wrapper that contradicts a signed Assertion is refused);
  exactly one bearer SubjectConfirmation whose Recipient = the ACS URL, no NotBefore;
  NotOnOrAfter on it and on Conditions, NotBefore, SessionNotOnOrAfter with a 120 second
  skew, validity at most 24 hours ahead; transient NameID refused (not a stable subject);
  NameID 1..1024 bytes without control characters; an unsigned Response wrapper's Status must still
  be Success (it can only refuse); InResponseTo equals the request this
  browser started (SP-initiated) or is absent (IdP-initiated).

## Flow (`bins/auth/src/saml.rs`)

1. Form post (`application/x-www-form-urlencoded`, 4 MiB cap, repeated fields refused),
   base64 decode (1 MiB XML).
2. Tracking: cookie `saml_{RelayState}` is the SP-signed JWT login set (Path = the ACS
   endpoint, 90 seconds, `SameSite=None; Secure` so the IdP's cross-site POST carries it). Its
   signed claims name the registration (`reg`), the `purpose` (`login` or `link`) and, for a link,
   the link `flow`; the ACS requires all of them (an older or foreign cookie is not accepted). Absent: IdP-initiated, refused unless the registration enables
   it, and never while a link flow is pending. A cookie present but a response without
   InResponseTo (or the reverse) is refused.
3. Verify, then `rust_identity_saml_consume`: one atomic call consumes the request ID and
   the assertion ID in `saml_assertion_replay` (V281) until NotOnOrAfter plus skew. The
   table is worker-only (FORCE RLS, policy for `setjoin_worker` alone: `setjoin_app` sees nothing and cannot insert);
   the reducer is SECURITY DEFINER, worker-owned. Frozen Go cannot touch it.
4. Identity: the link is (registration IdP entity ID, NameID) through the normalized
   `identity_auth_resolve('saml',...)` or the legacy `users.saml_name_id/saml_idp_entity_id`
   pair; never an address. Unlinked: the OIDC RP policy unchanged (registration
   `jit_enabled` or global JIT, else 401); before provisioning an address another user or alias
   already holds is refused 409 without linking. `rp::Assertion` is generalized with a `kind`;
   OIDC behaviour is untouched. A SAML login never rewrites an existing account's email.
5. Session (purpose `login`, or IdP-initiated): the same `settle`, mint reducers, fences and
   `rp_complete` as the OIDC RP. Success is `303` to an allow-listed target with the
   `access_token` cookie (no tokens in the body); a failure never mints.
   Link (purpose `link`): the ACS never mints and never provisions. The IdP's cross-site POST does
   not carry the SameSite=Strict `identity_link_flow` and `access_token` cookies, so the verified
   assertion is held (`rust_identity_saml_link_hold`: subject and groups bound to the link flow,
   2 minutes, one per flow) and the ACS answers `200` with a same-site refresh page to
   `GET /auth/saml/{idp}/link/complete?token=...`. That request carries the Strict cookies: the
   sealed flow, the exact live session and the one-use elevation are checked, the held assertion
   is released once for that flow only (`rust_identity_saml_link_take`) and
   `rust_identity_saml_link_finish` links it (receipt `saml-link-finish`). Audit:
   `saml.acs.link_held` at the ACS, `saml.acs.success` at completion.
6. RelayState/target allow-list (`relay_target`): one leading `/`, no `//`, `\\`, control
   characters, scheme or authority, at most 512 bytes, never under `/auth/saml/`; else `/`.
7. Audit (`admin_audit_log`, one `audit_write` statement): `saml.acs.success` (actor =
   user, notes login/link) and `saml.acs.<class>` for every failure (`malformed`,
   `oversize`, `unsigned`, `signature`, `structure`, `algorithm`, `issuer`, `audience`,
   `destination`, `recipient`, `subject`, `conditions`, `inresponseto`, `nameid`,
   `status`, `no_pinned_key`, `tracking`, `idp_initiated_refused`, `replay`,
   `replay_unavailable`, `link_unavailable`, `groups`, `refused`). Responses never name the class.

## IdP metadata

Inline XML or an https URL only; a literal private/loopback/link-local host is refused
before any transport is asked, the shared post-DNS resolver guards names, the document is
capped at 1 MiB for any `rp::Http`. The stored `idp_sso_url`/`sp_acs_url` still do not
override metadata; IdP signing keys come from the pinned certificate, never from metadata.

## IdP configuration

Register at the IdP: SP entity ID = the AuthnRequest Issuer `{root}/saml/metadata`, ACS =
`{root}/auth/saml/{percent-encoded IdP entity ID}/acs` (HTTP-POST), a stable NameID format
(persistent, email or unspecified), SHA-256 signatures, assertion or response signed.

## Tests and mutants

`tests/saml_acs.rs` (library, one test per check), `tests/saml_acs_c14n.rs`, auth
`tests/saml_acs.rs` (HTTP, database), auth `tests/saml_interop.rs` (SimpleSAMLphp in a
`gofree-samlacs-` container). `scripts/test-samlacs-mutants.py` restores each check's
absence (`SETJOIN_SAMLACS_MUTANT`, feature `oracle-mutants`) and requires its test to fail.
Divergence entries for the old ACS 404 goldens and the changed login goldens:
`tests/conformance/identity-saml/divergences.json` (`feature/`, owner-approved feature
2026-11-08 (#534), sha256-pinned).

## Known limits

Encrypted assertions and
SingleLogout are not supported. Refresh tokens are not delivered by the redirect.
