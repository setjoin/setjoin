# Shared certificate profile and trust (#526)

Foundation extracted from F06 without changing certificate/PEM admission or its
public compatibility re-exports. `certificate` uses RustCrypto DER and curve
decoders plus x509-parser; parsing grants no trust. `parse_chain` retains Go's
PEM scanner, all-block validation and canonical encoding. SMTP CMS signature and
chain verification use the unmodified audited OpenSSL crate separately.

`trust::TrustCache` caches only deployment-wide and recipient-domain anchors,
authorized by each stored DER fingerprint. It retains F06's generation fence,
uncached behavior while LISTEN is down and invalidation/reconnect semantics.
`pool_for` serves the scoped worker adapter; `pool_for_session` serves the inbound
worker connection. Neither accepts request-owned authority. Both expose identical
fingerprints and canonical authorized PEM to the verifier. The gateway supplies
one cache to SMTP and the process-local `smime_trust_changed` listener.

Verify the unchanged certificate/import oracle with gateway `mailsec_smime`, the
cache with `smime_trust_recorded` and `smime_trust_reconnect`, and enabled native
SMTP with `setjoin-smtp --test session enabled_smime_matches_frozen_go`, serial
with the assigned disposable DSNs and REQUIRE_DB=1. Family isolation remains in
force; F06 and SMTP depend on this foundation, never on one another.

F21 (#494) also composes the first-block metadata/key-byte helpers through F06
compatibility re-exports; these grant no trust. Identity self-service HTTP replays
cover their use. SMTP framing and preamble refusal remain in its inbound verifier.
