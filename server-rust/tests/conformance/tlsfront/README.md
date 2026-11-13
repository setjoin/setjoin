# TLS front door oracle (#413)

`build-peer.py` builds `test-results/gofree-tlsfront/gofree-tlsfront-peer` in the CI image,
with the shared module cache. It lifts the complete TLS config expression unchanged from
frozen `mailserverd/main.go` into a recording overlay (no tracked Go edits). It records the
source/template hashes and registers its `gofree-tlsfront-*` container before launch.

`setjoin-tls --test go_interchange` normally starts Rust servers only. The peer runs only in the CI image (including the shared module cache), as a Go TLS
client / `crypto/tls.Config.DecryptTicket` format consumer; it does not run a Go server in
replay. The checked-in JSON files are immutable Go recordings. Their keys, PSKs, certificates
and private keys are public **test fixtures**, never deployment credentials.

Session replay preserves the recorded PSK, certificate, cipher, negotiated metadata and expected
result. The harness retargets only the server/client creation timestamp, TLS 1.3 use-by timestamp
and the ticket's authenticated envelope (under the public fixture key), avoiding aging fixtures.
Rotation cases keep exactly one prior key; bad MACs, expired tickets and older keys cause a full
handshake. The wrong-key mutant must differ from the recorded resumed handshake.

Build/replay (workspace root, host Cargo; use assigned target/env and REQUIRE_DB=1):

```sh
python3 server-rust/tests/conformance/tlsfront/build-peer.py
cargo test --manifest-path server-rust/Cargo.toml --locked -p setjoin-tls -- --test-threads=1
```

For a **new** recording only, select its test with `GOFREE_RECORD_TLSFRONT=1`. Existing files
are never overwritten. TLS 1.2/1.3 archived cases are `go_issued_tls12_ticket_resumes_on_rust`
/ `go_issued_tls13_ticket_resumes_on_rust`; format cases are `rust_issued_tls12_ticket_is_go_compatible`
/ `rust_issued_ticket_is_go_compatible_encrypted_session_state`; rotation is
`ticket_rotation_and_rejections_match_recorded_go`.

The four database mutator mutants do not apply to the TLS transport (no rows, audit, notify
or state bumps). The actual ticket-key consumer mutant proves resumption discrimination.

`gateway --test tls_recorded` replays 16 Go HTTP/TLS cases with AES-GCM hardware
enabled and disabled (32 observations): h2, HTTP/1.1,
h2c, managed/autocert/static ordering, SNI normalization, wildcard boundaries and
expired/corrupt/cold caches. It compares status, protocol, cipher, served chain,
content type, HSTS and ticket count. Recording requires `PEBBLE_BIN` because the
real Go manager registers with the local CA even though serving never issues.
HTTPS adds Go’s default HSTS unless the application supplies its own value.

`setjoin-tls --test policy` adds 22 frozen-Go policy observations (11 clients ×
AES-GCM hardware available/unavailable), including TLS 1.2 ChaCha/P-384 rejection,
server cipher preference, cold-SNI `unrecognized_name`, and TLS 1.3 same-hash
cross-suite resumption. `policy.json` is immutable; recording-only
`GOFREE_RECORD_TLS_POLICY=1` also starts Pebble for cold managed configuration.
`route53-endpoints.json` was recorded from the frozen AWS SDK resolver; it pins
global/partition endpoint and signing-region selection outside custom test endpoints.
The two HTTP corpora are `http-negotiation.json` and `http-negotiation-no-aes.json`.

DNS worker replay lives in `crates/acme/tests/dns_recorded.rs`: nine single-name
and three multi-domain Go ticks. Multi-domain recordings keep Pebble's randomized
authorization order; replay canonicalizes independent names within a phase only,
checking every request/body, phase boundary, retry and per-name API sequence.
Cloudflare/Route53 prepare all names before cleanup; RFC2136 is sequential.
The fake has separate Route53 RRsets and Cloudflare IDs per name. Cancellation
holds a provider response after its mutation, then requires cleanup before the
worker exits, without retry or cache publication. Rebuild the peer after changing
`dns.go.txt`; ordinary replay never runs Go's managed issuance authority.

New ACME certificate/challenge keys use ECDSA P-256, an owner-approved divergence
from Go RSA2048 (2026-11-03). [Reviewed entries](../acme/divergences.json) apply only
to the two cold TLS-ALPN key-label observations; frozen Go goldens stay unchanged.
The renewal replay also asserts P-256 on new HTTP-01 keys despite #305's historical
key-label mask. Cached Go RSA keys keep their exact key and renewal CSR algorithm.
OpenSSL remains for legacy RFC2136 SHA1/SHA224 TSIG compatibility, never key generation.
