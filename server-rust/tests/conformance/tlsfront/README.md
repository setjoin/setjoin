# TLS front door oracle (#413)

The checked-in JSON files in this directory are immutable recordings from frozen Go. Their keys,
PSKs, certificates and private keys are public **test fixtures**, never deployment credentials.
The retired Docker/Go peer harness (`build-peer.py`, `peer.rs`, `peer.go.txt`, `dns.go.txt`,
`dns_tick.go.txt`, `tick.rs`) has been removed; every replay runs 100% in pure Rust with zero
Docker and zero Go compilation.

## `setjoin-tls --test go_interchange`

Replays against `setjoin_tls::Frontend` using a pure-Rust `rustls` client and independent Go
envelope verification:

- **Go → Rust (`tls13-resumed.json`, `tls12-resumed.json`)**: verifies `Tickets::open` decrypts
  the immutable Go-recorded wire ticket bit-for-bit to `server_state.plain`, translates retargeted
  timestamps via `state::for_rustls` (round-tripping back via `state::for_go`), and runs live
  over-the-wire TLS 1.2/1.3 full and resumed handshakes against `Frontend`.
- **Rust → Go (`tls13-session-metadata.json`, `tls12-session-metadata.json`)**: captures a live
  `Frontend`-issued ticket from the resuming client's `ClientHello`, decrypts it independently
  with Go 1.26's `SHA-512` → `AES-128-CTR` + `HMAC-SHA256` format and validates Go's `SessionState`
  wire framing against the recorded metadata.
- **Rotation and rejections (`ticket-generations.json`)**: verifies `current`, `previous`,
  `older-rejected`, `bad-mac`, and `expired` both directly against the recorded Go envelope and
  live over the wire against `Frontend`. The wrong-key mutant must fail resumption.

```sh
cargo test --manifest-path server-rust/Cargo.toml --locked -p setjoin-tls --test go_interchange --test policy
```

The four database mutator mutants do not apply to the TLS transport (no rows, audit, notify
or state bumps). The ticket-key consumer mutant proves resumption discrimination.

## `setjoin-gateway --test tls_recorded`

Replays 16 Go HTTP/TLS cases with AES-GCM hardware enabled and disabled (32 observations) using an
in-process pure-Rust `tokio-rustls` + `hyper` + `x509-parser` probe: h2, HTTP/1.1, h2c,
managed/autocert/static ordering, SNI normalization, wildcard boundaries and expired/corrupt/cold
caches. Compares status, protocol, cipher, served chain, subject CN, content type, HSTS and
ticket count against `http-negotiation.json` and `http-negotiation-no-aes.json`. HTTPS adds Go’s
default HSTS unless the application supplies its own value.

## `setjoin-tls --test policy`

Replays 22 frozen-Go policy observations (`policy.json`, 11 clients × AES-GCM hardware
available/unavailable), including TLS 1.2 ChaCha/P-384 rejection, server cipher preference,
cold-SNI `unrecognized_name`, and TLS 1.3 same-hash cross-suite resumption.

## `setjoin-acme --test dns_recorded`

Replays nine single-name and three multi-domain immutable Go DNS-01 ticks (`dns-*.json`) plus
`route53-endpoints.json` against an in-process pure-Rust peripheral (`crates/acme/tests/support/dns_fake.rs`):
Cloudflare HTTP API with bearer auth and publish gate, Route53 XML API with independent AWS SigV4
verification, and RFC2136 UDP DNS/TSIG (SHA1/SHA224/SHA256/SHA384/SHA512 plus unsigned).
Multi-domain replay canonicalizes independent names within a phase only, checking every
request/body, phase boundary, retry and per-name API sequence. Cloudflare/Route53 prepare all names
before cleanup; RFC2136 is sequential. Cancellation holds a provider response after its mutation,
then requires cleanup before the worker exits, without retry or cache publication.

New ACME certificate/challenge keys use ECDSA P-256, an owner-approved divergence from Go RSA2048
(2026-11-03). [Reviewed entries](../acme/divergences.json) apply only to the two cold TLS-ALPN
key-label observations; frozen Go goldens stay unchanged. Cached Go RSA keys keep their exact key
and renewal CSR algorithm. OpenSSL remains for legacy RFC2136 SHA1/SHA224 TSIG compatibility,
never key generation.
