# setjoin-tls (#413)

Foundation TLS transport for the Rust front door. No database access or business logic.
`Frontend::from_env` reads Go’s `TLS_CERT` / `TLS_KEY` (with native `TLS_CERT_FILE` /
`TLS_KEY_FILE` aliases when neither Go name is present) and `TLS_AUTOCERT_DOMAINS` /
`TLS_AUTOCERT_CACHE_DIR`; no configured source means no TLS frontend. It accepts TLS 1.2/1.3,
with ALPN `h2` then `http/1.1`, using ring-backed rustls pinned in Cargo.toml.
TLS 1.3 sends one session ticket, matching Go.
The complete TLS handshake (ClientHello plus negotiation) is bounded to 30 seconds.

Certificate selection mirrors frozen `mailserverd`: managed hashed cache (exact configured
SNI or one-label wildcard, currently unexpired) → autocert literal `name` / `name-rsa`
cache (exact whitelist, hostname match, unexpired) → hot-reloading static pair (`ReloadingPem`). Managed
blobs and static PEM pairs are reloaded automatically without restarts, so atomic edge-proxy or
ACME replacements affect new handshakes and `CertMonitor` (`served_chain()`) immediately after
the debounce window. Serving never registers an account, issues a certificate, or writes a cache entry.

`ReloadingPem` (#559, `src/reloading_pem.rs`) is pure `rustls` (ring) and available with
`default-features = false` (zero `setjoin-acme` or `openssl` dependency edges), powering direct
HTTPS, standalone auth, IMAPS/IMAP STARTTLS, SMTPS/Submission STARTTLS, LDAPS, and Federation
mTLS. It validates regular files (`metadata.is_file()`), caps reads at `1 MiB`
(`Read::take((1 << 20) + 1)`), watches subsecond metadata signatures via `std::fs::metadata()`
(following symlinks), separates disk I/O from the `RwLock<State>` via a `try_lock()` reload
mutex so concurrent handshakes never block, debounces stat checks (`1s` default), throttles
repeated failures on the same `(cert_sig, key_sig)` (`3s` default) while recovering immediately
on any new file signature, and retains the last-known-good `CertifiedKey` on corrupt/transient
writes. `setjoin-acme` is gated behind the `acme` feature (default ON for Release N).

Tests: `cargo test --locked -p setjoin-tls --test listener -- --test-threads=1` checks the
external TLS socket: both ALPNs, exact served certificate, SNI fallback, live replacement,
expired/corrupt cache fallback, and the distinct autocert filename namespace.

Session tickets use Go 1.26's SHA-512 key expansion and AES-128-CTR + HMAC-SHA256 envelope;
RustCrypto/ring implement every primitive and authentication comparison. The live key ring
accepts only the supplied current/previous generation. `state.rs` translates Go's server
SessionState into pinned rustls 0.23.46 metadata, and Rust-issued tickets serialize back into
Go's format. Both stacks retain responsibility for PSKs, key schedules and binders. TCP
0-RTT is disabled; expired (>7 days), malformed and unauthenticated tickets miss closed.
The rustls version is pinned because its serialized session format is private.

`go_interchange` replays archived Go TLS 1.2/1.3 sessions (decrypting the immutable recorded Go
tickets directly via `Tickets::open` and translating retargeted timestamps via `state::for_rustls`),
verifies live `Frontend`-issued tickets against Go's `SHA-512` → `AES-128-CTR` + `HMAC-SHA256`
envelope and `SessionState` wire layout, and compares live TLS 1.3 current/previous, older-generation,
bad-MAC and expired-ticket behavior with immutable Go recordings.
A deliberately wrong key must fail the resumption oracle. Replay runs 100% in pure Rust with zero
Docker and zero Go. See [recording contract](../../tests/conformance/tlsfront/README.md).
Application resumption data is not installed by this frontend.

`Frontend::from_env_with_client_verifier` (#468) accepts the gateway's optional
ring-backed rustls client verifier; TLS continues to own proof of key possession
and chain verification. The transport has no database dependency. The gateway
passes the connection's first peer leaf to HTTP requests as `PeerCertificate`
extensions; forwarded certificate headers never populate that type.

`Frontend::served_chain` is the source for the gateway's certificate monitor: the first usable
configured SNI's complete served chain, or the static-only empty-SNI selection. It reads through
the same selector as actual connections; no caller supplies unrelated certificate metadata.

TLS-ALPN validation shares `Frontend::tls_alpn_store` with the renewal worker. A pending
matching SNI plus offered `acme-tls/1` gets its isolated RFC 8737 certificate and no session
tickets. Ordinary connections keep the application certificate. The gateway closes a
completed validation handshake without HTTP dispatch. See [ACME contract](../acme/DOX.md).

TLS policy is restricted to X25519/P-256 and the four configured TLS 1.2 ECDHE AES-GCM
suites. TLS 1.2 ChaCha/P-384 are refused. TLS 1.3 ordering follows Go's client preference
and AES-GCM hardware predicate (AES+PCLMUL on x86_64, AES+PMULL on arm64); the same-hash
AES128/ChaCha PSK bridge preserves Go's resumption when a client changes suites.
`tests/policy.rs` replays immutable Go negotiations with both hardware predicates,
including rejected ALPN/curves/suites, cold-SNI alert and cross-suite resumption.
