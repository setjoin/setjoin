# setjoin-tls (#413, #559, #560)

Slim pure-`rustls` (ring) TLS transport for all Setjoin listeners. Zero database access, zero business logic, zero `openssl` / `openssl-sys` / `setjoin-acme` dependencies, and standard semver `rustls = "0.23"` / `tokio-rustls = "0.26"` (no private exact `rustls` pin).

## Certificate Loading & Atomic PEM Hot-Reload (`ReloadingPem`)

`ReloadingPem` (#559, `src/reloading_pem.rs`) powers every TLS listener in Setjoin:

1. Direct HTTPS (`crates/tls` `Frontend`) & standalone auth (`bins/auth`)
2. SMTP STARTTLS / SMTPS (`crates/protocols/smtp`)
3. IMAP STARTTLS / IMAPS (`crates/protocols/imap`)
4. LDAPS (`crates/protocols/ldap`)
5. Federation mTLS (`crates/protocols/federation`)
6. `bins/gateway` & `bins/setjoind` direct HTTPS startup and `CertMonitor` (`Frontend::served_chain()`)

`Frontend::from_env` reads `TLS_CERT` / `TLS_KEY` (falling back to native `TLS_CERT_FILE` / `TLS_KEY_FILE` aliases when neither primary variable is present); no configured pair returns `Ok(None)`. `ReloadingPem`:

- validates regular files (`metadata.is_file()`) and caps reads at `1 MiB` (`Read::take((1 << 20) + 1)`);
- watches subsecond metadata signatures via `std::fs::metadata()` (following symlinks such as `/etc/letsencrypt/live/...`);
- separates disk I/O from `RwLock<State>` behind a `try_lock()` reload mutex so concurrent handshakes never block;
- debounces stat checks (`1s` default), throttles repeated failures on the same `(cert_sig, key_sig)` (`3s` default) while recovering immediately on any new file signature, and retains the last-known-good `CertifiedKey` on corrupt or transient writes.

## Handshake Policy, Resumption & Optional mTLS

- Accepts TLS 1.2 and TLS 1.3 with ALPN `h2` then `http/1.1`; handshake total timeout is bounded to 30 seconds.
- Session resumption uses `rustls`'s built-in ring `Ticketer` (shared across the AES-GCM and ChaCha20 server configs; TLS 1.3 sends 1 ticket, 0-RTT disabled). Go TLS session-ticket wire interchange (`state.rs`, `tickets.rs`, `tls-ticket-keys` DB worker) was retired in `#560`.
- Built-in ACME (`crates/acme`, `DirCache`, `TlsAlpnStore`, `setjoin-acme.socket`) was retired in `#560`. Operators manage ACME at the edge (Caddy or certbot) exporting PEM files; see `docs/guides/EDGE_TLS_ACME_MIGRATION.md`.
- `Frontend::from_env_with_client_verifier` (#468) installs the gateway's optional ring-backed rustls client verifier. The gateway exposes the connection's first verified peer leaf to HTTP requests as `PeerCertificate` request extensions; forwarded certificate headers never populate `PeerCertificate`.
- `Frontend::served_chain` returns the live chain from `ReloadingPem` for `CertMonitor`.
- TLS policy (`src/policy.rs`) restricts key exchange to X25519 / P-256 and the four configured TLS 1.2 ECDHE AES-GCM suites (TLS 1.2 ChaCha and P-384 are refused). TLS 1.3 cipher preference follows host AES-GCM hardware capability (`aes_gcm_hardware()`) and client preference.

## Verification

- `cargo test --locked -p setjoin-tls`:
  - `tests/listener.rs` — ALPN (`h2` / `http/1.1`), built-in `Ticketer` session resumption, 30s handshake timeout, `TLS_CERT`/`TLS_KEY` loading.
  - `tests/pem_hot_reload.rs` — DANE-EE key-reuse & full key rotation with active h2 survival, concurrent fault tolerance & cooldown recovery, symlink rotation, size/mismatch startup refusal, and direct HTTPS + mTLS `PeerCertificate` across atomic PEM swap.
  - `tests/policy.rs` — TLS 1.2/1.3 cipher/curve/ALPN negotiation against immutable recordings with both AES-GCM hardware predicates.
