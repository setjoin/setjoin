# TLS front door oracle (#413, #560)

The checked-in JSON files in this directory are immutable recordings from frozen Go. Their keys,
PSKs, certificates and private keys are public **test fixtures**, never deployment credentials.
Every active replay runs 100% in pure Rust with zero Docker and zero Go compilation.

In Release N+1 (`#560`), `setjoin-acme`, Go TLS session-ticket wire interchange (`go_interchange`,
`ticket-generations.json`, `tls-ticket-keys`), and the private `rustls` version pin were retired.
`setjoin-tls` now uses standard semver `rustls = "0.23"`, rustls's built-in ring `Ticketer`, and
pure-`rustls` `ReloadingPem` for all TLS listeners.

## `setjoin-gateway --test tls_recorded`

Replays the 4 static-PEM / h2c Go HTTP/TLS cases (`tls13-h2`, `tls13-http11`, `tls12-http11`,
`h2c-prior-knowledge`) with AES-GCM hardware enabled and disabled (8 observations) using an
in-process pure-Rust `tokio-rustls` + `hyper` + `x509-parser` probe against `http-negotiation.json`
and `http-negotiation-no-aes.json`. HTTPS adds the default HSTS header unless the application
supplies its own value.

## `setjoin-tls --test policy`

Replays the non-ACME, non-ticket-bridge frozen-Go policy observations (`policy.json`, 9 clients ×
AES-GCM hardware available/unavailable = 18 observations), including TLS 1.2 ChaCha/P-384 rejection,
server cipher preference, and unmatched ALPN rejection.

```sh
cargo test --manifest-path server/Cargo.toml --locked -p setjoin-tls --test policy
```
