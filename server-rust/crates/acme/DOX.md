# setjoin-acme (#305)

Managed ACME certificate lifecycle for the Platform `acme-renewal` worker and the HTTP-01 /
TLS-ALPN-01 responders and DNS provider APIs. No HTTP routes, no database. The gateway wires it (`bins/gateway/src/acme.rs`).

- **Cache** (`cache.rs`): frozen Go's `acme.DirCache` layout so either process serves what the
  other issued: blob (key PEM, then chain PEM) at `hex(sha256(domain))`, 0600 files in a 0700
  directory, same-directory temp + fsync + rename. The account key is SEC1 `EC PRIVATE KEY`
  (`account.key` or `TLS_AUTOCERT_KEY_FILE`), created once, 0600.
- **Manager** (`manager.rs`): Go's `renewIfNeeded` for HTTP-01, TLS-ALPN-01 and DNS-01. One order for all
  configured domains (multi-SAN), renewed when any is missing, unparsable or within 30 days of
  expiry, three attempts per round (30 s doubling to 1 h, 20 % jitter), 12-hour tick, one round
  at a time, nothing published when validation fails, the cached private key reused so the DANE-EE
  hash survives renewal. Registration is `create_from_key` then `mailto:` contact update.
- **TLS-ALPN-01**: the worker shares a `TlsAlpnStore` with the application TLS listener.
  Only offered `acme-tls/1` plus a matching pending SNI selects the single-use challenge pair.
  The digest extension comes from rcgen's RFC 8737 encoder; RAII withdraws pending responses
  on success, failure and cancellation. Application certificate validation remains separate
  from this deliberately critical-extension certificate. No challenge request reaches HTTP.
- **Keys**: new certificate and TLS-ALPN challenge keys use ring-backed ECDSA P-256.
  Go issues RSA2048; this divergence is owner-approved 2026-11-03 and recorded in
  [reviewed divergences](../../tests/conformance/acme/divergences.json). Cached Go RSA
  keys remain readable and reusable on renewal, preserving DANE-EE SPKI; ring signs
  their CSRs without generating RSA keys. Account keys remain P-256/SEC1.
  Vendored OpenSSL remains only for RFC2136 SHA1/SHA224 TSIG HMAC and comparison;
  it is not used for key generation. No cryptographic primitive is implemented here.
- **DNS-01 (#413)**: Cloudflare token auth (TTL 120); Route53 SigV4 via reqsign's cached
  credential chain (JSON keys, environment, profile, web identity/ECS/IMDS, configured credential
  process) and XML APIs; RFC2136 UDP updates with optional TSIG. Hickory owns DNS wire/modern
  TSIG; OpenSSL supplies Go-compatible SHA1/SHA224 HMAC over Hickory's TSIG wire encoding.
  Go's partial provider configs have propagation timeout zero: publish, cleanup, fail before
  notifying the CA, retry three times. Route53/RFC2136 TTL stays zero; RFC2136 Present clears
  the TXT RRset before inserting its value. Preserve these observed Go defects (ARCH-029).
  No real provider/zone is used in tests; endpoints are injectable only through the library.
- **CSR**: the first configured domain is the CommonName, all identifiers are SANs (lego).
  Pebble strips CSR subjects from issued certificates; the wire-CSR test separately checks
  subject/SANs plus the P-256 public key and ECDSA-SHA256 signature.
- **Tests**: `tests/cache.rs` (layout, modes, construction errors), `tests/pebble.rs` (issuance,
  key reuse, fresh untouched, failure publishes nothing) against Let's Encrypt's pebble
  (`PEBBLE_BIN`, fixtures `tests/conformance/acme/pebble`; a missing binary fails when
  `REQUIRE_DB` is set). The Go-vs-Rust seed-plus-one-tick oracle is
  `bins/gateway/tests/acme_renewal_recorded.rs`.

`tests/dns_recorded.rs` replays twelve Go managed ticks (nine single-name and three multi-domain; AWS environment credentials,
all five TSIG hashes and unsigned RFC2136). A Go CI-image peripheral supplies fake DNS/provider
APIs, validates AWS signatures with the independent official Go SDK and validates TSIG on both
sides. Bad-token/key mutants must cause no mutation. The helper and source-hash receipt are
built with `tests/conformance/tlsfront/build-peer.py`; normal replay runs no Go authority.
`gateway --test acme_tls` proves live chain replacement and an existing h2 connection survives.
The two TLS-ALPN worker goldens are in `tests/conformance/acme/goldens/acme-tls-alpn-*`.

Graceful `Manager::run` cancellation drains already-started DNS Present/CleanUp work before
returning. The tick may stop waiting, but it must not abandon a provider that has applied
an update and has not yet returned its record ID. Retry/backoff and cache publication stop.
`dns_recorded::shutdown_finishes_dns_publication_and_cleanup_before_returning` gates the
fake provider response after its TXT mutation, then checks the first recorded Go attempt's
publication/cleanup effects without a second attempt. Hard process/task aborts cannot offer
this graceful drain guarantee.

Multi-domain DNS orders process every pending authorization. Cloudflare/Route53 prepare
all names before cleanup; RFC2136 requires complete per-name sequences. Three additional
immutable Go ticks (`dns-*-multi-zone.json`) pin both modes. Their peripheral keeps Route53
RRsets and Cloudflare IDs separate per name. Pebble randomizes authorization order: replay
sorts only independent names within the same phase, retaining every request/body, phase
boundary, retry count and per-name API sequence. Original single-name goldens stay unchanged.
