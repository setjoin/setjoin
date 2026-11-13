# Feature & Dependency Research

Date: 2026-06-03
Scope: Four open-source mail servers analyzed for features, architecture, and dependency choices relevant to SetJoin.
Sources: Project documentation, GitHub source trees, DeepWiki architecture dumps, crate/package registries, license files.

---

## 1. Server Projects Analyzed

### 1.1 Stalwart Mail Server (Rust)

**Repository:** github.com/stalwartlabs/stalwart | **License:** AGPL-3.0 / SEL (Enterprise)
**Stars:** ~10,500 | **Latest:** v0.15.0 (Dec 2025)

Stalwart is an all-in-one mail and collaboration server written entirely in Rust. It replaces the traditional Postfix + Dovecot + SpamAssassin stack with a single binary. Organized as a Cargo workspace of 20+ crates using Rust Edition 2024. Uses `tokio` + `rustls` + `hyper` as its async/HTTP stack and supports eight storage backends (RocksDB, FoundationDB, PostgreSQL, MySQL, SQLite, S3, Azure, Redis) via feature gates.

**What SetJoin can learn:** Stalwart's crate layering discipline (protocol-parser crates with zero deps, business-logic crates depending only on `common`, feature-gated storage backends) is the best architectural model in the space. Their spam pipeline (FTRL-Proximal linear classifier with feature hashing, per-user Bayesian models, LLM classification optional) is the most advanced open-source spam system. Their `registry` crate (dynamic, schema-driven configuration stored in the DB, hot-reloaded via `ArcSwap`) is a better pattern than env-var-only config.

### 1.2 Maddy (Go)

**Repository:** github.com/foxcpp/maddy | **License:** GPL-3.0
**Stars:** ~5,600 | **Latest:** v0.8.1

Maddy is a composable all-in-one mail server written in Go. It integrates SMTP, Submission, and IMAP into a single daemon with a modular pipeline architecture defined entirely in configuration files. Endpoints, checks (SPF/DKIM/DMARC/DNSBL/Milter/rspamd), modifiers (DKIM signing, header rewriting), and delivery targets are connected via config, not code.

**What SetJoin can learn:** Maddy's composable pipeline model (config-file-defined chains of check -> modify -> deliver) is a more flexible approach than hardcoded SMTP processing. Their PostgreSQL update broker pattern (multiple gateway instances sharing one DB, coordinated by LISTEN/NOTIFY) validates SetJoin's LISTEN/NOTIFY approach. The Milter protocol support (Sendmail milter, Unix sockets) is a feature SetJoin should consider for interoperability with existing enterprise spam appliances. Maddy's ACME integration (DNS-01 challenge via RFC 2136, acme-dns, and multiple libdns providers) is the most complete in the Go mail server space.

### 1.3 Apache James (Java)

**Repository:** github.com/apache/james-project | **License:** Apache-2.0
**Latest:** v3.8.2 (Jan 2025), 4.0.0 in development

Apache James is a modular Java mail server maintained by the Apache Software Foundation since 2001. Its defining architectural feature is the **Mailet container** -- an inversion-of-control pipeline where incoming mail flows through a chain of Matcher (condition) + Mailet (action) pairs, analogous to servlet filters. James is the only server in this analysis with native JMAP support (since v3.6.0), making it the closest architectural cousin to SetJoin.

**What SetJoin can learn:** The Mailet concept (pluggable, chainable mail processors configured in XML) is the most mature mail processing pipeline in existence. James's distributed deployment model (Cassandra for metadata, S3/Swift for blobs, RabbitMQ for queuing, OpenSearch for search) is a production-proven reference for horizontal scaling. Their Sieve engine (`jSieve`) is a standalone library, separate from the server -- a model SetJoin could follow by extracting its Sieve logic into `shared/`. The multi-backend search abstraction (Lucene, ElasticSearch, OpenSearch depending on deployment size) is a pattern SetJoin could adopt for search scalability.

### 1.4 Cyrus IMAP (C)

**Repository:** github.com/cyrusimap/cyrus-imapd | **License:** BSD-4-Clause
**Latest:** v3.12.1 (experimental), v3.8.6 stable

Cyrus IMAP is the oldest continuously maintained mail server in existence (Carnegie Mellon, 1994). Written in C, it uses a custom binary mailbox format (cyrus.index, cyrus.cache, cyrus.expunge), Xapian for full-text search, and a murder-of-crows clustering architecture (frontend proxies + backend data nodes + MUPDATE replication). It is the reference implementation for IMAP IDLE, CONDSTORE, QRESYNC, and Sieve (RFC 5228 author is a Cyrus contributor).

**What SetJoin can learn:** Cyrus's mail storage design (separate files for index, cache, expunge data -- mmap'd for zero-copy reads) is the performance gold standard for mailbox access patterns. The Murder clustering architecture is the most battle-tested design for horizontal IMAP scaling. Xapian integration proves that an external search index (not just database full-text search) is necessary for mail search at scale. Cyrus's Sieve implementation (server-side, compiled to bytecode by `sievec`, executed at LMTP delivery) is the most complete Sieve implementation in any server.

---

## 2. Power Features to Adopt

### P0 -- High Impact, Aligns With Current Phase Work

#### 2.1 FTRL-Proximal Spam Classifier (from Stalwart)

**What it is:** Stalwart replaced its Bayesian spam classifier with a FTRL-Proximal (Follow-the-Regularized-Leader) linear classifier with feature/cuckoo hashing. Features map into a configurable vector space; the model trains online from user Junk/Not-Junk actions. This is 5x faster than their prior Bayesian implementation and achieves better precision.

**Effort:** 3 weeks (Go, in `mailserver/internal/smtp/` antispam pipeline)
**Why:** SetJoin's current spam scoring is rules-based (SpamAssassin-style weighted rules). Stalwart's approach learns per-user preferences from Junk folder moves -- no manual rule tuning. The FTRL algorithm is simple enough to implement directly (no library needed; the core update is ~50 lines of Go). Feature hashing avoids the unbounded vocabulary problem of Bayesian classifiers.
**Files to modify:**
- `mailserver/internal/smtp/antispam.go` -- add FTRL classifier
- `mailserver/sql/reducers/` -- new reducer `spam_train(p_account_id, p_message_id, p_is_spam)`
- `mailserver/sql/migrations/` -- new table `spam_model(user_id, model_bytes, updated_at)`

#### 2.2 Composable Check/Modify/Deliver Pipeline (from Maddy)

**What it is:** Maddy's SMTP processing pipeline is defined in config as a chain of **checks** (SPF, DKIM, DMARC, DNSBL, Milter, rspamd), **modifiers** (DKIM sign, replace_sender, replace_rcpt), and **delivery targets** (remote MX, LMTP, queue). The order is configurable, not hardcoded. Adding a new check is a config change, not a code change.

**Effort:** 2 weeks (Go, refactor `internal/smtp/` pipeline)
**Why:** SetJoin's SMTP pipeline (`internal/smtp/inbound.go`) runs checks in a hardcoded sequence. A composable pipeline would allow customers to insert custom checks (Milter, rspamd) and reorder processing without forking the gateway. This is a strong enterprise differentiator -- large organizations often have existing spam appliances they want to keep.
**Files to modify:**
- `mailserver/internal/smtp/pipeline.go` -- new composable pipeline engine
- `mailserver/internal/smtp/inbound.go` -- replace hardcoded sequence with pipeline
- `mailserver/internal/config/config.go` -- add `smtp_pipeline` config section

#### 2.3 ACME DNS-01 Challenge Automation (from Maddy / Stalwart)

**What it is:** Both Maddy and Stalwart implement automated TLS certificate issuance and renewal via ACME (RFC 8555) with DNS-01 challenge. Maddy supports RFC 2136 dynamic DNS updates and multiple provider-specific `libdns` plugins. Stalwart supports 7+ DNS providers (Cloudflare, Route53, GCP DNS, Bunny, Porkbun, DNSimple, Spaceship) and automatically updates TLSA records for DANE.

**Effort:** 2 days (Go, new `internal/acme/` package)
**Status:** TLS-ALPN-01 and HTTP-01 already implemented via `golang.org/x/crypto/acme/autocert` in `mailserver/cmd/gateway/main.go:913-935`. DNS-01 is the remaining gap — needed for air-gapped deployments and wildcard certs.
**Why:** The existing autocert covers internet-facing deployments. DNS-01 adds coverage for firewalled/air-gapped deployments where ports 80/443 are not reachable. Uses `github.com/go-acme/lego/v4` (MIT) for its 50+ DNS provider catalog.
**Implementation plan:** `docs/plans/acme-dns01-challenge.md`
**Files to create:**
- `mailserver/internal/acme/dns01.go` — Lego-based cert manager with GetCertificate hook
- `mailserver/internal/acme/dns_providers.go` — provider factory (cloudflare, route53, rfc2136)
- `mailserver/internal/acme/cache.go` — disk-backed cert cache
**Dependency:** `github.com/go-acme/lego/v4` (MIT)

### P1 -- High Impact, Medium Effort

#### 2.4 Mailet-Style Pluggable Mail Processors (from Apache James)

**What it is:** James's Mailet container runs incoming mail through a chain of Matcher + Mailet pairs. Each Mailet is a Java class implementing `org.apache.mailet.Mailet` with `service(Mail)` and `init(MailetConfig)`. The chain is defined in XML. This has been stable for 20+ years and is the most flexible mail processing architecture in existence.

**Effort:** 3 weeks (Go, new `internal/mailet/` package)
**Why:** This is a superset of Maddy's pipeline (item 2.2) -- Mailets are Go plugins (via `plugin` package or WASM) that run arbitrary logic, not just configurable checks. This enables customer-written mail processors (e.g., "encrypt all outbound mail to partner.com with PGP", "append legal disclaimer to all external mail"). The Matcher language (conditions on headers, body, size, recipient) is a superset of SetJoin's existing Rules engine.
**Files to create:**
- `mailserver/internal/mailet/interface.go` -- `Matcher` and `Mailet` interfaces
- `mailserver/internal/mailet/container.go` -- chain runner with error isolation
- `mailserver/internal/mailet/matchers/` -- built-in matchers (by_sender, by_recipient, by_header, by_size)
- `mailserver/internal/mailet/mailets/` -- built-in mailets (forward, archive, notify, tag)
**Dependency:** `github.com/google/koanf` (structured config with hot reload, Apache-2.0) for XML/TOML chain definitions

#### 2.5 Xapian-Style External Full-Text Search Index (from Cyrus IMAP) ✅ IMPLEMENTED

**What it is:** Cyrus uses Xapian (C++ search library) as a separate full-text search index. The research initially recommended Bleve (pure Go) or Meilisearch (Rust, HTTP API) as SetJoin's search backend.

**Status:** Implemented via **pg_search** (ParadeDB BM25 extension) — `mailserver/sql/schema/036_pg_search.sql`. Replaces 3 GIN indexes (`messages_body_tsv_idx`, `messages_subject_tsv_idx`, `messages_from_tsv_idx`) with a single BM25 index on `(id, body_tsv, subject_tsv, from_tsv, received_at)`. Uses ICU tokenizer for CJK support. Paradb.score(id) provides relevance ranking. This is a better fit than Bleve or Meilisearch — it lives inside PostgreSQL (zero external services), uses the same connection pool, and benefits from existing backup/replication infrastructure.

**Why pg_search > Bleve for SetJoin:**
- No external service — same PostgreSQL cluster, same backups, same HA
- CJK support via ICU tokenizer (Bleve's CJK support requires separate analyzer)
- BM25 relevance scoring (better than tsvector GIN for ranked results)
- Already deployed in production schema (Phase 36)

#### 2.6 Per-User Spam Model Training (from Stalwart)

**What it is:** Stalwart's users train the spam filter by moving messages to/from the Junk folder or toggling the `$Junk` flag. Each user has an independent model (FTRL-Proximal weights vector) that learns their personal spam/ham preferences. Auto-learning also triggers from spam traps and DNSBL hits.

**Effort:** 2 weeks (Go + PL/pgSQL)
**Why:** Spam is subjective -- what one user considers spam, another considers a desired newsletter. Per-user models solve this. SetJoin already has the infrastructure: Junk folder tagging (Phase 17 tag system), a spam scoring pipeline (`internal/smtp/antispam.go`), and server-side rules. Adding per-user model persistence and training is a natural extension.
**Files to modify:**
- `mailserver/internal/smtp/antispam.go` -- per-user model loading, scoring, training on Junk/Not-Junk moves
- `mailserver/sql/reducers/` -- `spam_train`, `spam_score`
- `mailserver/sql/migrations/` -- `spam_model` table
- `mailserver/internal/notify/` -- trigger model retraining on tag changes (`message_tags` INSERT/DELETE for Junk)

#### 2.7 Milter Protocol Support (from Maddy / Cyrus)

**What it is:** The Sendmail Milter protocol allows external programs (spam filters, virus scanners, DKIM signers, archivers) to inspect and modify mail during SMTP transaction via a Unix socket protocol. Maddy implements a Milter client (connect to external Milters). Cyrus ships with a Milter server.
**Effort:** 1 week (Go, new `internal/milter/` package)
**Why:** Many enterprise environments have existing Milter-based spam/virus appliances (Symantec, Mimecast, Proofpoint). Supporting Milter as a protocol allows SetJoin to slot into these environments without requiring customers to replace their security stack.
**Files to create:**
- `mailserver/internal/milter/client.go` -- connect to external Milters
- `mailserver/internal/milter/protocol.go` -- Milter protocol implementation

### P2 -- Lower Priority, Future Phases

#### 2.8 Sieve Engine as Standalone Library (from Apache James `jSieve`)

**What it is:** Apache James ships `jSieve` as a standalone Java library -- not coupled to the server. This allows any application to use Sieve filtering. Stalwart does the same with its `sieve-rs` crate (Rust). SetJoin's Sieve support is embedded in the SMTP pipeline.
**Effort:** 2 weeks (Go, extract to `shared/sieve/`)
**Why:** Extracting Sieve into `shared/` would allow the auth server, migration tools, and admin CLI to all use the same Sieve engine without importing the full mailserver. This is a code-quality cleanup, not a user-facing feature.
**Files to create:**
- `shared/sieve/parser.go` -- Sieve script parser
- `shared/sieve/evaluator.go` -- Sieve script evaluator
- `shared/sieve/extensions.go` -- registered extension catalog

#### 2.9 Encrypted Search via Blind Indexing (from Stalwart spam privacy)

**What it is:** Stalwart v0.15.0 added "encryption-at-rest" for spam training data -- the training corpus is stored encrypted so that even a database compromise does not expose which messages were marked as spam by which users. This is a privacy feature for multi-tenant deployments.
**Effort:** 1 week
**Why:** SetJoin's per-tenant data isolation is already strong (RLS-enforced). Encrypting training data adds defense-in-depth for multi-tenant deployments where one tenant's spam annotations could leak information about another tenant's mail patterns if RLS were bypassed.

#### 2.10 Murder-Style Horizontal Scaling for Mail Storage (from Cyrus IMAP)

**What it is:** Cyrus's Murder architecture uses: (a) frontend proxies that accept IMAP/POP3/LMTP connections, (b) backend data nodes that store mailboxes on local disk, (c) an MUPDATE protocol that replicates mailbox location metadata across all nodes. This allows mailbox-level sharding without a central metadata store.
**Effort:** 8 weeks (multi-component, Go + PL/pgSQL)
**Why:** SetJoin currently scales vertically (PostgreSQL handles all mail metadata). For 10,000+ user deployments, mailbox-level sharding across multiple storage nodes is necessary. The Murder architecture is the most proven design for this.

---

## 3. Dependencies to Adopt

### 3.1 Rust (mail-core / guard-core / desktop-core)

| Dependency | Version | License | Replaces | Why Better | Effort |
|---|---|---|---|---|---|
| `mail-parser` | 0.11 | Apache-2.0 / MIT | None (new capability) | RFC 5322/2045/2047/2183 MIME parsing in pure Rust. Used by Stalwart in their `email` crate. Handles MIME tree construction, header decoding, charset conversion, and attachment extraction. Would replace the need to pass raw MIME through JMAP to the client -- `mail-core` could pre-parse and index. | 3 days |
| `mail-auth` | 0.8 | Apache-2.0 / MIT | `mailserver/internal/smtp/dkim.go`, `spf.go`, `dmarc.go` (partial) | DKIM, SPF, DMARC, ARC, BIMI, MTA-STS, TLS-RPT verification in Rust. Same author as `mail-parser`. SetJoin's Go SMTP auth is battle-tested but `mail-core` will need these for client-side DKIM signature verification (a feature no mail client has today). | 5 days |
| `sieve-rs` | 0.7 | Apache-2.0 / MIT | None in Rust (Go has embedded Sieve in `internal/smtp/`) | Full Sieve engine in Rust supporting all registered extensions. Stalwart uses this. Enables client-side Sieve evaluation in `mail-core` -- run filters locally before syncing to server. | 3 days |
| `mail-builder` | 0.4 | Apache-2.0 / MIT | None (new capability) | RFC 5322/2045 MIME message construction in Rust. Used by Stalwart's `smtp` and `jmap` crates. Would let `mail-core` build MIME messages client-side for JMAP `Email/import` without round-tripping raw bytes. | 1 day |
| `rkyv` | 0.8 | MIT | `serde` (for cache layer) | Zero-copy deserialization. Stalwart uses this for their storage layer. For `mail-core`'s SQLite cache, `rkyv` would allow reading cached JMAP objects directly from mmap'd pages without deserializing. Performance improvement for large mailboxes. | 2 days |
| `tracing` | 0.1 | MIT | None (new capability) | Structured, async-aware logging. Stalwart uses their own `trc` crate, but `tracing` is the Rust ecosystem standard (Tokio's own choice). Would give `mail-core` span-based instrumentation compatible with any backend (Jaeger, OpenTelemetry, console). | 1 day |

### 3.2 Go (mailserver / authserver)

| Dependency | Version | License | Replaces | Why Better | Effort |
|---|---|---|---|---|---|
| `github.com/blevesearch/bleve` | 2.5.x | Apache-2.0 | N/A (NOT NEEDED) | ~~Embedded full-text search in pure Go.~~ **Implemented via pg_search BM25 extension** (`mailserver/sql/schema/036_pg_search.sql`) — ParadeDB inside PostgreSQL, zero external services, ICU CJK tokenizer, relevance scoring. Better fit than Bleve for SetJoin's DB-centric architecture. | 0 days (already done) |
| `github.com/go-acme/lego/v4` | 4.x | MIT | None (new capability) | ACME client with 50+ DNS provider plugins. Used by Caddy, Traefik. Would power item 2.3 (ACME automation). More mature than `golang.org/x/crypto/acme` alone -- Lego adds the DNS provider ecosystem. | 2 days |
| `github.com/google/koanf` | 2.x | Apache-2.0 | `internal/config/config.go` (env-var parsing) | Structured config with hot reload, multiple providers (env, file, S3, Vault), multiple formats (TOML, YAML, JSON, HCL). Stalwart's `registry` crate follows the same philosophy but in Rust. Koanf would let SetJoin move beyond env-var-only config to file-based config with hot reload -- same capability without the rewrite Stalwart did. | 3 days |
| `github.com/prometheus/client_golang` | 1.22.x | Apache-2.0 | `internal/metrics/` (hand-rolled) | Prometheus metrics export. Both Maddy and Stalwart expose OpenMetrics/Prometheus endpoints. SetJoin already has metrics instrumentation (`internal/metrics/`) but no Prometheus exporter. Adding this enables Grafana dashboards and alerting for on-premise deployments. | 1 day |
| `github.com/jhillyerd/enmime` | 2.x | MIT | `internal/mimeutil/` (partial) | MIME parsing: header decoding, charset conversion, attachment extraction, HTML-to-text. More comprehensive than SetJoin's hand-rolled `mimeutil` -- handles edge cases like nested multipart/alternative, TNEF (winmail.dat), and S/MIME detection. | 3 days |
| `github.com/drakkan/sftpgo` | N/A | AGPL-3.0 | N/A (reference only) | Not a dependency to import, but a Go project (15k stars) that models multi-backend authentication (LDAP, SQL, OIDC, SAML) with plugin auth providers. Their auth abstraction pattern is worth studying for SetJoin's auth chain (`internal/auth/chain.go`). | N/A (design reference) |

### 3.3 JavaScript/TypeScript (webmail)

| Dependency | Version | License | Replaces | Why Better | Effort |
|---|---|---|---|---|---|
| `@tiptap/extension-markdown` | 3.x | MIT | Hand-written `handlePaste` in `RichTextEditor.svelte` | Official TipTap markdown paste extension. Handles `**bold**`, `*italic*`, `` `code` ``, `[text](url)`, `1. lists`, `> blockquotes`, `--- hr` on paste. Better than writing our own converter -- actively maintained by TipTap team, handles edge cases (nested formatting, escaping). | 1 hour |

---

## 4. Dependency Upgrade Candidates

### 4.1 Go (minor/patch upgrades -- run `go get -u ./...`)

These are outdated with newer patch versions available. All are safe upgrades (no breaking changes expected per SemVer):

| Current | Latest | Package | Impact |
|---|---|---|---|
| v1.41.7 | v1.41.9 | `github.com/aws/aws-sdk-go-v2` | S3 SDK -- bug fixes |
| v1.101.0 | v1.102.2 | `github.com/aws/aws-sdk-go-v2/service/s3` | S3 service client -- bug fixes |
| v1.25.1 | v1.27.0 | `github.com/aws/smithy-go` | Shared types -- major version jump within v1 means feature additions |
| v5.2.5 | v5.3.0 | `github.com/go-chi/chi/v5` | HTTP router -- new features |
| v7.1.0 | v7.2.0 | `github.com/minio/minio-go/v7` | S3 client -- new features |
| v0.15.0 | v0.18.2 | `github.com/emersion/go-message` | MIME parsing -- significant improvements |
| v1.18.5 | v1.18.6 | `github.com/klauspost/compress` | Compression -- bug fix |
| v0.17.3 | v0.17.4 | `github.com/go-webauthn/webauthn` | WebAuthn -- bug fix |
| v0.0.0-... | v0.0.0-... | `github.com/emersion/go-sasl` | SASL -- updated since 2020 |
| v1.2.1 | v1.4.0 | `github.com/gorilla/sessions` | Sessions -- security fixes |

### 4.2 Go (major version upgrades -- evaluate carefully)

| Current | Consider | Package | Notes |
|---|---|---|---|
| v1.4.1 | v2.x | `github.com/jpillora/overseer` | Hot-restart library. v2 may change API. | Not urgent -- current version works. |
| v1.0.1-0.2019... | v1.1.0 | `github.com/boombuler/barcode` | TOTP QR codes. Stable v1.1.0 available. |

### 4.3 npm (webmail -- patch upgrades available)

| Current | Latest | Package | Notes |
|---|---|---|---|
| 2.58.0 | 2.61.1 | `@sveltejs/kit` | Three minor versions behind. Includes Vite 7 fixes, CSP improvements. |
| 7.0.0 | 7.1.2 | `@sveltejs/vite-plugin-svelte` | Vite 8 compatibility fixes. |
| 3.4.5 | 3.4.7 | `dompurify` | XSS sanitizer -- bug fixes. |
| 5.55.7 | 5.56.1 | `svelte` | Svelte 5 -- performance improvements. |
| 4.4.6 | 4.5.0 | `svelte-check` | Type-checking improvements. |
| 8.0.10 | 8.0.16 | `vite` | Build tool -- bug fixes. |
| 4.1.5 | 4.1.8 | `vitest` + `@vitest/coverage-v8` | Test runner -- bug fixes. |

### 4.4 Rust (crates -- stable, no major upgrades needed)

All three Rust crates (`mail-core`, `guard-core`, `desktop-core`) use current stable versions of their dependencies. No upgrade candidates identified. Notable:

- `tokio` 1.x -- latest stable
- `reqwest` 0.12 -- latest stable (0.13 expected but not yet released)
- `rusqlite` 0.31 -- latest stable
- `uniffi` 0.28 -- latest stable

### 4.5 Consider Evaluating (future investigation)

| Library | Current SetJoin | Alternative | Why Consider |
|---|---|---|---|
| `pgx/v5` | v5.9.2 | `pgx/v5` v5.10+ (check) | pgx v5.10 may add query result streaming |
| `rs/xid` | v1.6.0 | `google/uuid` v7 | UUIDv7 is time-sortable, better for B-tree indexes |
| TLS stack | stdlib `crypto/tls` | `rustls` (via `rustls-go` FFI) | Stalwart's move from `ring` to `aws-lc-rs` for FIPS compliance. Not needed yet -- Go's `crypto/tls` is FIPS-compliant when built with `GOEXPERIMENT=boringcrypto`. |

---

## 5. Anti-Recommendations

These are popular libraries or architectural choices we should NOT adopt, with specific reasons.

### 5.1 Libraries to Avoid

| Library | Problem | Alternative |
|---|---|---|
| **`golang.org/x/oauth2` with `golang.org/x/oauth2/google`** (for non-Google flows) | Pulls in Google-specific dependencies (cloud metadata, Google API clients) as transitive deps. SetJoin air-gap deployments cannot use cloud OAuth. Auth server already uses `zitadel/oidc/v3` for OIDC which doesn't need `x/oauth2/google`. Mailserver uses `golang.org/x/oauth2` for M365 Graph but should pin to the base package only. | Pin `golang.org/x/oauth2` without `+google` subpackage. |
| **`github.com/emersion/go-imap` v2** | v2 is a long-running development branch (3+ years) that is not yet stable. v1.2.1 is the stable version SetJoin uses. v2 drops features required for migration connectors. | Keep v1.2.1. Re-evaluate when v2 reaches GA (if ever). |
| **`ring` crate (Rust)** | Stalwart migrated FROM `ring` TO `aws-lc-rs` in 2025. `ring` is maintained by a single developer, has a slower release cadence, and lacks FIPS 140-3 validation. `aws-lc-rs` is AWS's officially supported Rust crypto library based on BoringSSL. | Use `aws-lc-rs` (Apache-2.0 / ISC) for any new Rust crypto. `guard-core` already uses `aes-gcm`, `p256`, `sha2` directly -- no `ring` dependency. |
| **`electron` (for desktop client)** | Memory overhead (300-500 MB idle), slow startup, large binary size. Mailspring, Missive, and pre-Tauri Delta Chat all suffer from this. | Tauri 2 (already adopted in `desktop/src-tauri/`). |
| **`@microsoft/microsoft-graph-client` (npm)** | Pulls in Azure SDK transitive deps, uses OAuth implicit flow (deprecated), requires internet connectivity for token refresh. | SetJoin's M365 Graph integration is server-side (Go, `msgraph-sdk-go`), not client-side. |
| **`libetpan` (C library, used by Mailspring)** | C library with known memory safety issues, unmaintained (last release 2017). Mailspring uses it for MIME parsing. | `mail-parser` (Rust) or `enmime` (Go). |
| **`clamav` C library FFI** | ClamAV's C library is under LGPL, requires signature database downloads (internet-dependent), and has a C API that is hard to bind safely. SetJoin already invokes `clamd` via TCP socket (`internal/smtp/clamav.go`) -- that architecture is correct. | Do not link against `libclamav`. Keep the TCP daemon approach. |

### 5.2 Architectural Anti-Patterns

| Pattern | Why Avoid | Evidence |
|---|---|---|
| **Proprietary JMAP dialect** | Missive's JMAP dialect only works with Missive's server. No third-party client support. No ecosystem. | Standards-compliant JMAP (RFC 8620/8621) with IETF-registered capability extensions only. |
| **IMAP as primary sync protocol** | IMAP is polling-based, stateful per-connection, slow for large mailboxes. Velo, Mailspring, and Delta Chat are IMAP-only and all suffer from sync performance issues. | JMAP is the primary protocol. IMAP is a bridge for legacy clients. |
| **Cloud-only AI features** | Velo's GPT-4 side panel requires internet and a vendor API key. In air-gap deployments, the feature silently breaks. | All AI features use local LLM inference (Ollama, llama.cpp). No cloud API dependency. |
| **Google Fonts / CDN asset loading** | Mailspring loads fonts from third-party URLs. On Chinese networks, Google Fonts is unreachable. In air-gap, timeouts delay startup. | All assets (fonts, icons, translations) bundled in the binary. Already compliant -- maintain this. |
| **Electron for desktop** | 300-500 MB RAM idle for a single IMAP account. | Tauri 2 (already adopted). RAM target: <100 MB idle. |
| **No admin console** | Velo, Missive, Delta Chat have zero IT management surface. Organizations need provisioning, quotas, audit logs. | Admin console is a first-class module (30+ pages). |

### 5.3 License Traps

| License | Risk | SetJoin Impact |
|---|---|---|
| **GPL-3.0 (libraries, not server code)** | GPL libraries linked into Go/Rust binaries make the entire binary GPL. SetJoin's server is AGPL-3.0 (compatible) but the dual-license model (MIT for clients) would be compromised by GPL deps in `mail-core` or `guard-core`. | All Rust client crates must use MIT/Apache-2.0/BSD deps only. Go server can use GPL deps if needed (the server is AGPL anyway), but prefer MIT/Apache-2.0 for shared code. |
| **BSL (Business Source License)** | Time-bomb license -- converts to open-source after N years. Not OSI-approved. Examples: MariaDB MaxScale, CockroachDB (used to be). | Do not depend on BSL-licensed libraries. |
| **SSPL (Server Side Public License)** | MongoDB's license. Not OSI-approved. Incompatible with AGPL. | Do not depend on SSPL-licensed libraries. |
| **Elastic License v2** | Elasticsearch's new license. Not OSI-approved. Restricts managed service providers. | Do not depend on Elastic License v2 libraries. |

---

## 6. Summary: Highest-ROI Actions

In priority order, with effort estimates:

| # | Action | Priority | Effort | Category |
|---|---|---|---|---|
| 1 | Upgrade Go dependencies (`go get -u ./...`) | P0 | 0.5 days | Maintenance | ❌ |
| 2 | Upgrade npm dependencies (`npm update`) | P0 | 0.5 days | Maintenance | ❌ |
| 3 | Add `@tiptap/extension-markdown` for markdown paste | P0 | 1 hour | JS deps | ❌ |
| 4 | Implement FTRL-Proximal spam classifier | P0 | 3 weeks | Feature | ✅ Implemented (12 tests, admin + CLI) |
| 5 | Add `lego/v4` ACME DNS-01 challenge | P0 | 2 days | Go deps + feature | ✅ Implemented (43 tests, admin + CLI) |
| 6 | Full-text search index | P1 | — | Done | ✅ pg_search BM25 (Phase 36) |
| 7 | Add Prometheus metrics exporter | P1 | 1 day | Go deps | ❌ |
| 8 | Composable SMTP check/modify/deliver pipeline | P1 | 2 weeks | Feature | ✅ Implemented (33 tests, admin + CLI) |
| 9 | Adopt `mail-parser` + `mail-auth` in `mail-core` | P1 | 5 days | Rust deps | ❌ |
| 10 | Per-user spam model training | P1 | 2 weeks | Feature | ✅ Bundled with #4 |

**Total remaining effort:** 2.5 days (maintenance: items 1-3, 7) + 5 days (mail-parser/mail-auth in Rust) = **~1.5 weeks**.
