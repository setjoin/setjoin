# Security — Implementation Status

This document describes the email security stack implemented in Phase 7.
All features are live in the Go gateway and PL/pgSQL reducers.

> **Protocol Audit (May 2026):** 587 findings across 24 protocols remediated.  
> **Database Query Audit (May 2026):** Full codebase audit completed — 33 findings across 4 rules. See `docs/specs/DATABASE_SECURITY.md` for enforced query standards.  
> **Compliance rules:** `.opencode/rules/email-auth.md`, `smtp.md`, `tls.md`  
> **RFC references:** `docs/rfcs/rfc7208-spf.md`, `rfc6376-dkim.md`, `rfc5321-smtp.md`  
> **OWASP references:** [[reference-owasp-security-standards]], [[reference-cwe-authorization]]
> **WORM compliance:** `docs/specs/WORM_COMPLIANCE.md` — SEC 17a-4(f), FINRA 4511(c), CFTC 1.31(c)-(d)

## Implemented Features

| Feature | Status | Location |
|---|---|---|
| SPF (RFC 7208) | ✅ Implemented — 30% → 85% compliance | `gateway/internal/smtp/spf.go` |
| DKIM (RFC 6376) | ✅ Verification + Signing — 18% → 75% compliance | `gateway/internal/smtp/dkim.go` |
| DMARC (RFC 7489) | ✅ Policy enforcement — 32% → 70% compliance | `gateway/internal/smtp/dmarc.go` |
| Anti-spam | ✅ Heuristics + RBL | `gateway/internal/smtp/antispam.go` |
| Greylisting | ✅ SQL + SMTP RCPT TO | `sql/schema/021_greylist.sql` |
| ClamAV | ✅ clamd integration (fixed May 2026) | `gateway/internal/smtp/clamav.go` |
| TLS | ✅ Implicit TLS + STARTTLS on 25/587/465/993 | `gateway/internal/smtp/*.go`, `gateway/internal/imap/imap.go` |
| DLP | ✅ Outbound content policy | `sql/schema/024_dlp.sql`, `sql/reducers/send.sql` |
| Rate limiting | ✅ Sliding window | `sql/schema/022_rate_limit.sql` |
| WORM immutability | ✅ S3 Object Lock compliance mode (SEC 17a-4(f), FINRA, CFTC) | `gateway/internal/storage/worm.go`, `docs/specs/WORM_COMPLIANCE.md` |
| S/MIME + PGP | ✅ Detection only | `gateway/internal/smtp/crypto.go` |
| DNS timeouts | ✅ 5s deadline on all Lookup calls | `gateway/internal/smtp/helpers.go` |

---

## Architecture

**Go gateway** handles all network I/O: DNS lookups, TLS termination, ClamAV socket communication, regex parsing.

**PL/pgSQL reducers** handle policy decisions: scoring thresholds, counter updates, queue management, state tokens.

This division keeps `deliver()` deterministic and testable without network access.

---

## SPF (7.1) — RFC 7208

Implemented in `gateway/internal/smtp/spf.go`.

### Protocol compliance improvements (May 2026)

- **Case-insensitive matching:** All mechanism names lowercased before comparison (§4.6)
- **v=spf1 detection:** Case-insensitive via `strings.ToLower()` before `HasPrefix` (§4.5)
- **Multiple records:** Returns `permerror` if domain has >1 SPF TXT record (§4.5)
- **NXDOMAIN → none:** DNS NXDOMAIN returns `none` instead of `temperror` (§4.3)
- **Null MAIL FROM:** Uses EHLO/HELO identity for bounce/DSN messages (§2.4)
- **DNS lookup count:** ≤10 total DNS mechanism lookups enforced (§4.6.4)
- **ptr + exists mechanisms:** Both implemented (§5.5, §5.7)
- **Macro expansion:** Basic support for `%{s}`, `%{l}`, `%{o}`, `%{d}`, `%{i}`, `%{h}` (§7)

### Mechanisms supported
`ip4:`, `ip6:`, `a`, `mx`, `ptr`, `exists`, `include:`, `redirect=`, `all`

### Results
`pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`

---

## DKIM (7.2) — RFC 6376 / RFC 8301 / RFC 8463

Implemented in `gateway/internal/smtp/dkim.go`.

### Protocol compliance improvements (May 2026)

- **SignDKIM wired:** Function was dead code — now called in outbound delivery path via `signDKIM()`
- **Body hash validation:** `bh=` verified against canonicalized body hash (§3.4)
- **Body canonicalization:** Simple and relaxed modes with correct CRLF handling
- **Header canonicalization:** Simple + relaxed + header unfolding (§3.4.1-3.4.2)
- **rsa-sha1 rejection:** Returns `DKIMPermErr` per RFC 8301 §3.1
- **Key size enforcement:** Sub-1024-bit RSA keys rejected per RFC 8301 §3.2
- **Ed25519 support:** `ed25519-sha256` verification per RFC 8463
- **Tag completeness:** `t=`, `x=`, `i=`, `l=`, `q=`, `z=` parsed and generated

### Inbound verification
- Parses `DKIM-Signature` header
- Looks up public key at `<selector>._domainkey.<domain>`
- Supports RSA-SHA256, Ed25519; rejects RSA-SHA1 and sub-1024-bit keys
- Validates `bh=` body hash with canonicalization
- Result stored in `messages.dkim_result`

### Outbound signing
- `SignDKIM()` called in `deliverOne()` → `signDKIM(ctx, item, rawMsg)` in `outbound.go`
- Queries `domain_signing_keys` for the sender's domain
- Generates `DKIM-Signature:` header with `t=` and `x=` timestamps
- Wired into outbound delivery before `deliverToMX()`

---

## DMARC (7.3) — RFC 7489

Implemented in `gateway/internal/smtp/dmarc.go`.

### Protocol compliance improvements (May 2026)

- **Relaxed alignment:** `adkim`/`aspf` tags parsed; organizational domain match (§3.1)
- **Policy tree walk:** Walks exact domain → organizational domain on NXDOMAIN (§6.6.3)
- **pct enforcement:** Sampling applied to policy enforcement (§6.6.4)
- **Temperror handling:** DNS temp errors return `DMARCTempErr` instead of `DMARCNone`
- **TXT concatenation:** Multi-character-string records concatenated (§6.6.2)

- Looks up `_dmarc.<domain>` TXT record
- Checks SPF and DKIM alignment with `From` header domain
- Policy actions:
  - `reject` → SMTP 550 rejection before `deliver()`
  - `quarantine` → message proceeds but can be routed to spam
  - `none` → no action, result logged for reporting
- Result stored in `messages.dmarc_result`

### DMARC Reporting (RFC 7489 §7)

Implemented in `gateway/internal/smtp/dmarc_report.go` (Wave 14, May 2026).

**Aggregate reports (rua):**
- `RecordDMARCResult()` called on every inbound delivery — upserts per-domain/per-day counters into `dmarc_reports` table
- `DMARCReportWorker` goroutine runs every 24h — builds RFC 7489 §7.2 XML, enqueues as outbound email via `outbound_queue`
- `parseRUA()` extracts email from `mailto:user@example.com!10m` format
- Schema: `sql/schema/034_dmarc_reports.sql` — per-domain/per-day aggregation + forensic_reports table

**Admin monitoring (Wave 15):**
- `GET /admin/dmarc/live` — current-day pass/fail/none/temperror counts + per-domain breakdown
- `GET /admin/dmarc/failures` — last 100 DMARC failures with SPF/DKIM details
- `GET /admin/dmarc/trend` — 30-day trend data for charts
- Web UI at `/admin/dmarc` — stats cards, per-domain table, trend bar chart, failures list with 30s auto-refresh option

**Domain DMARC configuration (Wave 15):**
- `domains.dmarc_rua`, `domains.dmarc_ruf`, `domains.dmarc_pct` columns for per-domain report settings
- Admin domains page supports editing rua/ruf/pct fields
- DNS wizard generates DMARC records with rua/ruf embedded

### Admin Monitoring Dashboard (Wave 15)

Implemented in `gateway/internal/handlers/admin_monitor.go`.

**Unified live stats endpoint:** `GET /admin/monitor/live?sections=dmarc,queue,volume,threats,system`
- DMARC: pass/fail/none live counts from `dmarc_reports`
- Queue: pending/deferred/bounced from `outbound_queue`
- Volume: received/sent/bytes 24h from `messages` + `outbound_queue`
- Threats: RBL blocks, auth failures, top virus names from `message_trace` + `quarantined_messages`
- System: goroutines via `runtime.NumGoroutine()`

---

## MTA-STS / TLS-RPT / DANE (RFC 8461 / 8460 / 7672 — Wave 17)

Implemented in `gateway/internal/smtp/mtasts.go`, `tlsrpt.go`, `dane.go` (May 2026).

### MTA-STS (RFC 8461) — Downgrade-resistant SMTP Transport

1. DNS TXT: `_mta-sts.{domain}` → discovers policy host
2. HTTPS GET: `https://mta-sts.{domain}/.well-known/mta-sts.txt` → fetches policy
3. Parse: `version STSv1`, `mode enforce|testing|none`, `mx`, `max_age`
4. Cache: in-memory `sync.RWMutex` with `max_age` expiry
5. Enforce: in `enforce` mode, skip MX hosts not in policy list
6. VerifyConnection callback on outbound TLS config for PKIX-TA validation

### TLS-RPT (RFC 8460) — TLS Session Reporting

1. DNS TXT: `_smtp._tls.{domain}` → discovers rua reporting endpoint
2. Session recording: `RecordTLSSession()` after every delivery attempt
3. Failure classifier: `classifyTLSError()` maps to RFC 8460 result types
4. Daily aggregation: `TLSRPTWorker` → builds JSON per §3 → HTTPS POST
5. SMTP fallback via `outbound_queue`

### DANE / TLSA (RFC 7672) — DNS-Based Certificate Pinning

1. DNSSEC-aware: `github.com/miekg/dns` with EDNS0 DO flag
2. TLSA lookup: `_25._tcp.{mx-host}` — RR type 52
3. Validate: all 4 usage modes (PKIX-TA, PKIX-EE, DANE-TA, DANE-EE)
4. Enforce: TLSA records present → STARTTLS MANDATORY (§3.1.2)
5. DNSSEC errors: AD flag + Rcode checks for secure/indeterminate/bogus

### DNS Wizard Records

| Record | Format |
|---|---|
| MTA-STS | `_mta-sts.example.com IN TXT "v=STSv1; id=..."` |
| TLS-RPT | `_smtp._tls.example.com IN TXT "v=TLSRPTv1; rua=mailto:..."` |

---

## ClamAV + Virus Quarantine (7.6 + Wave 12)

Implemented in `gateway/internal/smtp/clamav.go` and `gateway/internal/handlers/admin_quarantine.go`.

### ClamAV Integration

- **Command protocol:** Uses `nINSTREAM`, `nPING`, `nVERSION` (fixed from broken `z` prefix, May 2026)
- **Unix socket support:** Auto-detects path prefix (`/` or `.`) for local socket connections
- **Connection pooling:** Caches connections for 30s with `sync.Mutex` — no per-scan TCP open
- **Health check:** `clamav.Ping()` called on `InboundServer.Start()` — warns if unavailable
- **systemd:** ClamAV daemon listening on port 3310 with persistent DB volume

### Quarantine System (May 2026)

Virus-infected messages are no longer rejected at SMTP level. Instead:
1. **Accept & store** — message delivered normally (stored in SeaweedFS + messages table)
2. **Tag swap** — Inbox tag replaced with Quarantined tag (system, exclusive group `quarantine`)
3. **Quarantine record** — INSERT into `quarantined_messages` table with virus name + preview token
4. **All Mail exclusion** — Quarantined messages excluded from All Mail virtual view (same as Trash/Spam)

**Schema:** `sql/schema/033_quarantine.sql`
- `quarantined_messages` table: `message_id`, `mailbox_id`, `original_tag`, `reason`, `reason_type`, `virus_name`, `preview_token`, timestamps, release/reject info
- `mailboxes.quarantine_self_service` column (per-mailbox toggle, default TRUE)
- Tags `exclusive_group` extended with `'quarantine'` value

**API endpoints:**
| Endpoint | Access | Purpose |
|---|---|---|
| `GET /admin/quarantine` | Admin | List all (filter by status, search by from/subject) |
| `GET /admin/quarantine/stats` | Admin | Active/released/rejected counts |
| `GET /admin/quarantine/{id}/preview` | Admin | Sanitized HTML safe preview |
| `POST /admin/quarantine/{id}/release` | Admin | Release to user's inbox |
| `POST /admin/quarantine/{id}/reject` | Admin | Permanent delete |
| `GET /quarantine` | User | List own quarantined messages |
| `GET /quarantine/count` | User | Count (for inbox sidebar badge) |
| `POST /quarantine/{id}/release` | User | Release to inbox (self-service) |
| `POST /quarantine/{id}/reject` | User | Delete (self-service) |

**Webmail UI:**
- **Admin:** `/admin/quarantine` — table with status filter, stats bar, preview modal, release/reject buttons
- **User:** `/quarantine` — self-service table with preview/release/reject
- **Sidebar:** Inbox shows "Quarantined (N)" badge when count > 0

## Anti-spam (7.4)

Implemented in `gateway/internal/smtp/antispam.go`.

**RBL/DNSBL checks**
- Checks `zen.spamhaus.org`, `bl.spamcop.net`, `b.barracudacentral.org`
- Each hit contributes +2.0 to spam score

**Heuristic scoring**
- Missing `Message-ID`: +1.0
- Missing `Date`: +0.5
- HTML-only body: +1.0
- Suspicious subject keywords: +1.5
- All-caps subject (>70%): +1.0

Score and symbols stored in `messages.spam_score` and `messages.spam_headers`.
`deliver()` routes to Spam tag if score >= threshold (default 5.0).

## Greylisting (7.5)

Implemented in `sql/schema/021_greylist.sql`.

- Unlogged `greylist` table tracks `(client_ip, sender, recipient)` triplets
- First attempt → insert, return 450 temporary failure
- Retry after 5 minutes → accept and whitelist
- `greylist_whitelist` table for bypass entries
- Wired into SMTP inbound at `RCPT TO` stage

## ClamAV (7.6)

Implemented in `gateway/internal/smtp/clamav.go`.

- Connects to clamd via TCP (default port 3310)
- Uses `zINSTREAM` protocol for scanning
- Virus detected → SMTP 550 rejection before `deliver()`
- `zPING` and `zVERSION` for health checks
- Configured via `CLAMAV_ADDR` env var

## TLS (7.7)

Implemented in SMTP and IMAP servers.

- **Implicit TLS**: dedicated ports (SMTP 465, IMAP 993)
- `SetTLS(certFile, keyFile)` on `InboundServer` and `imap.Server`
- MinVersion TLS 1.2, X25519 + P-256 curve preferences
- Uses same certificate files as HTTPS gateway (`TLS_CERT`, `TLS_KEY`)

## DLP (7.9)

Implemented in `sql/schema/024_dlp.sql` and `sql/reducers/send.sql`.

- `dlp_policies` table with regex patterns, keywords, file type blocks
- `dlp_check()` function evaluates outbound messages
- Actions: `block` (RAISE EXCEPTION), `warn`, `quarantine`, `notify_admin`
- Violations logged to `dlp_violations` table
- Runs in `send()` after Sent insert but before outbound queue

## Rate Limiting (7.10)

Implemented in `sql/schema/022_rate_limit.sql`.

- Unlogged `rate_limit_counters` table with sliding windows
- `rate_limit_check(key, max_attempts, window_min, block_min)`
- SMTP submission: 10 attempts per 5 min per IP, 5 per 15 min per account
- Auto-block with exponential backoff

## S/MIME + PGP (7.8)

Partially implemented in `gateway/internal/smtp/crypto.go`.

- `DetectCrypto()` identifies S/MIME and PGP envelopes from `Content-Type`
- Full sign/encrypt/decrypt operations deferred to future phase

---

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `SMTP_INBOUND_ADDR` | SMTP MTA port | `:25` |
| `SMTP_SUBMISSION_ADDR` | SMTP MSA port | `:587` |
| `IMAP_ADDR` | IMAP port | `:143` |
| `SMTP_INBOUND_TLS_ADDR` | SMTP implicit TLS | `''` (disabled) |
| `IMAP_TLS_ADDR` | IMAP implicit TLS | `:993` when `TLS_CERT`/`TLS_KEY` are configured; non-loopback IMAP configuration is rejected without that certificate pair |
| `TLS_CERT` | TLS certificate file | `''` |
| `TLS_KEY` | TLS private key file | `''` |
| `CLAMAV_ADDR` | clamd TCP address | `''` (disabled) |

---

## Testing

Run all tests (short mode skips DNS lookups):

```bash
cd mailserver/gateway
go test ./... -short
```

Run with DNS tests:

```bash
go test ./...   # includes SPF and DMARC DNS lookups
```

---

## Deferred Security Findings (May 2026 Auth Audit)

These findings were confirmed during the May 2026 comprehensive auth endpoint audit
(36 findings verified by 37-agent workflow). They are deferred because they require
cross-cutting infrastructure changes rather than localized fixes. Tracked here so
they are not forgotten.

| ID | Finding | Blocked By | Target Phase |
|----|---------|------------|--------------|
| **H8** | ~~No domain-scoped authorization — `user_admin` has unrestricted global scope identical to `super_admin`. The `Claims` struct has zero domain-related fields, and `RequireRole` performs no domain-boundary check.~~ **CLOSED — resolved by the Phase 16 identity/RBAC work.** `Claims` now carries `DomainScope`, populated from the role-union authority chain (`mailserver/internal/auth/chain.go` `resolvePermissions`, mirroring the authserver's JWT domain-scope mint), and domain boundaries are enforced downstream: handlers read the caller's scope via `middleware.DomainScopeFromContext` and every admin query/mutation folds it in (`admin_scope_within` / `admin_can_reach` / `($1 <= 0 OR domain_scope = $1)` predicates). | Closed — no longer blocked. | Resolved (Phase 16 shipped; row retained for the audit trail) |
| **M2** | Refresh endpoint body contains only `refresh_token` (no email/username), so the threat interceptor's `extractMeta` can't extract a username for lockout escalation. Only IP-based protection applies to the refresh endpoint. | Threat interceptor must decode the refresh token to extract the email claim, or the refresh endpoint must accept an optional email field. | Phase 15 (API/HA/Ops) or next security hardening pass |
| **M6** | ~~JIT (Just-In-Time) provisioning has no server-side email verification. SAML ACS lacks `email_verified` check entirely. `updateSSOEmail` silently overwrites email on every SSO login with no notification or audit event.~~ **CLOSED as N/A.** SetJoin IS the mail server — JIT creates the user's mailbox, no external address exists to send verification to. The IdP is the trust anchor; if the admin doesn't trust their IdP, they shouldn't federate with it. `email_verified` SAML attribute check is a protocol-level concern, not an email verification challenge. | — | — |

### Resolution criteria

- **H8**: ~~`Claims` struct gains `DomainID` and `DomainScope` fields. `RequireRole` enforces domain boundaries for non-`super_admin` roles. Admin CRUD handlers respect domain scoping.~~ **Met — closed.** Evidence: `mailserver/internal/auth/chain.go` `resolvePermissions` (populates `claims.Permissions` + `claims.DomainScope`), `middleware.DomainScopeFromContext` (per-request scope extraction), and the admin enforcement predicates `admin_scope_within` / `admin_can_reach` / `($1 <= 0 OR domain_scope = $1)` (see `access_reviews.go`, `admin_users.go`, `admin_departments.go`).
- **M2**: Refresh handler extracts username from the decoded refresh token payload, or the threat interceptor gains a token-aware extraction path.
- **M6**: Closed as N/A. JIT verification is circular for a self-hosted mail server (no external address exists pre-provisioning). SAML `email_verified` attribute check is a protocol concern handled by the IdP, not an email verification challenge. `updateSSOEmail` should still emit an audit event — tracked as a separate Phase 16 improvement.
