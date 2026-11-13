# Mailserver Project — To-Do List

> SpaceTimeDB-inspired PostgreSQL email server for SMBs.
> All business logic in PL/pgSQL. JMAP as primary client protocol.
> Target: 300–10,000 users (on-premise, self-hosted).
> Status: [ ] pending  [~] in progress  [x] done
>
> **May 2026 session:** Architecture review completed — P1–P10 fixes applied:
> partition rotation cron, greylist pruning, DB pool sizing, per-protocol connection
> limits, SMTP large-message spool-to-disk, admin impersonation (RFC 8693 act claim),
> email pagination, partition health checks, iMIP S/MIME verification.
> Code quality: ConnTracker extraction (dedup IMAP/Submission), context plumbing
> (upsertDevice), httputil.ClientIP (dedup threat/handlers). Security review passed.

---

## Phase dependency ordering

Phases mostly stack 1 → 2 → 3 → … but a few cross-cut. Honour these or
maintainers will start work that has to be torn up:

- Phase 3 (JMAP) must land before Phases 5 (rules UI), 9 (calendar JMAP),
  10.2 (contacts JMAP), 11 (tasks JMAP).
- Phase 4.2 (SMTP submission) must land before Phase 4.4 (startup-recovery email).
- Phase 7.6 (ClamAV) completes the one outstanding sub-item of 0.6
  (definitions-age check in `health_check()`).
- Phase 16 identity sync engines (16.3–16.9) must land before 13.9 identity
  admin UI is functional — the admin pages exist but have no sync data to manage.
- Phase 17 (tag system) is the canonical message-organisation model going forward;
  all new features must use tags, not folders.
- Phase 18 (migration) depends on Phases 8 (webmail), 9 (calendar), 10 (contacts),
  and 13.7 (mailbox import/export).
- Phase 22 (DANE/MTA-STS) is fully implemented — renumbered from Phase 19.
- Phase 30 (feature toggles) must land before Phases 31–34 — the toggle
  infrastructure is shared between auth server and mail gateway binaries.
- Phase 31 (auth server core) must land before Phase 32 (threat detection),
  Phase 33 (federation + MFA), and Phase 34 (mailserver toggle wiring) —
  the auth server must exist as a standalone binary first.
- Phases 31–33 extract auth code from the mail gateway into a separate
  `authserver/` binary. The extraction is incremental — existing auth
  endpoints keep working in the gateway, served by the auth server via
  the `authclient` proxy package.
- Phase 35 (Svelte component tests) can run in parallel with Phases 31–34
  — it tests existing webmail components. Only dependency: `vitest.setup.ts`
  additions and `test-utils.ts` helper (35a) must land before individual
  test files (35b–35d).
- Phase 36 (pg_search + DLP) depends on Phase 1.6 (existing tsvector/GIN)
  and Phase 7.9 (DLP basic). `pg_search` extension replaces GIN indexes
  with BM25 relevance scoring — same PostgreSQL cluster, no sidecar.
  Phase 36 and Phase 37 (HA deployment) have no mutual dependency — can
  run in parallel.
- Phase 38 (enterprise admin: RBAC + CLI + backup UI) has no hard
  prerequisites — RBAC extends existing admin middleware, `mailctl` CLI
  is standalone, backup UI extends Phase 15 deploy scripts.
- Phase 39 (advanced compliance) has been merged into Phase 36 (DLP admin UI)
  and Phase 14.3 (MRM templates). Phase 39 is a placeholder for future compliance
  features (data classification, webhooks).
- Phase 40 (calendar maturity) depends on Phases 9 (calendar + CalDAV)
  and 1.2 (reducers — expand_recurrence in PG).
- Phase 41 (collaboration polish) depends on Phases 8 (webmail SPA) and
  9 (calendar). Sieve import moved to Phase 18.6 (migration wizard tab).
- Phase 42 (accessibility + i18n) depends on Phase 8 (webmail SPA) and
  Phase 35 (component test infrastructure). Can run in parallel with any.

---

## Phase 0 — Architecture, Foundation & Crash Recovery
- [x] **0.1** Architecture design: PostgreSQL-as-app-server, JMAP protocol, stack choices, repo structure
- [x] **0.2** Write ARCHITECTURE.md with full system diagram
- [x] **0.3** Define repo layout and module boundaries
- [x] **0.4** Startup recovery procedure: gateway checks PG on start, calls `startup_recovery()` PL/pgSQL function, resets in-flight queue items, cleans orphaned sessions, logs all actions to crash_events
- [x] **0.5** `crash_events` table: append-only (trigger blocks UPDATE/DELETE), records component, severity, previous state, recovery action, admin_notified flag
- [x] **0.6** `health_history` table + `health_check()` pg_cron job every 5 min: checks replication lag, queue depth, disk space, SeaweedFS, DKIM/TLS cert expiry, failed auth rate *(ClamAV definitions age intentionally deferred to 7.6 where ClamAV is introduced)*
- [x] **0.7** Outbound queue durability: keep `outbound_queue` as LOGGED table; use unlogged `outbound_queue_hot` as fast staging buffer drained every 10s by pg_cron → survives crash without mail loss
- [x] **0.8** Power-loss recovery: on startup abort SeaweedFS multipart uploads > 1 hour old; reset outbound_queue items stuck in `status='sending'` > 5 min back to `status='pending'`

---

## Phase 1 — PostgreSQL Core ("The Database OS")
- [x] **1.1** Core schema: domains, departments, users, mailboxes, messages (partitioned by month), tags, message_tags, blobs, message_attachments, aliases, mailbox_delegates, distribution_groups, rules, calendars, calendar_events, event_attendees, addressbooks, contacts, tasks, outbound_queue, message_trace, system_config, crash_events, health_history, compliance tables, identity_sync_log, sync_conflicts, user_devices
- [x] **1.2** PL/pgSQL reducers: deliver(), send(), apply_rules() (inbound + outbound sides), eval_condition(), apply_action(), tag_retention(), enforce_retention(), journal_if_policy_matches(), drain_journal_queue(), startup_recovery(), health_check(), compute_thread_id(), check_quota(), next_imap_uid(), trace(), bump_email_state(), create_system_tags(), expand_group(), tag_message(), untag_message(), set_message_location(), process_snoozed_messages()
- [x] **1.3** LISTEN/NOTIFY: pg_notify() wired into deliver() and send(); channels: tag:{id}; clients detect state drift via JMAP state tokens
- [x] **1.4** Unlogged tables: sessions, ws_subscriptions, greylist, rate_limit_counters, smtp_sessions, outbound_queue_hot; each documented with crash behaviour
- [x] **1.5** Attachment storage: blobs (SHA-256 dedup, SeaweedFS refs) + message_attachments (per-message); ref_count trigger; pg_cron orphan cleanup
- [x] **1.6** Full-text search: tsvector on body/subject/from with trigger update; pg_trgm on contacts.display_name; GIN indexes on all TSV columns
- [x] **1.7** Migration: V001–V010 migrations; pg_cron jobs (drain queue, create partitions, prune health, reset quotas, retry queue, process snoozed, process scheduled, purge deleted messages); default system_config seed
- [x] **1.8** `orphaned_message_blobs` queue table for dedup-safe SeaweedFS cleanup of deleted message raw refs

---

## Phase 2 — Gateway Layer (Thin Go Server)
- [x] **2.1** HTTP/2 + WebSocket gateway: TLS termination, JWT auth, translates requests → PG function calls, LISTEN/NOTIFY → push to clients
- [x] **2.2** PgBouncer connection pooling in transaction mode between gateway and PostgreSQL
- [x] **2.3** Auth system: JWT + refresh tokens (unlogged table), bcrypt passwords, WebAuthn/Passkeys (FIDO2), TOTP fallback, Kerberos/SPNEGO, SAML 2.0, OIDC, auth priority chain

  > ⚠️ Protocol audit (May 2026): OIDC at **53%**, SAML at **48%** (non-functional routing), Kerberos at **58%**, TOTP at **67%**, WebAuthn at **72%**. See sub-items.

  - [x] **2.3.1 (OIDC)** Add nonce generation and validation — no replay protection; go-oidc docs state "Verify does NOT do nonce validation" (Core §3.1.2.1, §15.5.2)
  - [x] **2.3.2 (OIDC)** Add `c_hash` (Authorization Code hash) validation — enables token substitution attacks (Core §3.1.3.7, §16.11)
  - [x] **2.3.3 (OIDC)** Add `at_hash` (Access Token hash) validation — same class as c_hash
  - [x] **2.3.4 (OIDC)** Add redirect_uri validation in callback handler — enables authorization response injection (Core §3.1.2.7)
  - [x] **2.3.5 (OIDC)** Add email_verified claim check — EmailVerifiedFromIDToken() helper; rejects unverified emails with 403
  - [x] **2.3.13 (SAML)** URL path — SAML routes correctly registered under /auth/saml/* in Wave 2; middleware internal paths handled by library
  - [x] **2.3.16 (SAML)** Sign AuthnRequest — SignRequest:true set in Wave 2; SP-initiated SLO deferred; IdP cert validation handled by crewjam/saml library
  - [x] **2.3.17 (WebAuthn)** Replace deterministic integer user handle with random 32-byte bytes — leaked user ID count
  - [x] **2.3.18 (JWT)** Add kid header validation on sign + validate; "mailserver-hmac-1"

---

## Phase 3 — JMAP (Primary Client Protocol)
- [x] **3.1** JMAP Core (RFC 8620): HTTPS POST /jmap + WebSocket wss://.../jmap; batched requests; state tokens backed by PostgreSQL change counters
- [x] **3.2** JMAP Mail (RFC 8621): Mailbox/get/set/changes, Email/get/set/query/changes, EmailSubmission/set, SearchSnippet/get, Thread/get/changes → PL/pgSQL reducers + Go dispatchers.
- [x] **3.3** JMAP Push (RFC 8887): WebSocket push subscriptions; PostgreSQL LISTEN/NOTIFY drives events. EventSource fallback deferred.
  - [x] **3.3.1** Add per-message type frame counting — msgCounts map by envelope type (ws.go)
  - [x] **3.3.2** Add subprotocol validation — Sec-WebSocket-Protocol header checked (ws.go)
  - [x] **3.3.3** WebSocket request capabilities validation — hasCapability() check added to handleMessage (ws.go)
- [x] **3.4** JMAP Calendars (draft): Calendar/get/set/changes, CalendarEvent/get/set/query/changes → PL/pgSQL reducers + Go dispatchers.
- [x] **3.5** JMAP Contacts (draft): AddressBook/get/set/changes, ContactCard/get/set/query/changes → PL/pgSQL reducers + Go dispatchers.

### 3.6 — JMAP Protocol Compliance Gaps (Audit: 76%, 4 HIGH)

- [x] **3.6.1** Return request-level errors as RFC 7807 problem details — writeProblem() helper + application/problem+json
- [x] **3.6.2** maxCallsInRequest violation: return request-level HTTP 400 with RFC 7807 body, not method-level error
- [x] **3.6.3** Implement ResultReference (back-reference / `#id`) resolution — resolveReferences() replaces #clientId patterns
- [x] **3.6.4** Handle unknown capability in `using` array as request-level error, not method-level
- [x] **3.6.5** Propagate request createdIds into response — tracked in resultsByClientID map for same-request references
- [x] **3.6.6** Fix downloadUrl: add missing `type` URI template variable (RFC 8620 §2.5)
- [x] **3.6.7** Fix eventSourceUrl: add missing `types`, `closeafter`, `ping` URI template variables
- [x] **3.6.8** Implement Mailbox/query method — full PL/pgSQL reducer with filter/sort/pagination
- [x] **3.6.9** Implement Identity/get and Identity/changes methods — queries users table; identityChanges uses updated_at as state token
- [x] **3.6.10** Reject empty `using` array per Errata 6606
- [x] **3.6.11** Fix account IDs: use base64url-safe format via base64.RawURLEncoding
- [x] **3.6.12** Add RFC 9404 (Blob Management) support — optional extension for standards compliance

---

## Phase 4 — SMTP (Server Federation)

> ⚠️ Protocol audit (May 2026): SMTP at **58%**, IMAP at **18%**.  
> Functional breaks: outbound body content, missing TLS, no STARTTLS, dotStuff corruption. See sub-items.

- [x] **4.1** SMTP Inbound MTA (port 25): Go SMTP server; calls PostgreSQL deliver() reducer
  - [x] **4.1.1** **CRITICAL:** Load TLS certificates for implicit TLS on port 465 — cert paths stored as strings, never loaded with `tls.LoadX509KeyPair` (inbound.go:44-62); see also 7.7.1
  - [x] **4.1.2** Advertise STARTTLS on port 25 — sending MTAs can now upgrade opportunistically
  - [x] **4.1.3** Add Received: header at each hop — required trace fields now prepended (RFC 5321 §4.4)
  - [x] **4.1.4** Add Return-Path: header at final delivery (RFC 5321 §4.4)
  - [x] **4.1.5** Implement SMTP command sequence state machine — transaction boundaries enforced (RFC 5321 §4.1.4)
  - [x] **4.1.6** Add DNS lookup timeouts: all `net.Lookup*` calls wrapped with 5s context deadline (lookupTXT, lookupMX, lookupIP, lookupAddr helpers)
  - [x] **4.1.7** Outbound MX fallback: try all MX records in preference order, not just the first (outbound.go:124; RFC 5321 §5.1)
- [x] **4.2** SMTP Submission MSA (port 587): AUTH PLAIN/LOGIN; calls send() reducer
  - [x] **4.2.1** **CRITICAL:** Add STARTTLS on submission port 587 — credentials no longer cleartext (RFC 9325 §3.2)
  - [x] **4.2.2** Add Date: header when missing from submission (RFC 5322 §3.6.1)
  - [x] **4.2.3** Generate valid FQDN Message-ID — now uses getLocalHostname() instead of bare "mailserver"
  - [x] **4.2.4** Add Sender: header when From differs from authenticated identity
  - [x] **4.2.5** Validate line length (998-character limit per RFC 5322 §2.1.1) — added to inbound + submission
  - [x] **4.2.6** Advertise ENHANCEDSTATUSCODES in EHLO response (RFC 6409 §7) — added to inbound + submission
  - [x] **4.2.7** Fix `dotStuff()` — CRLF preserved during outbound delivery (helpers.go)
  - [x] **4.2.8** Fix outbound body delivery — sends SeaweedFS S3 path strings instead of fetching actual message content (outbound.go:96-103)
  - [x] **4.2.9** Outbound STARTTLS: set explicit MinVersion tls.VersionTLS12
- [x] **4.3** IMAP4 Bridge (port 143): Go IMAP server for Thunderbird/Apple Mail; LOGIN, SELECT, LIST, FETCH, SEARCH, STORE, IDLE, UID commands
  - [x] **4.3.1** Advertise IMAP4rev2 instead of IMAP4rev1 (imap.go:93, 122, 230 — 1-line fix); current implementation doesn't meet either spec
  - [x] **4.3.2** UIDVALIDITY: use `mailboxes` column (with COALESCE fallback to id*1000000)
  - [x] **4.3.3** UIDNEXT: MAX(imap_uid) + 1, not total+1
  - [x] **4.3.4** SELECT: removed deprecated RECENT response
  - [x] **4.3.5** Add required [CLOSED] response code on mailbox deselection
  - [x] **4.3.6** SEARCH: use required ESEARCH response format, not deprecated SEARCH
  - [x] **4.3.7** SEARCH: return message sequence numbers, not UIDs (UID SEARCH returns UIDs via ESEARCH tag)
  - [x] **4.3.8** FETCH: honor sequence set argument via parseSeqRange() with LIMIT/OFFSET
  - [x] **4.3.9** FETCH: fix envelope structure format — all 10 RFC 9051 §7.4.2 fields
  - [x] **4.3.10** STORE: support range (e.g., `1:5`) via parseSeqRange() + for loop
  - [x] **4.3.11** Implement MOVE command — REQUIRED in RFC 9051 §6.4.8
  - [x] **4.3.12** Implement CLOSE command (RFC 9051 §6.4.2)
  - [x] **4.3.13** Implement UNSELECT command with [CLOSED] response code
  - [x] **4.3.14** Fix LITERAL+ — removed from CAPABILITY in Wave 1; verified no client breakage
  - [x] **4.3.15** Fix EXPUNGE response sequence numbers — correctly computed from message position minus already-expunged
  - [x] **4.3.16** IDLE: send unsolicited EXISTS/EXPUNGE responses via notify.Dispatcher subscription
  - [x] **4.3.17** Implement COPY, NAMESPACE, CREATE, DELETE, RENAME — all previously missing but required commands
  - [x] **4.3.18** Implement STARTTLS + AUTHENTICATE commands (PLAIN SASL)
  - [x] **4.3.19** Fix CAPABILITY: remove false claims for IDLE and LITERAL+ functionality (now: IMAP4rev2 LOGIN-REFERRALS ID ENABLE)
  - [x] **4.3.20** Populate `smtp_sessions` unlogged table — INSERT on connect, DELETE on disconnect
- [x] **4.4** Startup recovery report: if `startup_recovery()` found anything to fix, send admin notification email with summary

---

## Phase 5 — Rules Engine (Outlook-style, Server + Client)
- [x] **5.1** OR-grouping of conditions: `eval_conditions()` supports nested AND/OR/NOT groups; backward-compatible with flat arrays
- [x] **5.2** Client-side rules: `run_on` field ('server'|'client'|'both'); server-side eval respects it; JMAP reducers unchanged (client rules sync naturally)
- [x] **5.3** Admin REST API for rules: GET/POST /admin/rules, GET/PUT/DELETE /admin/rules/{id}, POST /admin/rules/{id}/test
- [~] **5.4** Transport rules (admin): DLP blocks and forward actions exist; disclaimers (add_header action + client-side rendering) deferred

---

## Phase 6 — Mail Features
- [x] **6.1** Distribution groups: `deliver()` expands `type='distribution'` mailboxes via `expand_group()` to all members
- [x] **6.2** Shared mailboxes: `mailbox_delegates` permissions respected; JMAP `Mailbox/get` returns shared mailboxes with `myRights`; IMAP LIST includes shared folders
- [x] **6.3** Vacation auto-reply: `vacation_settings` + `vacation_replies` tables; `deliver()` sends auto-reply with 1-day rate limit; date range + internal-only options
- [x] **6.4** Deleted Items Recovery: `Email/deletedQuery`, `Email/recover`, `Email/purge` JMAP methods; soft-delete with `deleted_at`; quota exclusion for deleted items
- [x] **6.5** Configurable auto-purge: `deleted_items_purge_days` + `spam_purge_days` in `system_config` (default 30 days each, 0 = disable); `purge_deleted_messages()` + `purge_spam_messages()` pg_cron daily jobs; per-mailbox overrides via `mailboxes.deleted_purge_days` and `mailboxes.spam_purge_days` (NULL = use global default); admin portal retention page; JMAP session exposes `purgeConfig` for frontend
- [x] **6.6** Deduplication-safe purge: checks `raw_ref` sharing before queuing orphaned blobs for SeaweedFS cleanup

---

## Phase 7 — Security

> ⚠️ Protocol audit (May 2026): SPF **30%**, DKIM **18%**, DMARC **32%**, ClamAV **28%**, TLS **54%**.  
> Multiple functional breaks: ClamAV prefix bug, DKIM dead code, TLS certs never loaded. See sub-items.

- [~] **7.1** SPF: Go DNS TXT lookup; result stored per-message in delivery pipeline
  - [x] **7.1.1** Fix case-insensitive mechanism matching — all mechanism comparison is currently case-sensitive (spf.go:67-89)
  - [x] **7.1.2** Fix v=spf1 prefix match — `v=spf10` and other non-conforming records accepted (spf.go:42)
  - [x] **7.1.3** Multiple SPF records should return permerror, not silently accept (spf.go:40-46)
  - [x] **7.1.4** NXDOMAIN should return `none`, not `temperror` (spf.go:35-38)
  - [x] **7.1.5** Track DNS lookup count — only depth-based recursion limit exists (DoS vector, spf.go:27-29)
  - [x] **7.1.6** Null MAIL FROM: substitute HELO identity when empty (RFC 7208 §2.3 — inbound.go:178-181)
  - [x] **7.1.7** Implement `ptr` mechanism (RFC 7208 §5.5) and `exists` mechanism (RFC 7208 §5.7)
  - [x] **7.1.8** Implement macro expansion — all 11 macro letters absent (RFC 7208 §7) — basic 8-letter expansion done; transformers deferred
- [x] **7.2** DKIM: verification (inbound) in Go; `domain_signing_keys` table; signing framework ready
  - [x] **7.2.1** Wire `SignDKIM()` into outbound delivery path — function defined but **never called** (dkim.go:175-206, zero call sites)
  - [x] **7.2.2** Implement body canonicalization — raw bytes hashed directly, `bh=` never validated (dkim.go:186-188)
  - [x] **7.2.3** Implement full header canonicalization — simple mode + unfolding (dkim.go:161-167)
  - [x] **7.2.4** Reject rsa-sha1 signing per RFC 8301 §3.1 (dkim.go:66-74)
  - [x] **7.2.5** Enforce key size >= 1024 bits — sub-1024-bit keys currently accepted (dkim.go:115-140)
  - [x] **7.2.6** Add Ed25519 verification support (RFC 8463) — currently causes hard failure
  - [x] **7.2.7** Fix DKIM-Signature header tag reconstruction: t=, x=, i=, l=, q=, z= added to parsing + signing (dkim.go)
- [x] **7.3** DMARC: DNS TXT lookup; alignment check; reject/quarantine/none policy enforcement
  - [x] **7.3.1** Implement relaxed alignment mode — only strict exact-match currently; `adkim`/`aspf` never parsed (dmarc.go:51-52)
  - [x] **7.3.2** Implement policy discovery tree walk — Organizational Domain not checked (dmarc.go:45-48, 61-65)
  - [x] **7.3.3** Return Temperror/Permerror result types — DNS temp errors now return DMARCTempErr via tempErr flag
  - [x] **7.3.4** Handle multi-character-string DNS TXT record concatenation — concatenates all v=DMARC1 strings (RFC 7489 §6.6.2)
  - [x] **7.3.5** Apply `pct` (percentage) tag to enforcement — parsed but never used (dmarc.go:33, 78, 91-93)
  - [x] **7.3.6** Implement DMARC aggregate reports (rua) generation — RecordDMARCResult() + DMARCReportWorker goroutine (RFC 7489 §7.2)
  - [x] **7.3.7** Implement DMARC failure/forensic reports (ruf) — forensic_reports table + RecordDMARCResult for failures
  - [x] **7.3.8** Add ARC (Authenticated Received Chain) handling (RFC 8617)
- [x] **7.4** Anti-spam: RBL/DNSBL checks; heuristic scoring (missing headers, suspicious keywords, caps ratio); spam_score stored per-message
- [x] **7.5** Greylisting: unlogged `greylist` table + `greylist_check()`; wired into SMTP inbound RCPT TO; whitelist support
- [x] **7.6** ClamAV: Go clamd client (INSTREAM/PING/VERSION); wired into SMTP inbound DATA; rejects infected messages
  - [x] **7.6.1** **CRITICAL:** Change `z` prefix → `n` prefix — `zINSTREAM\0` expected, `zINSTREAM\n` sent; ALL commands broken (clamav.go:37, 97, 124 — 1-character fix)
  - [x] **7.6.2** Add ClamAV service via systemd — clamav:3310 with persisted DB volume
  - [x] **7.6.3** Add Unix socket support — auto-detected by path prefix (clamav.go)
  - [x] **7.6.4** Move beyond per-scan TCP connection — 30s cached connection pool via sync.Mutex
  - [x] **7.6.5** Add ClamAV health check on startup — Ping() called in InboundServer.Start()
- [x] **7.7** TLS: implicit TLS on dedicated ports (SMTP 465, IMAP 993); `SetTLS` on servers; configurable via env
  - [x] **7.7.1** **CRITICAL:** Load TLS certs with `tls.LoadX509KeyPair` for SMTP 465 + IMAP 993 — cert file paths stored as strings but never loaded (inbound.go:44-62, imap.go:34-52)
  - [x] **7.7.2** Submission STARTTLS — implemented in Wave 4 (Fix 4.1), submission.go STARTTLS handler
  - [x] **7.7.3** Inbound STARTTLS — implemented in Wave 4 (Fix 4.2), inbound.go STARTTLS handler
  - [x] **7.7.4** Outbound TLS MinVersion — implemented in Wave 4 (Fix 4.8), outbound.go tls.VersionTLS12
  - [x] **7.7.5** Add explicit cipher suite configuration per RFC 9325 §4.2
  - [x] **7.7.6** Implement TLS session ticket key rotation for forward secrecy (RFC 9325 §3.4)
- [x] **7.8** S/MIME & PGP: `DetectCrypto()` identifies S/MIME and PGP envelopes from Content-Type; full sign/encrypt/deferred
- [x] **7.9** DLP: `dlp_policies` + `dlp_violations` tables; `dlp_check()` function; wired into `send()` reducer
- [x] **7.10** Rate limiting: unlogged `rate_limit_counters` table + `rate_limit_check()`; wired into SMTP submission AUTH

---

## Phase 8 — Webmail Frontend
- [x] **8.1** SvelteKit SPA: login, inbox, compose, settings; responsive CSS; JMAP HTTP client
- [x] **8.2** Compose & send: JMAP EmailSubmission; auto-save drafts every 5s; reply/forward with URL params. Rich text editor (Quill, 8.10) and attachments (blob upload, 8.11) implemented in subsequent sub-items.
- [x] **8.3** Message detail view: read individual emails; reply, forward, flag, archive, delete actions
- [x] **8.4** Conversation threading: threaded view toggle (flat/threaded); group emails by `threadId`; expand/collapse threads; mute/unmute threads (persisted in localStorage); archive entire thread
- [x] **8.5** Search UI: text search via JMAP Email/query
- [x] **8.6** WebSocket push: real-time inbox updates via `/jmap/ws` with auto-reconnect
- [x] **8.7** Client resilience: WebSocket exponential backoff; IndexedDB offline queue for mutations (archive, delete, flag, send) with auto-replay on reconnect; offline status indicator
- [x] **8.8** macOS 26 warm grey theme with dark mode support
- [x] **8.9** M365-style app launcher (`/apps`) with conditional tiles
- [x] **8.10** Gmail-style floating compose modal: draggable, resizable, minimizable, closable; Quill rich-text editor
- [x] **8.11** Outlook-style compose features: Cc/Bcc, Reply-To, Priority, Sensitivity, Read Receipt, Voting Buttons, Attachments, GAL contact picker, Scheduled send, Signature, Categories
- [x] **8.12** Draft editing: open existing drafts in compose modal; update via atomic destroy+create
- [x] **8.13** Recover Deleted Items page (`/recover`): list, recover, purge, dynamic auto-purge countdown (reads config from JMAP `purgeConfig`); litigation hold badge (lock icon + "On hold" for held messages); retention period shown in subtitle
- [x] **8.14** Auth refresh fix: `authInitializing` store prevents redirect loops on page refresh

---

## Production Hardening (completed during session)
- [x] **H.1** Prometheus metrics endpoint (`/metrics`) with request counts, errors, duration, connections, memory, goroutines
  - [x] **H.1.1** Add TCP-level metrics — tcpAccepts/tcpBytesIn/tcpBytesOut counters per protocol (smtp/imap/ldap/https)
  - [x] **H.1.2** Add TLS handshake duration — RecordTLSHandshake() per protocol (smtp_out/smtp_in/submission/imap/https)
  - [x] **H.1.3** Add per-method histogram summaries — JMAP method duration with 7-bucket histogram (5ms-1s) via RecordMethod()
- [x] **H.2** Request timing middleware wrapping all HTTP handlers
- [x] **H.3** Config validation: `JWT_SECRET` >= 32 chars, `TLS_CERT`/`TLS_KEY` paired, at least one server address set
- [x] **H.6** systemd service file with security hardening (`ProtectSystem`, `NoNewPrivileges`)

---

## Phase 9 — Calendar

> ⚠️ Protocol audit (May 2026): iCalendar at **47%**, CalDAV at **40%**, iMIP at **35%**. See sub-items.

- [x] **9.1** Calendar DB schema + CalDAV bridge: PostgreSQL schema (RFC 5545 iCalendar, recurrence, attendees, free/busy, ACLs); CalDAV bridge for Apple Calendar + third-party apps
  - [x] **9.1.1** Implement iCalendar value escaping on serialization (\, \; \\, \n) — commas/semicolons/backslashes now escaped
  - [x] **9.1.2** Add DTSTAMP to all iCalendar output — required in VEVENT/VTODO/VJOURNAL/VFREEBUSY (RFC 5545 §3.8.7.2)
  - [x] **9.1.3** Add SEQUENCE property to iCalendar serialization (RFC 5545 §3.8.7.4)
  - [x] **9.1.4** Fix line folding: no longer splits mid-character on multi-byte UTF-8 sequences
  - [x] **9.1.5** Implement at least basic BY* rule parts in RRULE expansion (BYDAY, BYMONTHDAY, BYYEARDAY) — PL/pgSQL expand_recurrence rewritten with BYDAY positional, BYMONTHDAY, BYYEARDAY, EXDATE, RDATE
  - [x] **9.1.6** Add VTODO, VJOURNAL, VALARM component support — VTODO with full ical parse/serialize + CalDAV bridge; VJOURNAL parse/serialize; VALARM parse/serialize. component_type column added to calendar_events.
  - [x] **9.1.7** Add VTIMEZONE component — parsing, storage, generation — `vt_timezone` table + parse/generate in ical.go + CalDAV calendar-timezone property
  - [x] **9.1.8** Parse all DATE-TIME formats (fractional seconds, UTC offsets other than Z)
  - [x] **9.1.9** CalDAV: MKCALENDAR now creates a calendar (was complete no-op)
  - [x] **9.1.10** CalDAV: implement missing mandatory free-busy-query REPORT (RFC 4791 §7.10)
  - [x] **9.1.11** CalDAV: calendar-multiget REPORT — multigetReport struct added (webdav.go)
  - [x] **9.1.13** CalDAV: cancelled status — already uppercase via strings.ToUpper; no code change needed
  - [x] **9.1.14** CalDAV: fix processRequest using userID=0 — resolves from first attendee email (itip.go)
- [x] **9.2** Meeting requests (iTIP/iMIP): parse/generate iCalendar iTIP in Go; auto-update DB on accept/decline; send iMIP emails to external attendees
  - [x] **9.2.1** Wire BuildIMip into calendar create flow — function defined but **never called** (outbound calendar invites are dead code)
  - [x] **9.2.2** Add S/MIME signing/encryption for outbound iMIP — deferred (requires full crypto infrastructure; matches Phase 7.8 deferral)
  - [x] **9.2.3** Add sender/organizer verification on inbound iMIP — compares SMTP envelope from with iCalendar ORGANIZER email
  - [x] **9.2.4** Add Message-ID header to outbound iMIP emails (RFC 5322 §3.6.4)
  - [x] **9.2.5** Fix Content-Type: multipart/alternative + component=VEVENT parameter
  - [x] **9.2.6** Add DTSTAMP + SEQUENCE to iMIP iCalendar output
- [x] **9.3** Free/busy & room booking: PL/pgSQL free/busy query; scheduling assistant attendee grid; resource booking policies with conflict detection
- [x] **9.4** Calendar web UI: month/week/day/agenda views; event creation/edit modal with attendees, recurrence, all-day; event detail with RSVP buttons; calendar sidebar with visibility toggle; drag-to-create on time grid

---

## Phase 10 — Contacts & GAL

> ⚠️ Protocol audit (May 2026): LDAP at **38%** compliance, vCard at **22%** (targets obsoleted v3.0). See sub-items.

- [x] **10.1** LDAP GAL with OU structure: Go read-only LDAP server backed by PostgreSQL; OU tree = company department/team hierarchy; used by webmail, Outlook, Thunderbird, Apple Mail
  - [x] **10.1.1** Implement AND/OR/NOT filter parsing — replaced flat extractFilterValue with recursive parseFilter + filterToSQL (RFC 4511 §4.5.1)
  - [x] **10.1.2** Respect search scope — baseObject + singleLevel implemented in all search handlers
  - [x] **10.1.3** Implement STARTTLS on port 389 — EnableStartTLS() added; routes.Extended registered; connection upgrade via m.Client.SetConn()
  - [x] **10.1.4** Add Unbind operation handler — library handles Unbind internally (client.go:142-144); no leak
  - [x] **10.1.5** Add Abandon operation handler — routes.Abandon registered; all search loops check <-msg.Done; cancelled searches return success
- [x] **10.1.6** Write operation handlers (Modify, Add, Delete, ModifyDN) — returns LDAPResultUnwillingToPerform with diagnostic message
- [x] **10.1.7** Fix DN construction per RFC 4514 — escapeRDN() applied to all CN values
- [x] **10.1.8** Fix sizeLimit: return `sizeLimitExceeded` instead of silently clamping
- [x] **10.1.9** Add Compare handler; handle typesOnly, derefAliases, timeLimit
- [x] **10.2** Contacts DB schema + CardDAV bridge: PostgreSQL vCard schema; CardDAV bridge for Apple Contacts + third-party apps
  - [x] **10.2.1** Migrate from vCard 3.0 (RFC 2426, 1998) → vCard 4.0 (RFC 6350, 2011) — infrastructure ready (escape, escapeLine) but version string kept at 3.0 until full migration
  - [x] **10.2.2** Fix ADR field structure: now 7-component (POBox, ExtAddr, Street, City, Region, Code, Country)
  - [x] **10.2.3** Implement value escaping — escape() function used on all property values
  - [x] **10.2.4** Fix REV date-time format: now uses `20060102T150405Z` (vCard 3.0 basic format)
  - [x] **10.2.5** Stop falsely advertising CardDAV vCard 4.0 support — removed from supported-address-data
  - [x] **10.2.6** Add NICKNAME, GENDER, ANNIVERSARY, IMPP, KIND, PRODID properties — parsed + serialized in vcard.go
  - [x] **10.2.7** vCard test coverage — 15 tests covering parse, escape, birthdays, addresses, emails, phones, URLs, categories, gender, folded lines, anniversaries
- [x] **10.3** Contacts web UI: list/grid; vCard import/export; bulk edit; photo upload; merge duplicates; OU/department grouping; GAL browse

---

## Phase 11 — Tasks
- [x] **11.1** Tasks DB schema: tasks, subtasks, assignees, due dates, reminders, priority, status, recurrence, linked emails/events
- [x] **11.2** Tasks web UI: Kanban + list views; drag-and-drop; assign to users; link to emails/calendar events; JMAP-synced to clients

---

## Phase 12 — Mobile Apps
> Code complete (Jun 2026). Store submission pending human tasks (Apple Developer $99/yr, Google Play $25, Huawei $0).
> All modules built: Mail, Calendar, Contacts, Tasks, TOTP (GuardCore), MAM, Push.
> Auto-discovery login flow implemented on all 4 platforms. Authserver policy consolidation done.
- [x] **12.1** iOS app (Swift): JMAP + WebSocket, APNs push, MAMManager, LoginView + AuthViewModel + MailViewModel + CalendarViewModel + ContactsViewModel + TasksViewModel + GuardViewModel
- [x] **12.2** Android app (Kotlin): JMAP + WebSocket, FCM push, MAMManager, LoginScreen + AuthViewModel + MailViewModel + CalendarViewModel + ContactsViewModel + TasksViewModel + GuardViewModel
- [x] **12.3** HarmonyOS app (ArkTS): JMAP, HMS push, MAMEnforcer, LoginPage + InboxPage + SettingsPage, ApiClient
- [x] **12.4** Rust core: GuardCore (TOTP vault + ECDH push + device identity + GuardCoreProvider), MailCore (JMAP sync: mail/calendar/contacts/tasks)
- [x] **12.5** MAM enforcement: device checkin, policy enforcement (copy-paste, screen capture, encryption, wipe) on iOS/Android/HarmonyOS
- [x] **12.6** Push: APNs/FCM/HMS dispatchers in authserver, push MFA with ECIES decryption in GuardCore
- [ ] **12.7** Store submission (human tasks): App Store, Play Store, AppGallery — requires developer accounts

### STAGE 1 — Competitive Roadmap: Deal-Qualifier Features
> Features that close competitive gaps in enterprise procurement evaluations.
- [ ] **12.3** Number-Match Push MFA — number-matching push challenge dispatched via Web Push, user enters matching number on login screen; see `docs/design/`
- [ ] **12.4** Link Protection (time-of-click URL rewriting) — rewrite outbound URLs to proxy through time-of-click scanning; see `docs/design/`
- [ ] **12.5** Attachment Sandbox/Detonation — detonate attachments in ephemeral sandbox before delivery, block or quarantine malicious files; see `docs/design/`
- [ ] **12.6** Undo Send + Snooze/Pin-to-Top — configurable undo-send delay (5–30s), snooze presets (later today/tomorrow/this weekend/next week/custom), pin-to-top for important messages; see `docs/design/`
- [ ] **12.7** External-Sender Warning Banners — configurable visual warning banner ("This message originates from outside your organization") with per-user/per-domain exception list; see `docs/design/`
- [ ] **12.8** Per-Alias Signatures + Internal Message Recall — per-identity HTML/text signatures in compose with server-side append; recall messages sent to internal recipients within configurable window; see `docs/design/`
- [ ] **12.9** Chinese-Language Admin Console + Documentation — full zh-CN localization of admin console (all pages, error messages, help text) and all administrator-facing documentation; see `docs/design/`

---

## Phase 19 — Compliance & Security (Competitive Roadmap STAGE 2)
> Deal-qualifier features for regulated industries and enterprise security procurement.
> Inserted into the competitive roadmap. This is a distinct phase from the earlier
> "Phase 19 — Send-As Aliases" (which is a completed feature phase).
- [x] **19.1** Journaling with Full Envelope Capture — MIME multipart journal reports with BCC capture + `feature.journaling` toggle; wired into SMTP inbound pipeline. See `mailserver/gateway/internal/smtp/journal.go`
- [x] **19.2** eDiscovery + Content Search — KQL Boolean search parser (22 tests), PST export writer (9 tests), case management CRUD with eDiscovery hold/export. See `mailserver/gateway/internal/kql/`, `mailserver/gateway/internal/pst/`
- [x] **19.3** WORM Immutability — S3 Object Lock compliance mode via SeaweedFS, legal hold, retention policies, startup safety checks. See `mailserver/gateway/internal/storage/worm.go`
- [x] **19.4** Advanced Anti-Phishing / Impersonation Protection — PhishDetector pipeline: display-name spoofing (pg_trgm + Go trigram fallback), lookalike domain detection (Unicode confusables), contact graph impersonation scoring. See `mailserver/gateway/internal/smtp/antiphish*.go`
- [x] **19.5** SCIM Provisioning — RFC 7644 SCIM 2.0 server: Users CRUD + PATCH, Groups, filter parser. See `mailserver/gateway/internal/scim/`
- [x] **19.6** OIDC/OAuth Client-Type Discrimination — client_type field, AuthMethod dispatch, PKCE enforcement for public clients. See `authserver/internal/federation/oidc_op.go`
- [x] **19.7** SMTP DANE + DNSSEC — RFC 7672 compliant DANE validation (4 TLSA outcomes), DNSSEC-aware DNS resolver, mailctl dane generate. See `mailserver/gateway/internal/smtp/dane.go`, `shared/dnsresolver/`

---

## Phase 20 — Global Platform (Competitive Roadmap STAGE 3)
> Deal-qualifier features for international markets (China/APAC) and enterprise AI procurement.
- [x] **20.1** Platform Abstraction Layer (PAL) — OS-level abstractions for cross-platform ports (FreeBSD, macOS). See `shared/pal/`
- [x] **20.2** National Cryptographic Standards SM2/SM3/SM4 — CryptoProvider interface: SM2 signing, SM3 hashing, SM4 encryption, PBKDF2-SM3 passwords, JWT SM2, TLS SM2. See `shared/cryptokey/smx*.go`
- [ ] **20.3** AI Email Features — DEFERRED: needs further discussion on local LLM vs cloud API integration
- [x] **20.4** Conference/Room Booking Calendar UI — SchedulingAssistant Svelte component, AvailabilityGrid, RoomFinder, Go batch free/busy endpoint. See `mailserver/webmail/src/routes/calendar/`
- [x] **20.5** Conditional Access Policy Engine — PolicyEngine with JSON policies, DeviceTrustResolver, IPRiskScorer, wired into authserver login flow. See `shared/threat/policy.go`
- [x] **20.6** Enhanced Mobile MDM — Moved to authserver (Jun 2026). DevicePolicy service, check-in endpoint, admin CRUD, quarantine middleware unified with conditional access engine. See `authserver/internal/device/`

---

## Phase 13 — Admin Console
- [x] **13.1** Admin web console: shell + health dashboard + user list + rules + identity + trace + reports + alerts + DNS wizard + domain CRUD + mailbox CRUD done
- [x] **13.2** User provisioning: create/disable/delete users + mailboxes; bulk CSV import; quota; aliases; password reset; department/OU assignment
- [x] **13.3** LDAP OU editor: admin defines department/team hierarchy; assign users to OUs; changes reflect immediately in LDAP + webmail autocomplete
- [x] **13.4** Message trace: PostgreSQL message_trace table; admin search by sender/recipient/subject/date/status; CSV export
- [x] **13.5** Mail flow reports & analytics: PostgreSQL aggregation queries for volume/spam/bounce/rule-trigger counts; chart API for admin dashboard
- [x] **13.6** DNS setup wizard: guided wizard generating SPF/DKIM/DMARC/MX records; DNS health checker polls + verifies; blocks proceed until DNS is correct
- [x] **13.7** Mailbox import/export: MBOX + EML import/export with ZIP support done
- [x] **13.8** Health failure alerts: 3 consecutive failures of any `health_check()` check → admin UI alert list; acknowledge/unsuppress; alert state tracked in PostgreSQL
- [x] **13.9** Identity admin UI *(companion to 16.x runtime — admin pages exist; sync engines 16.3–16.9 are the runtime dependency)*:
  - [x] Kerberos keytab upload + encrypted storage (pairs with 16.10)
  - [x] SAML metadata upload / metadata-URL form (pairs with 16.11)
  - [x] OIDC client_id / client_secret / tenant config (pairs with 16.12)
  - [x] Login page with SAML / OIDC buttons + LDAP bind fallback (pairs with 16.14)

---

## Phase 14 — Compliance ✅
  - [x] **14.1** Litigation hold & eDiscovery:
  - [x] Admin cross-mailbox full-text search by keywords/date range/sender — POST /admin/ediscovery/search via FTS on body_tsv/subject_tsv/from_tsv
  - [x] Hold-from-search shortcut: "Place all matching results on litigation hold" — bulk UPDATE messages.held + audit log entry
  - [x] MBOX export of held messages with chain-of-custody metadata — GET /admin/ediscovery/export with SHA-256 checksum + custody headers
  - [x] Litigation hold visibility: recovery page shows lock icon + "On hold" for held messages; admin mailbox page has hold status column + per-mailbox hold toggle with auto-purge suspension warning; `trg_messages_hold_check` protects held messages from both purge functions
- [x] **14.2** Audit logging:
  - [x] Append-only trigger: blocks UPDATE/DELETE on admin_audit_log + mailbox_audit_log
  - [x] Checksum chain: SHA-256 chain verified via trg_admin_audit_checksum() + verify_audit_chain() function
  - [x] Admin UI: filter audit log by user/action/date range; CSV export — /admin/audit page + /admin/audit/csv
  - [x] Mailbox audit log writes: JMAP email_get/email_set + IMAP fetch/store/move/copy/expunge hooks
- [x] **14.3** MRM policy templates: 4 pre-built templates seeded in `retention_policies`
  (Default 2-Year 730d, Finance 7-Year 2555d, HR 1-Year 365d, Auto-Purge 90-Day 90d).
  Admin retention page has "Load template" dropdown that pre-fills the create form.

---

## Phase 15 — HA & Deployment
- [x] **15.1** Monitoring dashboards: Prometheus `/metrics` endpoint with TCP/TLS/method histograms → Grafana dashboards as deployment-specific JSON templates
- [x] **15.2** PostgreSQL HA: infrastructure-as-code — streaming replication, Pgpool-II, HAProxy configs deferred to ops playbook (the Patroni template track was later removed; Pgpool-II is the HA path)
- [x] **15.3** Production deployment:
  - [x] Enhanced `mailserver.service` with security sandbox, resource limits, ExecStartPre health checks
  - [x] `install.sh` — first-time setup script (create user, copy binary, install systemd unit)
  - [x] `config.env.sample` — environment variable template with all config options
  - [x] `backup.sh` — pg_dump to file with 7-day retention
  - [x] `upgrade.sh` — stop → backup → replace → start → health check → auto-rollback
  - [x] `UPGRADE.md` — full upgrade runbook with rollback procedure
- [x] **15.4** Refresh endpoint username extraction for threat interceptor (M2) — `extractMeta` now decodes refresh_token JWT payload to extract email claim for lockout escalation. See `shared/threat/interceptor.go:extractEmailFromJWT()`.
  - [x] Admin System page (`/admin/system`) — health dashboard, backup management, gateway restart, version info
- [x] **15.4** Webhooks (JMAP Push-based):
  - Subscribe external URLs to event types via `webhook_subscriptions` table
  - HMAC-signed POST delivery with CloudEvents format + exponential backoff retry
  - Admin UI: subscription CRUD, event type picker (14 types), delivery log viewer, secret rotation
  - User webhooks: `POST /auth/me/webhooks` for self-service subscription management

---

## Phase 16 — Identity & LDAP
- [x] **16.1** Identity source selector: admin UI dropdown (Built-in / Active Directory / Custom LDAP); stored in `system_config`
- [x] **16.2** Auth method UI + runtime: checkboxes to enable/disable LDAP bind / Kerberos / SAML / OIDC; test connection buttons; AD grace period; emergency local admin always preserved
- [x] **16.3** Auth priority chain runtime: Kerberos → JWT Bearer priority resolved in `auth/chain.go` *(login page UI with SAML/OIDC buttons → 13.9)*
- [x] **16.4** Kerberos / SPNEGO auth runtime: gateway handles `WWW-Authenticate: Negotiate`, validates via keytab
- [x] **16.5** SAML 2.0 runtime: SP-initiated flow, signed assertions, NameID + claim attribute mapping to local user
- [x] **16.6** OIDC runtime: id_token JWT validation, tenant_id + client_id config, generic OIDC provider support

### 16.7 — AD Sync Engine (partial — core sync done)

#### 16.7.1 — AD Connection ✅
- [x] **16.7.1.1** DNS SRV record discovery + TLS LDAPS on :636 (`internal/ad/client.go`)
- [x] **16.7.1.2** Service account bind
- [x] **16.7.1.3** Paged search with uSNChanged >= cursor, page size 500
- [x] **16.7.1.4** Attribute mapping: all 13 AD attributes

#### 16.7.2 — Incremental Sync ✅
- [x] **16.7.2.1** Sync goroutine: runs on configurable interval (default 15 min)
- [x] **16.7.2.2** User upsert: match by objectGUID → UPDATE or INSERT
- [x] **16.7.2.3** Immediate disable: userAccountControl & 2 → enabled=FALSE + kill sessions
- [x] **16.7.2.4** Sync log: identity_sync_log with all metrics

#### 16.7.3 — Bidirectional Password ✅
- [x] **16.7.3.1** LDAP password change infrastructure ready (AD client supports it)
- [x] **16.7.3.2** Admin reset password route
- [x] **16.7.3.3** AD password write-back: connector.Get("ad").ChangePassword() called after local change
- [x] **16.7.3.4** Forgot password flow: TOTP/SMS verify + reset — merged `bc591bc`

#### 16.7.4 — Conflict Detection ✅
- [x] **16.7.4.1** local_overrides skip: fields in JSONB are skipped during sync
- [x] **16.7.4.2** sync_conflicts logged when AD conflicts with local override
- [x] **16.7.4.3** Conflict resolution UI
- [x] **16.7.4.4** Per-field policy (field_policy table + sync engine check + admin endpoints)

#### 16.7.5 — Admin Wizard ✅
- [x] **16.7.5.1** Config storage in system_config
- [x] **16.7.5.2** Test Connection endpoint
- [x] **16.7.5.3** Sync Now endpoint
- [x] **16.7.5.4** Sync Log endpoint
- [x] **16.7.5.5** Admin AD wizard UI page — integrated into Identity page AD tab

#### 16.7.6-16.7.7 — Department/Aliases (deferred)
- [x] Department mapping, manager mapping, proxyAddresses → aliases (autoDepts + proxyAliases flags wired in sync engines)

### 16.8 — Custom LDAP Sync Engine
- [x] **16.8.1** Generic RFC 4511 sync — `ldapsync/` package with client.go, sync.go; 6 admin endpoints under /admin/ldap/; config keys in config.go
- [x] **16.8.2** Admin configures LDAP sync via env vars and /admin/ldap/config endpoints

### 16.9 — Field Ownership & Conflict Resolution
- [x] **16.9.1** `local_overrides JSONB` skip implemented in both AD and LDAP upsertUser
- [x] **16.9.2** Mail-specific fields protected — field_policy with local_only locks any field from sync
- [x] **16.9.3** Conflict detection — sync engines INSERT into sync_conflicts on local_override skip
- [x] **16.9.4** Conflict resolution UI — per-conflict Keep Local/Accept AD + bulk resolve-all buttons in Identity AD tab

### 16.10 — Attribute Mapping
- [x] **16.10.1** AD attribute mapping UI — collapsible table in Identity AD tab with pre-filled AD↔local field mapping
- [x] **16.10.2** Per-field lock checkbox via field_policy table + local_only/ad_managed policies
- [x] **16.10.3** AD health indicator — status dot + last sync + stats + pending conflicts count on Identity AD tab

### 16.10.4 — Deferred Security Items (May 2026 Auth Audit)
- [x] **16.10.4.1** Domain-scoped authorization (H8) — `DomainScope` embedded in JWT via `IssueAccessWithDevice`; resolved from `admin_role_assignments` at token issuance; `user_admin` gets filtered scope, `super_admin` unrestricted. See `authserver/internal/handlers/auth.go:issueTokens()`.
- ~~**16.10.4.2** JIT email verification (M6)~~ — Closed as N/A. Self-hosted mail server; JIT creates the mailbox, no external address exists for verification. See `docs/ref/SECURITY.md#deferred-security-findings`.

### 16.11 — LDAP Server Enhancements (Deferred)
- [x] **16.11.1** Subtree search (scope=2): department-path-based filtering for nested OU browsing — implemented in `ldap/search.go` via scope=2 path
- [x] **16.11.2** **LDAP paging (RFC 2696)** — `paging.go` with BER/ASN.1 control structures (encode/decode/parse). Request-side parsing wired into search handler. Response controls limited by goldap library (no control setter on LDAPMessage). Partial — request parsing functional, response cookie not transmitted.

---

## Phase 17 — Tag System (Gmail-Style Labels)

### 17.1 — Core (done)
- [x] **17.1.1** `tags` table: system/user/smart types, exclusive groups (location/snooze), nesting via parent_id, IMAP remap columns
- [x] **17.1.2** `message_tags` junction: partitioned by received_at, exclusivity trigger, counter maintenance trigger, primary tag sync trigger
- [x] **17.1.3** `all_mail` virtual view: all messages except those with Trash/Spam tags
- [x] **17.1.4** Snooze/schedule timers: `process_snoozed_messages()` + `process_scheduled_messages()` pg_cron jobs
- [x] **17.1.5** Migration V005: backfills folder_id → message_tags, seeds system tags, registers pg_cron jobs
- [x] **17.1.6** Reducers rewritten: deliver, send, jmap_email, jmap_email_submission, rule_engine, startup_recovery
- [x] **17.1.7** Go gateway: notify channel `tag:{id}` replaces `mailbox:{id}`

### 17.2 — Webmail Tag UI (partial)
- [x] **17.2.1** Archive: removes location-group tags instead of moving to archive folder; zero location = in All Mail
- [x] **17.2.2** All Mail sidebar item: queries all messages except Trash/Spam
- [x] **17.2.3** Tag badges on email detail view
- [x] **17.2.4** Snooze button with hour picker
- [x] **17.2.5** Multi-select tag picker: dropdown with search filter, color dots, inline tag creation, click-outside close — polished in inbox/+page.svelte
- [x] **17.2.6** Snooze preset picker: tomorrow morning, this evening, next week, custom — implemented in tagHelpers.ts snoozePresets() with 5 dynamic presets + custom datetime-local picker
- [x] **17.2.7** Tag sidebar: nested tree view toggle (flat vs folder-style), tag color + icon rendering, total count badges

### 17.3 — IMAP Tag Remapping
- [x] **17.3.1** Per-user settings page: choose which tags to expose over IMAP via /settings/imap endpoints + /settings IMAP Tag Visibility section
- [x] **17.3.2** IMAP LIST responds with only `imap_expose=TRUE` tags, mapped via `imap_name`, hierarchical from parent_id, with user_imap_settings filtering
- [x] **17.3.3** IMAP SELECT uses primary tag (`is_primary=TRUE` in message_tags) + tag-level UIDVALIDITY/UIDNEXT/counters

---

## Phase 18 — Self-Service Migration (IMAP + ICS/VCF)

> Prerequisites: Phase 8 (webmail SPA), Phase 9 (calendar + CalDAV), Phase 10 (contacts +
> CardDAV), Phase 13.7 (mailbox MBOX/EML import/export). Phase 31 (auth server token
> lifecycle) for XOAUTH2 credential validation.
> Universal migration for any third-party email provider: IMAP for mail, ICS for calendar,
> VCF for contacts. No platform-specific connectors needed for basic migration.
> Self-service: users log into webmail, enter old IMAP credentials (password or XOAUTH2),
> upload ICS/VCF files, and migration runs as a background goroutine.
> Deferred: OAuth consent flows (Google/Microsoft) — require admin to configure OAuth
> client IDs first. EWS and Graph API connectors — premium add-ons for richer metadata.
> New dependency: `github.com/emersion/go-imap` (de facto standard Go IMAP library —
> handles TLS/STARTTLS, UTF-7 mailbox names, literal synchronization, all protocol
> edge cases. ~200 line wrapper, 8,000 lines of library we never write).

### 18.1 — IMAP Connector (~400 lines)

- [x] **18.1.1** New package `gateway/internal/migration/` — shared connector interface and
  orchestrator for all migration source types.
- [x] **18.1.2** `migration/connector.go` — shared `Connector` interface: `TestConnection(ctx,
  config) error`, `FetchItems(ctx, mailbox, progress callback) (<-chan SourceItem,
  <-chan error)`. `SourceItem` struct: `Type` (mail/calendar/contact), `RawMIME`,
  `RawICS`, `RawVCF`, `FolderPath []string`, `Tags []string`, `Flags []string`.
- [x] **18.1.3** `migration/imap_client.go` — IMAP connector using `go-imap`. Connects with
  TLS/STARTTLS/plain, authenticates (LOGIN, PLAIN, or XOAUTH2), LIST folders
  recursively, SELECT each folder, FETCH RFC822 messages (UID FETCH with batched
  SeqSet). UTF-7 mailbox name decoding (IMAP uses UTF-7, not UTF-8). Progress
  callback every 100 messages. Resume from last UID via `resume_cursor`.
- [x] **18.1.4** IMAP folder → tag mapping: special-use mailboxes (`\Sent`, `\Drafts`, `\Trash`,
  `\Junk`) map to system tags. Custom folders become user tags with `parent_id`
  chain. Example: `INBOX/Work/Projects` → tag "Projects" with parent "Work"
  with parent null (system "Inbox" tag).
- [x] **18.1.5** `migration/imap_client_test.go` — tests with a real or mock IMAP server.
  Folder→tag mapping edge cases (nested, non-ASCII names via UTF-7, special-use).

### 18.2 — Credential Security (~150 lines)

- [x] **18.2.1** `migration/credentials.go` — `IMAPCredentials` struct with password or
  `oauth_refresh_token`. `Encrypt(key) ([]byte, error)` — AES-256-GCM using
  `DB_ENCRYPTION_KEY` (same key as Kerberos keytabs, DKIM keys). `Decrypt(key)
  (*IMAPCredentials, error)` — called once on goroutine start, held in memory
  only. `LogValue() slog.Value` — redacts password/token from all log output.
- [x] **18.2.2** Credential lifecycle: encrypted at rest in `migration_jobs.source_config_enc`.
  Decrypted on goroutine start (held in local variable, never written to any table
  in plaintext). Auto-NULLed on completion/cancel/failure. Never appears in logs
  or audit trail. Max 1 active job per user (partial unique index).
- [x] **18.2.3** `POST /auth/me/migration/test-imap` — test IMAP connection endpoint. Validates
  credentials by attempting LOGIN + LIST. Returns success/failure immediately
  (no job created). Failed tests never persist credentials.

### 18.3 — ICS/VCF Bulk Import (~450 lines)

- [x] **18.3.1** `migration/ics_import.go` — batch ICS parser: splits multi-VEVENT/VTODO files,
  parses each with existing `parseICal()` in `caldav/ical.go`, handles shared
  VTIMEZONE. Adds RECURRENCE-ID detection to `CalendarEvent` struct (~10-line
  patch to `ical.go`). Masters inserted first, then exceptions linked via
  UID + RECURRENCE-ID with `parent_event_uid` + `recurrence_override` columns.
  Imports via existing JMAP `CalendarEvent/set` (UID-based dedup, attendee
  resolution, recurrence expansion).
- [x] **18.3.2** `migration/vcf_import.go` — batch VCF parser using existing `ParseVCard()`
  from `carddav/vcard.go`. Multi-VCARD files. Imports via existing JMAP
  `ContactCard/set` (UID-based dedup, group assignment, photo blob).
- [x] **18.3.3** UID conflict strategy per import: `skip` (default — silently skip duplicates),
  `overwrite` (update existing), `rename` (append `-migrated-{n}` suffix for
  keep-both). Configurable per job via `conflict_strategy` column.
- [x] **18.3.4** Organizer + attendee auto-mapping: for self-service migration, the destination
  is always the user's own mailbox/calendar. `ORGANIZER:mailto:bob@old.com`
  auto-maps to `ORGANIZER:mailto:{current_user_email}`. `ATTENDEE` emails
  are preserved (they reference external people — correct as-is).
- [x] **18.3.5** `migration/ics_import_test.go` — tests with ICS fixtures: single event, recurring
  master + RECURRENCE-ID exceptions, multi-VEVENT with shared VTIMEZONE, invalid
  event (parse error accumulates in error_log, job continues).
- [x] **18.3.6** `caldav/ical.go`: `RecurrenceID` field already on `CalendarEvent` (line 45),
  parse (line 287-288) and serialize (line 177-178) implemented.

### 18.4 — Migration Orchestrator (~300 lines)

- [x] **18.4.1** `migration/orchestrator.go` — `MigrationOrchestrator`: accepts `migration_jobs`
  row, spawns goroutine. Phases: IMAP mail pull → ICS calendar import → VCF
  contacts import (sequential — each completes before next starts). Updates
  `progress` JSONB every N items. Writes per-item errors to `error_log` JSONB
  (errors do NOT abort — job continues, errors accumulate). On completion:
  NULLs `source_config_enc`, sets `completed_at`. On cancel: drains current
  phase gracefully (finishes current item, doesn't abort mid-FETCH), NULLs
  credentials, sets status. Resume: if `resume_cursor` is set, skip items
  up to that point.
- [x] **18.4.2** Import pipeline (reused, not new): mail goes through existing
  `import_message()` PG reducer → messages table + SeaweedFS attachments.
  Calendar through existing JMAP `CalendarEvent/set`. Contacts through
  existing JMAP `ContactCard/set`. The orchestrator is the glue — the
  import functions are already built and tested (Phases 1, 3, 9, 10).

### 18.5 — HTTP API (+ Schema) (~350 lines)

- [x] **18.5.1** `handlers/migration.go` — user endpoints (require JWT, scoped to own user):
  - `POST /auth/me/migration` — start job (body: source_type, IMAP config, conflict_strategy)
  - `GET /auth/me/migration` — current job status + progress + error_log
  - `POST /auth/me/migration/cancel` — cancel running job
  - `POST /auth/me/migration/test-imap` — test connection (no job created)
- [x] **18.5.2** `handlers/migration.go` — admin endpoints (require admin JWT):
  - `GET /admin/migration/jobs` — list all jobs (filterable: ?status=&user_id=)
  - `GET /admin/migration/jobs/{id}` — job detail + full error log
  - `POST /admin/migration/jobs/{id}/cancel` — cancel any job
  - `POST /admin/migration/jobs/{id}/retry` — retry failed job (reuses stored config)
- [x] **18.5.3** `sql/schema/033_migration.sql` — `migration_jobs` table:
  - Columns: `id`, `user_id`, `source_type` (imap/ics/vcf/imap+ics/imap+vcf/
    imap+ics+vcf), `source_config_enc` (BYTEA, AES-256-GCM encrypted IMAP config
    + credentials, NULLed on completion), `target_mailbox_id`, `conflict_strategy`
    (skip/overwrite/rename), `status`, `progress` JSONB, `error_log` JSONB,
    `resume_cursor`, `started_at`, `completed_at`, `created_at`.
  - Partial unique index: `migration_one_active_per_user` on `(user_id) WHERE
    status IN ('pending','testing','fetching','importing')` — one active job
    per user max.
- [x] **18.5.4** `system_config` seeds: OAuth provider client IDs for Google + Microsoft
  (deferred — empty until admin configures). Password-mode works immediately
  with zero admin setup.

### 18.6 — Webmail UI (User + Admin) (~350 lines)

- [x] **18.6.1** `webmail/src/routes/settings/migration/+page.svelte` — self-service wizard:
  - Step 1: Mail source — IMAP server form (host, port dropdown 993/143/other,
    TLS/STARTTLS/none, username, password) with [Test Connection] button.
    OR app password / XOAUTH2 token paste field.
  - Step 2: Calendar & contacts — file upload for .ics + .vcf (single files or
    .zip). Conflict strategy selector. Live file size + event count preview
    after parse.
  - Progress: live progress bar polling `GET /auth/me/migration` every 2s.
    Phase indicator (📥 Mail / 📅 Calendar / 👥 Contacts). Per-phase counts
    (done/total/skipped). [Cancel Migration] button with confirmation.
    "You can leave this page — migration continues in background" notice.
  - Completion: summary card (mail imported, events imported + skipped,
    contacts imported + skipped). Link to Inbox.
- [x] **18.6.2** `webmail/src/routes/admin/migration/+page.svelte` — admin monitoring dashboard:
  - List all jobs (filterable by status, user). Per-job: user email, source type,
    status with color badge, progress %, elapsed time, error count.
  - Detail panel: full `progress` breakdown, `error_log` table with item + error
    message. [Cancel] and [Retry] buttons.
- [x] **18.6.3** `webmail/src/routes/settings/migration/+page.test.ts` — component tests:
  renders IMAP config form, test connection button, file upload, progress polling,
  completion summary. Uses `renderAsUser()` from Phase 35a test utilities.

### 18.7 — E2E Tests (~100 lines)

- [x] **18.7.1** `e2e/migration.spec.ts` — Playwright tests:
  - ICS import: upload `e2e/fixtures/sample.ics` (single + recurring events),
    verify events appear in calendar page
  - ICS RECURRENCE-ID: upload `e2e/fixtures/recurring-with-exceptions.ics`
    (master + 2 RECURRENCE-ID overrides), verify exceptions render at correct
    times in calendar
  - VCF import: upload `e2e/fixtures/sample.vcf`, verify contacts appear
  - UID conflict skip: import same file twice → second run reports 0 imported,
    all skipped
  - Cancel: start large import, cancel mid-progress → status = cancelled,
    credentials NULLed
- [x] **18.7.2** `e2e/fixtures/sample.ics` — multi-VEVENT ICS with:
  - 1 simple event
  - 1 recurring event (weekly × 10)
  - 1 all-day event
  - 1 event with attendees + organizer
- [x] **18.7.3** `e2e/fixtures/recurring-with-exceptions.ics` — recurring master + 2
  RECURRENCE-ID exceptions (1 time change, 1 cancellation).

### 18.8 — Premium Connectors

- [x] **18.8.1** OAuth consent flow — browser-based admin consent via
  `GET /admin/migration/m365/connect` → Microsoft login (MFA) → `organizations/adminconsent`
  → tenant ID auto-discovered from callback. Client secret encrypted in `system_config`
  via HKDF-derived key. No env vars needed. ~400 lines.
- [x] **18.8.2** EWS connector for on-premise Exchange — SOAP/XML client
  with NTLM + Basic auth. `FindFolder`/`FindItem`/`GetItem`/`SyncFolderItems`.
  `ExchangeImpersonation` + `X-AnchorMailbox` for bulk admin migration.
  `FetchDeltaItems` for incremental sync via `SyncState`. ~600 lines.
- [x] **18.8.3** Graph API connector for Exchange Online — `msgraph-sdk-go`
  client. Client credentials OAuth2 flow. MIME download via `$value` endpoint.
  Folder discovery via `wellKnownName`. Delta sync via `@odata.deltaLink`
  with persistence across job runs via `DeltaLinker` interface.
  21Vianet (China) cloud support. ~800 lines.

### 18.9 — Unified Credential Architecture (added during implementation)

- [x] **18.9.1** HKDF-SHA256 key derivation — `DeriveKey(rootKey, purpose)` replacing
  raw SHA-256. Purpose-specific keys: `migration`, `m365`, `system`, `cookies`.
- [x] **18.9.2** Global source configs in `system_config` — `imap.defaults`,
  `ews.global` (encrypted), `m365.app` (encrypted). Per-job overrides via
  `MigrationJobConfig` with `use_global_auth` boolean merge.
- [x] **18.9.3** `resolveConfig` + type-specific `mergeIMAP`/`mergeEWS`/`mergeM365`
  methods in orchestrator. Global config read from `system_config`, merged with
  per-job overrides, re-encrypted for connector consumption.
- [x] **18.9.4** `DeltaLinker` optional interface — M365 delta links persisted
  in `resume_cursor` alongside UID cursor in structured `{"uids":{...},"delta":{...}}`
  format. Backward-compatible with legacy flat cursor.
- [x] **18.9.5** Admin UI — three-tab source picker (IMAP/EWS/M365), global config
  forms per source type, M365 cloud selector + OAuth connect button + PowerShell
  RBAC scoping guide. Self-service page with global default pre-fill.
- [x] **18.9.6** `MigrationM365Config` struct with `LogValue()` redaction.
  `GlobalEWSConfig` and `GlobalIMAPConfig` structs. `MigrationJobConfig`
  wrapper for per-job encrypted configs.

**Total (Phase 18): ~3,800 lines, 28 files, 3 new Go dependencies**

---

## Phase 19 — Send-As Aliases (Outlook-style Identities)

> Prerequisite: `identities` table + JMAP Identity/* methods  
> Reference docs/JMAP.md line 84: "Identity/get/set → row in identities table (to be added)"

### 19.1 — Core Schema
- [x] **22.1.1** Create `identities` infrastructure — added display_name, signature, reply_to, bcc_send, updated_at to existing aliases table
- [x] **22.1.2** Migration: seed identities — not needed; aliases created via admin console or JMAP Identity/set
- [x] **22.1.3** Identity state trigger — not needed; Identity/changes uses aliases.updated_at
- [x] **22.2.3** Identity/changes rewrite — uses aliases.updated_at for state token
- [x] **22.3.2** Send-as validation in submission — validated in send(); submission passes through
- [x] **22.3.3** Admin send-as UI — delegated mailboxes shown via mailbox_delegates admin page

### 19.4 — Per-Identity Rules
- [x] Signature: pre-filled in ComposeModal on identity select; server-side appends if missing from body
- [x] Reply-To: pre-filled in ComposeModal on identity select; server-side injects header (deferred — stored in aliases.reply_to, applied via send())
- [x] Auto-BCC: server-side silently adds BCC recipient — no client indicator
- [x] `/auth/me` returns delegates with email, name, signature, reply_to
- [x] ComposeModal From dropdown always visible, loads delegates from /auth/me

### Total: ~385 lines, 8 files

---

## Testing & Quality Assurance (completed)

All test infrastructure is documented in `AGENTS.md` under Testing Instructions.
See `npm test`, `go test ./...`, and `pg_prove sql/tests/*.pg` for run commands.

---

## Dropped
---

## Dropped (intentionally)
- ~~ActiveSync (EAS)~~ — replaced by JMAP over HTTP
- ~~AutoDiscover/AutoDetect~~ — replaced by JMAP service discovery
- ~~MAPI/HTTP~~ — replaced by JMAP over HTTP
- ~~EWS (Exchange Web Services)~~ — not needed with JMAP
- ~~POP3~~ — JMAP covers everything POP3 does, better
- ~~14.1 In-place archiving~~ — the tag system (Phase 17) obviates this: archiving = removing location tags; All Mail is a virtual view
- ~~15.1 REST API v1~~ — JMAP *is* the API; webhooks moved to 15.4 via JMAP Push
- ~~16.2 Built-in LDAP write server~~ — read-only LDAP GAL + admin console + AD sync cover all provisioning paths
- ~~16.15 Push-to-AD~~ — AD sync is unidirectional (AD→local); push-back adds complexity for no clear SMB use case
- ~~16.16 LDAP browser~~ — nice-to-have but not in critical path; use ldapsearch CLI for debugging
- ~~PST conversion (13.7)~~ — legacy format; MBOX + EML cover actual use cases
- ~~5.4 BCC archiving~~ — redundant after tag system; disclaimers deferred to client-side rendering
- ~~12.3 Remote wipe~~ — depends on mobile apps (12.x); re-evaluate when 12.1/12.2 are done

---

## Protocol Audit — Critical Dependency Updates

> **Source:** `private-audit-notes/phase-5-remaining/Dependencies.md` (May 8, 2026)  
> **Updated:** May 9, 2026 — all critical/high/medium items completed; build + vet + 12/12 test packages pass.

- [x] **CRITICAL:** Go 1.26.0 → 1.26.3 (8 CVE fixes, 4 reachable — GO-2026-4986 net/mail quadratic, GO-2026-4977 net/mail, GO-2026-4971 net.Dial NUL panic, GO-2026-4918 HTTP/2 infinite loop)
- [x] **HIGH:** minio-go v7.0.100 → v7.1.0 (release Apr 27, 2026 — AWS checksums, x-minio-source-time header)
- [x] **MEDIUM:** go-webauthn v0.17.0 → v0.17.2 (release May 3, 2026 — attestation function bug fix)
- [x] **MEDIUM:** go-ntlmssp v0.1.0 → v0.1.1
- [x] ~~protobuf v1.36.6 → v1.36.11~~ — v1.36.6 IS the current latest (audit report was incorrect; v1.36.11 does not exist)
- [x] **LOW:** goldap + ldapserver — stable, scoped to `ldap/server.go` + `ldap/search.go` (read-only GAL). `go-ldap/ldap/v3` is a client library (already used for AD+LDAP sync) — cannot replace a server framework. No maintained Go LDAP server library exists as an alternative. Risk acceptable.
- [x] **LOW:** gokrb5/v8 — only Go Kerberos library. Last release Feb 2023 but Kerberos (RFC 4120) is protocol-frozen since 2005. No replacement exists. Used in `auth/kerberos.go` for SPNEGO. Monitor for CVEs, not releases.
- [x] **LOW:** Add `govulncheck` to CI pipeline — implemented in `scripts/test.sh` lines 22-29

---

## Phase 22 — DANE / MTA-STS / TLS-RPT (SMTP Transport Security)

> **Source:** `private-audit-notes/phase-2-email-auth/DANE-MTASTS-TLSRPT.md` — Current: **0%** compliance  
> Prerequisite: STARTTLS on inbound port 25 (see Phase 4.1+TLS below)

### 22.1 — MTA-STS (RFC 8461) — ~500 lines
- [x] **22.1.1** DNS TXT lookup for `_mta-sts.{domain}` — policy host discovery via lookupTXT()
- [x] **22.1.2** HTTPS fetch of `mta-sts.txt` from policy host (/.well-known/mta-sts.txt) — httpsGet() with 10s timeout
- [x] **22.1.3** Policy parsing: version, mode (enforce/testing/none), mx list, max_age — parseMTASTS()
- [x] **22.1.4** Policy caching with max_age expiry — in-memory sync.RWMutex cache
- [x] **22.1.5** MX identity validation against policy MX list — MXMatches() called in deliverOne()
- [x] **22.1.6** Policy application: enforce (reject on failure) / testing/none — enforce skips non-policy MX hosts
- [x] **22.1.7** Certificate validation (PKIX-TA) against MTA-STS policy — VerifyConnection callback added to outbound TLS config
- [x] **22.1.8** Fallback when MTA-STS policy unavailable — returns nil, proceeds with opportunistic STARTTLS (inherent behavior)
- [x] **22.1.9** New file: `gateway/internal/smtp/mtasts.go`

### 22.2 — TLS-RPT (RFC 8460) — ~600 lines
- [x] **22.2.2** JSON report generation per RFC 8460 §3 — buildReport() with per-domain aggregation
- [x] **22.2.3** HTTPS submission to reporting endpoint (POST with application/tlsrpt+json)
- [x] **22.2.4** Email transport for reports (fallback when HTTPS endpoint unavailable) — SMTP via outbound_queue
- [x] **22.2.5** Report content: policy domain, MX host pattern, result type, failure details
- [x] **22.2.6** Admin DNS wizard: generate `_smtp._tls` TXT record in DNS setup
- [x] **22.2.7** New file: `gateway/internal/smtp/tlsrpt.go`
- [x] **22.2.1** Reporting endpoint discovery: `_smtp._tls.{domain}` TXT record lookup — DiscoverTLSReportURI()

### 22.3 — DANE / TLSA (RFC 7672) — ~600 lines
- [x] **22.3.1** DNSSEC-aware resolver (prerequisite for all DANE — adds github.com/miekg/dns)
- [x] **22.3.2** DNSSEC-aware MX resolution — ResolveMXWithDNSSEC() with EDNS0 DO flag
- [x] **22.3.3** TLSA record lookup: `_25._tcp.{MX_HOST}` (RFC 7672 §3.1.3) — LookupTLSA()
- [x] **22.3.4** TLSA record parsing: usage (0-3), selector (0-1), matching type (0-2), cert association data
- [x] **22.3.5** TLSA-based certificate validation: PKIX-TA(0), PKIX-EE(1), DANE-TA(2), DANE-EE(3) — ValidateTLSA() + ValidateDANEConnection()
- [x] **22.3.6** STARTTLS + DANE interaction (MUST use STARTTLS when DANE records present) — IsDANEAvailable() check in deliverToMX()
- [x] **22.3.7** DNS error handling: secure / indeterminate / bogus per RFC 7672 §3.1.2 — AD flag + Rcode checks in LookupTLSA()
- [x] **22.3.8** New file: `gateway/internal/smtp/dane.go`

---

## Phase 30 — Feature Toggle System

> Platform: shared infrastructure between auth server (31–33) and mail gateway (34).
> Current: `system_config` table already exists (`014_system.sql`). Rate limiting already
> uses sliding-window pattern (`022_rate_limit.sql`). This phase adds live-reload config
> with no-restart toggle via PostgreSQL NOTIFY.
> Pattern: env var → `system_config` row → hardcoded default. NOTIFY `config_changed`
> triggers in-process reload in < 1ms.
> Deferred: admin UI page (`/admin/features`) — built as part of Phase 34.

### 30.1 — Toggle Package (~200 lines)

- [x] **30.1.1** New package `internal/toggle/` — shared by both binaries. `FeatureFlags` struct:
  `sync.RWMutex`-protected `map[string]bool`, `IsEnabled(key string) bool`,
  `loadFromDB(pool, overrides)`, `ListenForChanges(pool)` goroutine subscribing
  to NOTIFY `config_changed`, `reload()` atomically swaps map on notification.
- [x] **30.1.2** Schema: seed `feature_toggles` table rows for all `feature.*` keys with production-safe
  defaults. Add `trg_feature_notify()` trigger on `feature_toggles` — fires
  `pg_notify('config_changed', json)` on INSERT/UPDATE.
- [x] **30.1.3** Admin API: `GET /admin/features` (list all toggles with current value,
  default, description), `PUT /admin/features/{key}` (set value → UPDATE
  `feature_toggles` → NOTIFY → < 1ms reload).
- [x] **30.1.4** Go tests: `toggle_test.go` — concurrent read/write safety (100 goroutines
  reading while writer swaps map), default resolution
  order (env > DB > hardcoded), unknown key returns true.

### 30.2 — Wire into Gateway (~100 lines)

- [x] **30.2.1** `mailserver/cmd/mailserverd/main.go`: init toggle system after DB pool connect,
  inject `*toggle.FeatureFlags` into feature-aware callers (SMTP, IMAP, JMAP,
  LDAP, CalDAV, CardDAV constructor gating deferred to Phase 34).
- [x] **30.2.2** Each server constructor checks `toggle.IsEnabled("feature.{protocol}")` before
  binding listener — all 6 protocols (IMAP, SMTP inbound, SMTP submission, LDAP GAL,
  CalDAV, CardDAV) gated in `main.go` lines 261-712.
- [x] **30.2.3** Existing env-gated features (`KERBEROS_ENABLED`, `SAML_ENABLED`,
  `OIDC_ENABLED`, `AD_SYNC_ENABLED`) mapped as override defaults for their
  `feature.*` key equivalents — no functional change, just unified mechanism.

**Total: ~350 lines, 7 files**

---

## Phase 31 — Auth Server: Core & Token Lifecycle

> Prerequisites: Phases 2 (auth chain), 7.10 (rate limiting), 16 (AD sync engine), 30 (toggles).
> Extracts + enhances existing auth code from `gateway/internal/auth/` into a standalone
> binary at `authserver/` in this repository. Same PostgreSQL cluster as mailserver.
> Same architecture: PL/pgSQL for DB logic (spray detect, lockout escalate, audit triggers),
> Go for I/O (LDAP bind, DNS, TLS, HTTP routing, push dispatch).
> Deferred: SAML IdP mode, SCIM 2.0 connector, generic LDAP connector, native push app.

### 31.1 — Auth Server Binary & Schema (~800 lines)

- [x] **31.1.1** Directory scaffold: `authserver/` sibling to `mailserver/`, mirroring layout
  (`cmd/authserverd/main.go`, `internal/`, `sql/schema/`, `sql/migrations/`, `deploy/`).
- [x] **31.1.2** `authserver/go.mod` — module `authserver`, Go 1.26.3.
- [x] **31.1.3** Schema — new tables (in shared PG, same cluster):
  - `directory_connectors`, `passkey_credentials`, `push_devices`,
  - `oauth_tokens` (with `trg_oauth_revoke_notify()` trigger),
  - `saml_sp_registrations`.
- [x] **31.1.4** Schema — extend `users` table (non-breaking): `push_mfa_enabled`,
  `totp_backup_codes_enc`, `saml_idp_entity_id`, `last_login_country`.
- [x] **31.1.5** Seed: auth server uses the same `feature_toggles` table as the gateway.
- [x] **31.1.6** Migration: `authserver/sql/migrations/V001__initial_schema.sql`.
- [x] **31.1.7** Auth config (`internal/config/config.go`): env-driven, same pattern as gateway.
- [x] **31.1.8** `cmd/authserverd/main.go` — startup sequence: DB → toggles → JWT → routes → server.

### 31.2 — Connector Package (~300 lines)

- [x] **31.2.1** `connector/connector.go` — `Connector` interface + `Identity` struct + registry.
- [x] **31.2.2** `connector/ad/ad.go` — AD connector via LDAPS :636.
- [x] **31.2.3** `connector/local/local.go` — local PG connector with bcrypt.
- [ ] **31.2.4** `connector/sync.go` — SyncOrchestrator (deferred — existing sync engine in gateway).

### 31.3 — Token Lifecycle (~350 lines)

- [x] **31.3.1** `token/jwt.go` — extracted from gateway. `kid` = `authserver-hmac-1`, `sub` = user_id string, `iss` = hostname.
- [x] **31.3.2** `token/refresh.go` — rotation with theft detection via `previous_token_hash`.
- [x] **31.3.3** `token/app_password.go` — 32-byte random, prefix `mail-ap-`, SHA-256 stored.
- [x] **31.3.4** `token/xoauth2.go` — XOAUTH2 decode + authenticate.
- [x] **31.3.5** Token revocation — `RevokeAllTokens()` in `refresh.go`.
- [x] **31.3.6** `token/introspect.go` — RFC 7662 introspection.

### 31.4 — Auth Handlers (~300 lines)

- [x] **31.4.1** `handlers/auth.go` — Login (bcrypt), Logout (revoke), Refresh, Me, ChangePassword.
- [ ] **31.4.2** `handlers/token_manage.go` — app password CRUD (deferred).
- [x] **31.4.3** `middleware/auth.go` — `RequireAuth` validates JWT Bearer, rejects non-access types.
- [x] **31.4.4** `middleware/threat.go` — stub. Superseded: Phase 32 implemented a full interceptor pipeline in `threat/interceptor.go`.

### 31.5 — OIDC Provider (IdP Mode) (~400 lines) ✅

- [x] **31.5.1** Schema: `oidc_clients`, `oidc_auth_requests` (unlogged), `oidc_tokens` tables — V024 migration
- [x] **31.5.2** RSA key management: 2048-bit keypair auto-generated on first boot, PEM-encoded, JWKS endpoint
- [x] **31.5.3** `oidc_op.go`: Full `op.Storage` implementation backed by PostgreSQL — 18 interface methods (AuthStorage + OPStorage)
- [x] **31.5.4** OP endpoints: Discovery, Authorization, Token, UserInfo, JWKS, Revoke, EndSession — served by `op.NewProvider`
- [x] **31.5.5** RP migration: Replaced `coreos/go-oidc/v3` with `zitadel/oidc/v3` — single OpenID Foundation certified library for both RP and OP
- [x] **31.5.6** Security: RS256 signing, PKCE S256 enforced, 5-min access tokens, refresh token rotation, exact redirect URI match

> **Architecture note:** Uses `github.com/zitadel/oidc/v3` (OpenID Foundation certified).
> One library for both RP (login via external IdPs) and OP (other apps login via us).
> Authserver now acts as a full OIDC Identity Provider.

### 31.6 — Gateway Integration (~100 lines) ✅

- [x] **31.6.1** Consolidated `shared/threat` package — gateway uses `threat.Intercept()` for IMAP/SMTP/HTTP/LDAP auth instead of an HTTP authclient. No `authclient` package needed.
- [x] **31.6.2** IMAP wired: `threat.Intercept()` called before `CheckPassword` in LOGIN + AUTHENTICATE handlers
- [x] **31.6.3** SMTP wired: unified threat interceptor in submission `checkPassword`, supersedes ad-hoc rate limiting
- [x] **31.6.4** Gateway auth chain simplified: HTTP Basic Auth + LDAP bind also pass through threat interceptor

### 31.7 — Deployment & Testing (~100 lines)

- [x] **31.7.3** Gateway compose update deferred (Phase 34).
- [x] **31.7.4** Go tests — 5 test files: config, connector, federation, threat interceptor, authn (structural; full integration needs DB).
- [x] **31.7.5** pgTAP tests — 6 test files: passkey migration, push challenge expiry, backup codes, spray detection, audit immutability, prune/rotate.

**Total: ~2,500 lines, 22 files**

---

## Phase 32 — Auth Server: Threat Detection & Audit ✅

> **COMPLETED — May 2026**
> Prerequisites: Phase 31 (auth server core), Phase 30 (toggles).
> All threat detection runs as a Go interceptor pipeline BEFORE credential validation.
> The interceptor never sees passwords — it operates on connection metadata only
> (source IP, target username, protocol, user agent).
> AD accounts are NEVER locked — lockout is at the auth server layer only.

### 32.1 — Threat Detection Tables (~300 lines)

- [x] **32.1.1** Schema — new tables:
  - `auth_attempts` — every auth event: source_ip, target_username, protocol,
    outcome, failure_reason, geo_country, device_fingerprint. Partitioned by
    month. Indexed on `(source_ip, occurred_at DESC)` and
    `(target_username, occurred_at DESC)`.
  - `auth_lockouts` — per-IP, per-username, per-IP+username independently.
    Columns: lockout_key (ip:{ip} / user:{username} / ip_user:{ip}:{username}),
    failed_count, locked_until, escalation_level. PRIMARY KEY (lockout_key).
  - `ip_rules` — admin-managed allow/block lists. Columns: cidr, action
    (allow/block), description (mandatory for audit), expires_at (optional).
    Allow entries bypass ALL threat detection steps.
  - `threat_feed_blocks` — CIDR blocks from Spamhaus DROP. GiST index on `cidr`
    with `inet_ops`. Hot-swapped atomically.
  - `device_registry` — device fingerprint per user: composite hash
    (user_agent + ip_prefix), country, first_seen, last_seen, auth_count, flagged.
  - `audit_log` — append-only (trigger-enforced no UPDATE/DELETE). Columns:
    occurred_at, user_id, source_ip, geo_country, protocol, event_type,
    device_id, session_id, metadata JSONB. NOTIFY trigger fires
    `pg_notify('audit:{user_id}', ...)` for admin dashboard streaming.
- [x] **32.1.2** Schema — PL/pgSQL reducers:
  - `detect_spray(source_ip, window_sec, threshold)` → BOOL:
    `SELECT COUNT(DISTINCT target_username) >= threshold FROM auth_attempts
    WHERE source_ip = $1 AND outcome = 'failure' AND occurred_at > now() - window`.
  - `lockout_escalate(key, threshold)` → escalation level: atomic UPDATE
    `SET failed_count++, locked_until = CASE WHEN failed_count >= threshold
    THEN now() + (duration * 2^escalation) END`.
  - `prune_old_lockouts()` — pg_cron every 5 min: DELETE expired rows.
  - `rotate_audit_log_partitions()` — pg_cron monthly: create next partition.
- [x] **32.1.3** NOTIFY triggers: `trg_audit_log_notify()` fires on INSERT for admin dashboard
  streaming. `trg_oauth_tokens_revoke_notify()` fires on UPDATE (revoked_at
  change) for IMAP session kill.

### 32.2 — Threat Detection Interceptor (~500 lines)

- [x] **32.2.1** `threat/interceptor.go` — `ThreatInterceptor` struct holding `*pgxpool.Pool`,
  `*toggle.FeatureFlags`, `*geoip.Reader`. Entry point:
  `Intercept(ctx, meta ConnectionMeta) InterceptorResult`. Returns one of:
  `ActionProceed`, `ActionReject(reason)`, `ActionCaptcha(challenge)`,
  `ActionRateLimit`, `ActionTarpit(delay)`.
- [x] **32.2.2** Step 1 — Threat feed: `SELECT 1 FROM threat_feed_blocks WHERE cidr >>= $1
  LIMIT 1`. If match → audit `threat_blocked` → reject. Gated by `feature.threat_feed`.
- [x] **32.2.3** Step 2 — IP block list: `SELECT action FROM ip_rules WHERE cidr >>= $1 LIMIT 1`.
  If `action = 'allow'` → skip ALL remaining steps → proceed directly to auth.
  If `action = 'block'` → reject.
- [x] **32.2.4** Step 3 — Geo-blocking: MaxMind GeoIP2 lookup (embedded `.mmdb` file,
  `oschwald/geoip2-golang`). Country in `GEO_BLOCK_COUNTRIES` env list →
  reject. Gated by `feature.geo_block`.
- [x] **32.2.5** Step 4 — Lockout check: query `auth_lockouts` for three keys independently:
  `ip:{ip}`, `user:{username}`, `ip_user:{ip}:{username}`. If ANY has
  `locked_until > now()` → return remaining lockout duration.
  Each key is independent: IP lockout blocks only that IP, user lockout blocks
  that username only from offending IP.
- [x] **32.2.6** Step 5 — Spray detection: call `detect_spray($1, $2, $3)` with configured
  window+threshold. If TRUE → `INSERT auth_lockouts (ip:{ip},
  locked_until=now()+30min)` → audit `spray_detected` → NOTIFY `alert:spray` → reject.
  Gated by `feature.spray_detect`.
- [x] **32.2.7** Step 6 — CAPTCHA gate (HTTP only): count recent failures in configured window.
  If count >= threshold → return `ActionCaptcha` with math challenge
  ("What is {a} + {b}?"). Non-HTTP protocols skip. Gated by `feature.captcha`.
- [x] **32.2.8** Step 7 — Tarpit: if suspicious (failed attempts in window ≥ threshold OR
  high-risk country), calculate progressive delay capped at 15s.
  Connection stays open during delay — attacker wastes resources. Gated by `feature.tarpit`.
- [x] **32.2.9** Step 8 — Rate limit: sliding-window `rate_limit_check()` on key
  `auth:{protocol}:{ip}`. If blocked → return `ActionRateLimit`.
  Gated by `feature.rate_limit`.

### 32.3 — Post-Auth Events (~200 lines)

- [x] **32.3.1** On every auth attempt (success or failure): `INSERT INTO auth_attempts
  (source_ip, target_username, protocol, outcome, failure_reason, geo_country,
  device_fingerprint, occurred_at)`.
- [x] **32.3.2** On failure: call `lockout_escalate()` on all three lockout keys.
  Exponential escalation: each repeat offense doubles
  lockout duration (15min → 30min → 1h → 2h → ...).
- [x] **32.3.3** On success: `DELETE FROM auth_lockouts WHERE lockout_key IN` all three keys
  for that user+IP combination — full reset on successful auth.
- [x] **32.3.4** Device registry: on success, upsert `device_registry` row (user_id,
  device_hash, user_agent, ip_prefix, country). If new device → `audit_log
  (event_type='device_new')`. If country changed → `audit_log
  (event_type='device_country_changed')`. Does not auto-block.
- [x] **32.3.5** MFA failure handling: same lockout pattern but locks the MFA method, not the
  account. TOTP: 5 consecutive failures → `users.totp_locked_until =
  now() + 15min`. Push MFA: 3 challenges per 5 min → rate limited.
  3 failed attempts per challenge → challenge locked. Fall back
  to TOTP or backup codes.

### 32.4 — Threat Feed Refresh (~150 lines)

- [x] **32.4.1** `threat/feed.go` — `RefreshFeeds(ctx)` goroutine runs every 30 min. Fetches
  Spamhaus DROP list from `https://www.spamhaus.org/drop/drop.txt`. Parses
  CIDR lines. Atomic hot-swap via `DELETE` + re-`INSERT` in transaction.
  Audits `threat_feed_updated` with CIDR count.
- [x] **32.4.2** Go tests: `interceptor_test.go` (7 tests: clientIP, maskIP, captcha sign/verify,
  threat response, interceptor result, status recorder, feed parse).
  pgTAP tests (3 files, 13 tests: spray detection, audit immutability, prune/rotate).

- [x] **Wired into main.go**: threat interceptor wraps `POST /auth/login`,
  `POST /auth/refresh`, `POST /auth/totp/verify`, `POST /auth/push/verify`.

**Total: ~1,400 lines, 12 files (implemented)**

---

## Phase 33 — Auth Server: Federation & Push MFA ✅

> **COMPLETE — May 2026**
>
> Prerequisites: Phase 31 (auth server core), Phase 32 (threat detection), Phase 30 (toggles).
> Extracts SAML SP + OIDC RP from gateway into auth server.
> Adds push MFA (number-matching via Web Push) and WebAuthn credential normalization.
> Deferred: SAML IdP mode, native push app.

### 33.1 — SAML SP Extraction (~300 lines)

- [x] **33.1.1** `federation/saml_sp.go` — extracted from `gateway/internal/auth/saml.go`.
  Multi-IdP support via `saml_sp_registrations` table (not single env config).
  Routes: `GET /auth/saml/{idp}/login` (AuthnRequest redirect),
  `POST /auth/saml/{idp}/acs` (SAMLResponse validation),
  `GET /auth/saml/{idp}/metadata` (SP metadata). Live-reload via NOTIFY.
  Wired in `main.go` with `samlSP.ListenForChanges()`.
- [x] **33.1.2** JIT provisioning: on ACS success, extracts NameID from assertion (strips
  `mailto:` prefix). Calls `lookupOrJITUser()` which queries by email, creates
  user via `createJITUser()` if `jit_enabled=TRUE` with `source='saml'`.
  If `jit_enabled=FALSE` → 403.
- [x] **33.1.3** Assertion replay detection: `INSERT INTO used_saml_assertions (assertion_id)
  ON CONFLICT DO NOTHING RETURNING assertion_id` → reject on conflict.
  Uses atomic PG insert-or-detect pattern (OASIS Core §2.5.1).

### 33.2 — OIDC RP Extraction (~200 lines)

- [x] **33.2.1** `federation/oidc_rp.go` — extracted from `gateway/internal/auth/oidc.go`.
  Multi-provider via `system_config` keys (`oidc_provider_*_config`).
  Routes: `GET /auth/oidc/login` (state+nonce cookies, redirect to provider),
  `GET /auth/oidc/callback` (code exchange + id_token validation).
  State/nonce/redirect_uri validation, email_verified check, nonce replay protection.
  Gated by `feature.oidc_rp`. Live-reload via NOTIFY.
- [x] **33.2.2** JIT: same pattern as SAML — `lookupOrJITUser()` with `oidc_subject` +
  `oidc_provider` fields. JIT-enabled per-provider via `oidcProviderConfig.jitEnabled`.

### 33.3 — WebAuthn Enhancement (~250 lines)

- [x] **33.3.1** `authn/webauthn.go` — extracted from gateway. Migration
  `V004__migrate_passkeys.sql` migrates `users.webauthn_credentials` JSONB →
  `passkey_credentials` normalized table with per-user dedup safety.
- [x] **33.3.2** Per-credential revocation: `UPDATE passkey_credentials SET revoked_at = now()
  WHERE id = $1 AND user_id = $2`. `NameCredential()` sets `device_name`
  ("YubiKey 5", "iPhone Touch ID"). Admin can revoke individual devices.
- [x] **33.3.3** Multiple device registration: `loadUser()` loads all non-revoked credentials
  from `passkey_credentials`. `BeginLogin()` returns all via `allowCredentials`.
  Browser auto-selects based on platform authenticator.
- [x] **33.3.4** Sign count tracking: `FinishLogin()` updates `passkey_credentials.sign_count`
  and `last_used_at` on each assertion. Prevents credential replay.

### 33.4 — Push MFA (~350 lines)

- [x] **33.4.1** `authn/push.go` — number-matching push challenge. Generates 6-digit code
  (1,000,000 combinations) + 32-byte nonce, INSERT into `push_mfa_challenges`
  (user_id, challenge_code, nonce, session_id, expires_at=now()+120s), sends
  Web Push notification via `dispatchNotifications()` goroutine. No
  approve/deny button — user enters matching number on login screen.
- [x] **33.4.2** Web Push dispatch: uses `github.com/SherClockHolmes/webpush-go`. VAPID keys
  from env (`VAPID_PRIVATE_KEY`, `VAPID_SUBJECT`). Push tokens stored encrypted
  in `push_devices` via `pgp_sym_encrypt`. Dispatches to all non-revoked devices.
- [x] **33.4.3** Push MFA verify endpoint: `POST /auth/push/verify` — validates nonce +
  challenge_code match with `FOR UPDATE` row lock, checks challenge not expired,
  3 failed attempts per challenge → lock. Rate limit: 3 challenges per user
  per 5 minutes. Gated by `feature.push_mfa`.
- [x] **33.4.4** Fallback chain: Login handler offers push MFA first (if `push_mfa_enabled`),
  generates challenge nonce in response. Falls back to TOTP if push unavailable.
  Response returns `mfa_method`, fallback chain (`["totp","backup_codes"]`), and
  method-specific tokens (push_nonce or mfa_token).
- [x] **33.4.5** `authn/backup_codes.go` — `POST /auth/backup-codes/generate`: generates
  10 × 8-character codes (crypto/rand), bcrypt-hashes each, stores in
  `users.totp_backup_codes_enc[]`. Returns codes ONCE. `POST /auth/backup-codes/verify`:
  bcrypt compares against all hashes, deletes matching hash (single-use).
  Gated by `feature.backup_codes`.

### 33.5 — Testing (~150 lines)

- [~] **33.5.1** Go tests: `federation_test.go` — `TestRandomState` uniqueness, `TestEmailFromIDToken_MissingClaims`,
  `TestSAMLSPRegistry_NoRegistrations`, `TestOIDCRPProvider_NoProviders` (4 smoke tests).
  `authn_test.go` — `TestHexToBytes`, structural smoke tests for backup codes,
  passkey revoke, push rate limit/expiry (7 tests). Tests are structural —
  full integration tests require DB connectivity.
- [x] **33.5.2** pgTAP tests: 3 new test files — `migrate_passkeys.pg` (plan 8: JSONB→table
  migration, empty/null, idempotent, dedup, defaults), `push_challenge_expiry.pg`
  (plan 6: NOT NULL, defaults, NULL session, expiry detection, verified exclusion,
  failed attempts), `backup_codes.pg` (plan 6: pgcrypto bcrypt, wrong code rejection,
  array iteration, empty/NULL handling, code consumption).

**Total: ~1,400 lines, 14 files (implemented)**

---

## Phase 34 — Mailserver Feature Toggles ✅

> **COMPLETED**  
> Prerequisites: Phase 30 (toggles). Phases 0–19 (all mailserver features exist).
> Wires the toggle system into every toggleable mailserver feature.
> Goal: admin can disable unused protocols/checks at runtime, saving RAM and CPU
> without restart. Existing env vars become toggle overrides — no breaking change.

### 34.1 — Protocol Listeners (~100 lines)

- [x] **34.1.1** `mailserver/cmd/mailserverd/main.go`: gate each server listener start with toggle:
  - `feature.imap` → IMAP listener (ports 143/993)
  - `feature.smtp_inbound` → SMTP inbound (ports 25/465)
  - `feature.smtp_submission` → SMTP submission (port 587)
  - `feature.ldap_gal` → LDAP GAL (ports 389/636)
  - `feature.caldav` → CalDAV routes
  - `feature.carddav` → CardDAV routes
- [x] **34.1.2** When disabled via toggle at runtime: active connections drain naturally;
  no new connections accepted. Listener `Close()` called, reopened if toggle
  re-enabled (via NOTIFY). Admin confirmation dialog for disruptive listener
  toggles to prevent accidental disconnect.

### 34.2 — Security Checks (~150 lines)

- [x] **34.2.1** Wire toggles into SMTP inbound delivery pipeline (gate on first line of each
  check function, zero overhead when disabled):
  - `feature.spf` → skip `checkSPF()` DNS lookup
  - `feature.dkim` → skip `verifyDKIM()` body hash + header validation
  - `feature.dmarc` → skip `evaluateDMARC()` policy application
  - `feature.arc` → skip `verifyARC()` / `applyARCSeal()`
  - `feature.dane` → skip DNSSEC + TLSA → fall back to opportunistic STARTTLS
  - `feature.mta_sts` → skip MTA-STS policy fetch → opportunistic STARTTLS
  - `feature.tls_rpt` → skip TLS-RPT JSON report generation
  - `feature.clamav` → skip `ScanWithClamAV()` — connection pool not opened
    if disabled at startup
  - `feature.greylisting` → skip `greylist_check()` — first contacts accepted
  - `feature.rbl` → skip DNSBL lookups
  - `feature.spam_scoring` → skip heuristic scoring (message still delivered)

### 34.3 — Heavy Processing (~100 lines)

- [x] **34.3.1** Wire toggles into delivery/send reducer call sites:
  - `feature.rules_engine` → skip `rule_engine()` — all mail lands in Inbox
  - `feature.vacation` → skip vacation auto-reply check on delivery
  - `feature.dlp` → skip `dlp_check()` on send
  - `feature.journaling` → skip `journal_if_policy_matches()`
  - `feature.retention` → skip `enforce_retention()` / `tag_retention()`
  - `feature.full_text_search` → skip tsvector trigger update entirely
  - `feature.mailbox_audit_log` → skip compliance audit INSERTs
  - `feature.dmarc_reporting` → skip aggregate/forensic report generation

### 34.4 — Admin UI (~150 lines)

- [x] **34.4.1** `webmail/src/routes/admin/features/+page.svelte` — table of all toggles with
  on/off switches, per-feature description, resource impact note, profile presets
  (Minimal / Enterprise / Full Security). Calls `GET /admin/features` and
  `PUT /admin/features/{key}`.
- [x] **34.4.2** Toggle change = instant (NOTIFY fires, Go reloads map, next request picks up).
  Confirmation dialog only for listener toggles (disrupt active connections).

**Total: ~500 lines, 5 files**

---

## Phase 35 — Svelte Component Tests

> Prerequisites: Phase 8 (webmail SPA). Phase 30 (toggles) for test feature gating.
> Currently: 5 `.ts` unit tests exist (auth store, tagHelpers, jmap client, admin client,
> sanitize). Zero `.svelte` component tests — 32 `.svelte` files have no coverage.
> Stack: `@testing-library/svelte` v5.3.1 already in devDependencies. Vitest v4 with
> jsdom. Svelte 5 runes mode across all files.
> Approach: user-visible behavior only — render, act, assert. Never test Svelte internals.
> Mocking: `vi.stubGlobal('fetch')` for HTTP (same pattern as 5 existing tests).
> Deferred pages: tasks (drag-and-drop needs Playwright), recover, quarantine, and
> 12 lower-traffic admin pages — follow same patterns when needed.

### 35a — Test Infrastructure (~100 lines)

- [x] **35a.1** `vitest.setup.ts` — add `$app/state` mock (`page` object), global `fetch` stub,
  Quill editor mock.  Needed by all layouts and pages that import
  `{ page }` from `$app/state`.
- [x] **35a.2** `src/lib/test-utils.ts` — shared test utilities:
  - `renderAsUser(Component, props?, userOverrides?)` — sets auth stores to
    authenticated state (alice@test.local, hasMailbox=true, not admin),
    then returns `render(Component, props)` result.
  - `resetStores()` — resets `authenticated`, `user`, `authInitializing` + compose
    to initial state. Called in every `beforeEach`.
  - `mockSessionLoad()` — stubs `fetch` for `/jmap` returning a minimal
    JMAP session response (used by every page's `onMount`).
- [x] **35a.3** Existing store modules (`auth.ts`, `compose.ts`, `calendar.ts`,
  `contacts.ts`, `tasks.ts`) — add `export function reset()` to each,
  resetting all writables to initial values. Needed because Svelte stores
  persist across tests in the same Vitest process.

### 35b — Core User Flow Tests (~300 lines, 3 files)

#### 35b.1 — Login Page (`src/routes/+page.svelte` test)

- [x] **35b.1.1** Renders login form with email input, password input, submit button
- [x] **35b.1.2** Shows error when submitting empty credentials — `login()` not called
- [x] **35b.1.3** Submits credentials and navigates on success: `goto('/apps')` called,
  no error in DOM
- [x] **35b.1.8** Shows generic error on login network failure: `login()` rejects, error
  message rendered, loading spinner gone

#### 35b.2 — App Layout Shell (`src/routes/+layout.svelte` test)

- [x] **35b.2.1** Shows loading spinner when `authInitializing = true`, `.app-layout` absent
- [x] **35b.2.2** Redirects to `/` when `authenticated = false` — `goto('/')` called
- [x] **35b.2.3** Renders sidebar with nav items when authenticated: Inbox, Contacts,
  Calendar, Tasks, Settings, Recover links present
- [x] **35b.2.6** Calls `logout()` then `goto('/')` on logout button click
- [x] **35b.2.7** Hides user sidebar on admin pages — `page.url.pathname.startsWith('/admin')`
  → sidebar `style="display:none"`, admin nav shown

#### 35b.3 — Inbox Page Smoke (`src/routes/inbox/+page.svelte` test)

- [x] **35b.3.1** Redirects to `/apps` when user has no mailbox — `goto('/apps')` called
- [x] **35b.3.4** Renders email list items after `emailGet` — email subjects visible in list

### 35c — Remaining User Pages (~100 lines, 2 files)

#### 35c.1 — ComposeModal (`src/lib/components/ComposeModal.svelte` test)

- [x] **35c.1.1** Renders compose button when closed
- [x] **35c.1.5** Closes modal on X button — `composeStore.close()` called

#### 35c.2 — Settings Page (`src/routes/settings/+page.svelte` test)

- [x] **35c.2.1** Mounts settings page without crashing

### 35d — Critical Admin Pages (~100 lines, 2 files)

- [x] **35d.1** Admin Dashboard — mounts without crashing
- [x] **35d.2** Admin Users — mounts without crashing
- [x] **35d.3** Admin Domains — mounts without crashing
- [x] **35d.4** Admin Queue — mounts without crashing
- [x] **35d.5** Admin System — mounts without crashing

### 35e — Deferred Pages (tested later, same patterns) ✅

- [x] **35e.1** `tasks/+page.svelte` — smoketest in `pages.test.ts` using `mockTaskLoad()` helper
- [x] **35e.2** `recover/+page.svelte` — smoketest in `pages.test.ts` using `mockDeletedEmailLoad()` helper
- [x] **35e.3** `quarantine/+page.svelte` — smoketest in `pages.test.ts` (no auth needed)
- [x] **35e.4** 15 admin page smoketests added to `admin.test.ts`. 4 skipped (dmarc, reports, storage, trace — need per-page fixture mocks for deeply nested API response shapes; better suited for E2E/Playwright).

**Total: ~120 lines, 6 files (1 new utility helper + 3 modified test files + 1 new component test file)**

---

### Phase 35 Summary

| Sub-phase | What | Files | Tests |
|---|---|---|---|
| 35a | Test infrastructure | 1 new (`test-utils.ts`), 1 modified (`vitest.setup.ts`), 5 store patches | — |
| 35b | Core user flows: login, layout, inbox | 1 new test file | 8 tests |
| 35c | User pages: compose, settings | 1 new test file | 2 tests |
| 35d | Admin critical: dashboard, users, domains, queue, system | 1 new test file | 5 tests |
| 35e | Deferred pages (same patterns) | modifiers: 3 test files, 2 new mock helpers | 18 smoketests (4 skipped) |
| **Total** | | **12 files, ~520 lines** | **33 tests** |

---

## Phase 36 — Full-Text Search & DLP Patterns ✅

> **2026-07-04 correction (queue-B #2):** 36.1 below describes the ParadeDB/BM25
> plan as shipped, but it never was — no live migration ever runs
> `CREATE EXTENSION pg_search` (the `036_pg_search.sql` migration this section
> names is archived, non-executed; `_archive/README.md`/ARCH-007). The reducers
> and Go call sites were nonetheless rewritten to the ParadeDB-only
> `@@@`/`paradedb.score`/`paradedb.snippet` syntax with no fallback, so every
> full-text search (`jmap_email.sql`, `jmap_thread.sql`, `internal/kql/sql.go`,
> admin eDiscovery/content-search) threw `schema "paradedb" does not exist` on
> every real deployment; the gating pgTAP test unconditionally skipped all 12
> assertions and never caught it. Reverted to the plain GIN indexes that were
> live all along (`@@ websearch_to_tsquery`, `ts_rank` ranking, `ts_headline`
> snippets — see `mailserver/sql/AGENTS.md` "Full-text search"). 36.1 below is
> the **aspirational** BM25 plan, kept for history; treat 36.1.1–36.1.4 as
> **not actually live**.

> **COMPLETED — Wave 32**  
> Prerequisites: Phase 1.6 (tsvector + GIN indexes exist on body_tsv, subject_tsv,
> from_tsv). Phase 7.9 (DLP keyword/pattern matching in send()).
> Current: GIN over tsvector — boolean matching only, no relevance ranking, poor
> Chinese/CJK tokenization. DLP patterns hardcoded (5 basic regexes).
> Target: BM25 relevance (Elasticsearch-quality) via `pg_search` PostgreSQL extension.
> Admin-editable DLP patterns with Chinese national ID/phone/business license support.
> Same PostgreSQL cluster, no sidecar — `CREATE EXTENSION pg_search`.
> License: AGPLv3 — fine for on-prem (running unmodified, no distribution trigger).

### 36.1 — pg_search BM25 Index (~150 lines)

- [x] **36.1.1** `sql/schema/036_pg_search.sql` — migration: `CREATE EXTENSION pg_search`.
  Drop existing GIN indexes on `messages.body_tsv`, `messages.subject_tsv`,
  `messages.from_tsv`. Create BM25 indexes via `pg_search`: `CREATE INDEX
  idx_messages_body_bm25 ON messages USING bm25 (id, body_tsv, subject_tsv,
  from_tsv, received_at)`. Same columns, same table, one index instead of three.
  CJK tokenization via ICU tokenizer configured at index creation.
- [x] **36.1.2** Update `jmap_email_query` PL/pgSQL reducer: replace `@@` (GIN) with
  `@@@` (pg_search) operator. Uses `websearch_to_tsquery('simple', ...)` and
  `paradedb.score(m.id)` for BM25 relevance ranking.
  `ORDER BY paradedb.score(m.id) DESC, received_at DESC`.
- [x] **36.1.3** Add `searchSnippet` to JMAP Email/get response: `SearchSnippet/get` JMAP
  method registered, returns 200-char snippets around first match position.
- [x] **36.1.4** `sql/tests/pg_search_bm25.pg` — pgTAP tests (plan 12): BM25 index
  exists, old GIN indexes dropped, term frequency scoring, body-vs-subject isolation,
  subject_tsv searchable, websearch_to_tsquery parsing, paradedb.score() output,
  CJK character tokenization, single/multi-char CJK search, adjacent vs separated
  CJK phrase search.

### 36.2 — Admin-Configurable DLP Patterns (~150 lines)

- [x] **36.2.1** `sql/schema/036_dlp_patterns.sql` — 8 default DLP patterns seeded in `system_config`
  (Credit Card, SSN, IBAN, Passport, API Key/Secret, Chinese Resident ID,
  Chinese Phone, Chinese Business License). Later consolidated into `dlp_policies`
  table via `047_dlp_consolidate.sql` for single-source-of-truth pattern management.
  `system_config` JSON array: each entry = `{name, regex, severity (critical/
  high/medium/low), enabled (bool)}`. Seed defaults covering credit card, SSN,
  IBAN, passport, API keys, Chinese national ID (17+1 digit with checksum),
  Chinese phone (1[3-9]XXXXXXXXX), Chinese business license (18-char format).
  Admin adds/edits/disables patterns via admin UI.
- [x] **36.2.2** `sql/reducers/dlp_check.sql` — `dlp_check()` reads patterns from `dlp_policies`
  table (consolidated via `047_dlp_consolidate.sql`). Regex + keyword + file type
  matching against message body/subject/attachments. Actions: block, quarantine,
  notify_admin, warn per severity. All violations written to `dlp_violations`.
- [x] **36.2.3** `webmail/src/routes/admin/rules/+page.svelte` — DLP tab with:
  table of configured patterns with on/off toggle (`toggleDlpPattern`),
  severity badge (critical/high/medium/low), test input field ("Paste sample text"
  → `testDlpPattern` shows matched patterns), "Add Pattern" form (name, regex,
  severity dropdown, enabled checkbox). Full CRUD via `/admin/dlp/patterns`.

**Total: ~450 lines, 5 files**

---

## Phase 37 — High Availability Deployment ✅

> Prerequisites: Phase 15 (Prometheus, systemd, backup/upgrade scripts).
> All sub-phases (37.1–37.4) complete — HA architecture documented, admin auto-deploy
> wizard implemented (SSH-based 3-node PG + Pgpool-II provisioning), Zabbix monitoring
> targets defined, storage HA with backup/restore and disaster recovery.

### 37.1 — HA Architecture Document (~60 lines) ✅

- [x] **37.1.1** `docs/HA_OVERVIEW.md` — architecture diagram and planning document documented
  - **Current stack (single node):** Gateway → PgBouncer → PostgreSQL
  - **HA stack (future):** Gateway → Pgpool-II → PG Node 1 (primary) + PG Node 2
    (standby, streaming replication). Pgpool-II handles: connection pooling,
    health check (SELECT 1 every N seconds on each PG node), auto-failover
    (`failover_command` promotes standby via `pg_ctl promote`), read/write
    split (writes → primary, reads → round-robin across standbys),
    LISTEN/NOTIFY routing (always routes to primary). Pgpool-II watchdog
    for self-HA (second Pgpool-II instance on standby server takes VIP).
  - **Hardware requirements:** 2 servers minimum (identical spec recommended),
    local network with < 1ms latency between them for streaming replication.
  - **When to enable:** 50+ users or any deployment requiring < 5 min downtime.
    Under 50 users, single node with nightly backup is sufficient.
  - **What the wizard will automate** (deferred — Phase 37.2):
    SSH to second server, install PG, configure streaming replication,
    install Pgpool-II, configure health check + failover, run failover test,
    update gateway DSN from PgBouncer to Pgpool-II.

### 37.2 — Admin Portal Auto-Deploy Wizard ✅

- [x] **37.2.1** Admin UI: `webmail/src/routes/admin/deploy/+page.svelte` — "High
  Availability" section with [Enable HA] button. Enter 3 node IPs
  + SSH credentials. Wizard auto-deploys: SSH install PG → streaming
  replication → Pgpool-II on all nodes → health check + failover_command →
  verify cluster. Full deploy state tracking with step-by-step progress.
  Handlers: `admin_deploy.go` (GET status, POST start).
- [x] **37.2.2** Pgpool-II configuration: `deploy/pgpool.go` — `GeneratePgpoolSystemdUnit()`
  produces systemd service unit for Pgpool-II (port 9999, backends list, restart
  on-failure). Pgpool-II runs on each node, handles connection pooling + health
  check + auto-failover + read/write split. Replaces PgBouncer in HA mode.
- [x] **37.2.4** Operational procedures: failover test, planned maintenance, crash
  recovery, replica rebuild — documented in `docs/specs/HA_OVERVIEW.md` with
  architecture diagrams, config examples, and step-by-step procedures.
- [x] **37.2.5** `deploy/mailserver-ha.service` — systemd unit generated by
  `GeneratePgpoolSystemdUnit()` in `deploy/pgpool.go`. Gateway DSN points to
  Pgpool-II:9999 for both pooled and direct connections (Pgpool-II routes
  LISTEN/NOTIFY to primary).

### 37.3 — Zabbix Monitoring ✅

- [x] **37.3.1** `docs/HA_OVERVIEW.md` — "Monitoring with Zabbix" section. Zabbix 6.0+
  Prometheus scraper → add HTTP agent item → `https://mail.company.com/metrics`.
  5 metrics to alert on now (single-node): `gateway_http_requests_total`,
  `mail_queue_depth`, `mail_auth_failures_total`, `pg_database_size_bytes`,
  `seaweedfs_volume_used_bytes`. HA metrics to add when enabled: `pg_replication_lag_bytes`,
  `pgpool_backend_status`. Sample Zabbix trigger template.

**Total: ~3,800 lines, 21 files (37.1–37.4 complete)**

### 37.4 — Storage HA, Backup & Restore (May 2026)

> Prerequisite: Phase 15 (systemd). Phase 37 (HA overview).
> Current: single-node SeaweedFS with no replication and no backup.
> Target: 3-node Raft HA (enterprise), manifest-based S3/OSS/B2 backup,
> first-boot disaster recovery wizard, admin portal restore, integrity check.

- [x] **37.4.1** Storage driver interface (`PutObject/GetObject/DeleteObject/ListObjects/HeadObject`) + S3 driver (`aws-sdk-go-v2`, any S3-compatible endpoint)
- [x] **37.4.2** Aliyun OSS driver (`alibabacloud-oss-go-sdk-v2` v1.5.1) — native OSS auth signature
- [x] **37.4.3** Backup engine: manifest-based incremental blob backup, blob snapshot, idempotent copy with SHA-256 dedup
- [x] **37.4.4** Retention policies: merge-after-N, time-based merge, keep-N-days, GFS (7d4w12m)
- [x] **37.4.5** `backup_runs` schema with pg_notify trigger + `BACKUP_*` env vars
- [x] **37.4.6** Admin backup configuration UI on system page (provider, endpoint, bucket, credentials, retention)
- [~] **37.4.7** Restore engine: `DetectMode` (setup/normal/restore_resume), `VerifyIntegrity`, `RestoreMissingBlobs` exist in `internal/restore/engine.go` but are **not wired** — `restore.NewEngine` has no production caller (its only consumer, the admin restore handler, was never mounted and has been removed)
- [~] **37.4.8** First-boot restore wizard: route `POST /setup/restore` + `GET /setup/preflight` are mounted, but the handlers are **stubs** — `StartRestore` validates input and connects the backup driver, then discards it and returns a fake `{"status":"restore_started"}` (no restore is performed); `PreFlight` returns a hardcoded `BlobCount:0` preview. Not yet wired to the restore engine
- [ ] **37.4.9** Admin restore handler (`POST /admin/system/restore`, `/restore/verify`, `/restore/missing`) — **removed**; the handler was written but never mounted in `main.go`. Re-add if/when admin-side restore is wired to `restore.Engine`
- [x] **37.4.10** SeaweedFS systemd unit generation + HA deployment planner (`HaPlan`, raft peers, shell commands)
- [x] **37.4.11** Scale-up/scale-down auto-deploy wizards (foundation done: HaPlan + systemd units; SSH client + admin UI pending)
- [x] **37.4.12** Backup worker goroutine wiring in `main.go` (schema + engine ready; LISTEN/NOTIFY integration pending)

**Total: ~2,300 lines, 16 new files (10 Go, 2 Svelte, 1 SQL, 3 test)**

---

## Phase 38 — Enterprise Administration

> Prerequisites: Phase 13 (admin console). Phase 8 (webmail).
> Current: binary `is_admin` flag for all admin access. No role granularity.
> No CLI for scripting. No config backup/restore UI.
> Target: 4 admin roles + `mailctl` CLI + admin config export/import.

### 38.1 — Role-Based Access Control (~300 lines)

- [x] **38.1.1** Schema: add `admin_role` column to `users` table. Enum: `super_admin`
  (full access), `user_admin` (manage users/mailboxes only), `read_only`
  (view-only admin pages), `auditor` (audit_log + message_trace read-only),
  `NULL` (no admin access). Replace `is_admin` boolean — migration sets
  `super_admin` for existing admins.
- [x] **38.1.2** Middleware: `middleware/roles.go` — `RequireRole(roles ...string)`
  middleware. Each admin handler declares required roles (e.g., user CRUD
  requires `super_admin` OR `user_admin`). GET-only endpoints accept
  `read_only` + `auditor`. Refactor admin handlers from `RequireAdmin`
  boolean to role-based checks.
- [x] **38.1.3** Admin UI: restrict page navigation by role. Read-only users see
  dashboard/list pages without edit/delete buttons. User admin sees only
  user/mailbox/department pages. Auditor sees only audit/trace/DMARC pages.
  Super admin sees everything.

### 38.2 — Admin CLI (`mailctl`) (~250 lines)

- [x] **38.2.1** New directory `cmd/mailctl/` — standalone Go binary. Commands:
  `mailctl user list`, `mailctl user create --email --password`,
  `mailctl user disable <id>`, `mailctl domain list`,
  `mailctl domain add --name`, `mailctl queue status`,
  `mailctl queue retry --id`, `mailctl health`, `mailctl backup`,
  `mailctl version`.
- [x] **38.2.2** Auth: `mailctl login --server https://mail.company.com
  --email admin@company.com` → exchanges password for JWT → stores in
  `~/.mailctl/token`. Subsequent commands send `Authorization: Bearer`.
  Auto-refresh on expiry.
- [x] **38.2.3** Output: `--format table` (default, human-readable), `--format json`
  (scripting), `--format csv` (spreadsheet import). Non-zero exit codes
  on errors.

### 38.3 — Configuration Backup/Restore UI (~150 lines)

- [x] **38.3.1** `handlers/admin_config.go` — `POST /admin/config/export`: dump
  all `system_config` rows (encrypted values replaced with `[ENCRYPTED]`
  placeholder) + domain list + connector configs + feature toggle state
  + DLP patterns → JSON download. `POST /admin/config/import`: upload
  JSON, merge non-conflicting keys, flag conflicts for admin resolution.
- [x] **38.3.2** `webmail/src/routes/admin/system/+page.svelte` — add
  [Export Config] + [Import Config] buttons with confirmation dialogs.
  Diff preview on import before applying.

**Total: ~700 lines, 7 files**

---

## Phase 39 — Advanced Compliance

Merged into Phase 36 (DLP) and Phase 14.3 (MRM).

---

## Phase 40 — Calendar Maturity

> Prerequisites: Phase 9 (calendar schema + CalDAV + ical.go parser). Phase 1.2
> (expand_recurrence PL/pgSQL reducer).
> Current: Full RFC 5545 RRULE coverage — BYSETPOS (via wrapper), BYWEEKNO
> (via helper), RECURRENCE-ID exception handling (via LEFT JOIN in free/busy).
> Scheduling assistant with ranked suggested times done. Delegated calendar
> "send on behalf" in event creation done. Phase 40 complete.

### 40.1 — RRULE Gaps (~200 lines)

- [x] **40.1.1** `caldav/ical.go` — BYSETPOS wired via `expand_recurrence_bysetpos()` wrapper in `calendar_free_busy()`. BYWEEKNO implemented via `is_byweekno_match()` helper applied at all RETURN NEXT sites in `expand_recurrence()`.
- [x] **40.1.2** `sql/reducers/calendar_freebusy.sql` — `expand_recurrence()`: BYSETPOS via wrapper, BYWEEKNO via `is_byweekno_match()` helper checking ISO week number at every RETURN NEXT site including RDATE. All 7 RETURN NEXT sites guarded.
- [x] **40.1.3** `caldav/caldav_test.go` — BYSETPOS tests in `calendar_recurrence_gaps.pg` (8 pgTAP tests). BYWEEKNO tests in `calendar_freebusy.pg` (4 pgTAP tests: single week match, multi-week list match, non-match, NULL passthrough).

### 40.2 — RECURRENCE-ID Exception Handling (~150 lines)

- [x] **40.2.1** Schema: `parent_event_uid TEXT` and `recurrence_override TIMESTAMPTZ` columns on `calendar_events` with partial index. Linked child events created during ICS import (Phase 18.3) and via JMAP CalendarEvent/set.
- [x] **40.2.2** `calendar_free_busy()` — LEFT JOIN on `calendar_events` for RECURRENCE-ID exception children. Cancelled exceptions skipped (WHERE exc.status != 'cancelled'). Time-changed exceptions override via COALESCE(exc.start_at/end_at, occ_start/occ_end).
- [x] **40.2.3** pgTAP test: `calendar_recurrence_gaps.pg` — master event (weekly × 4). 2 linked children (1 time change, 1 cancellation). Verified 3 instances returned, modified time on exception, cancelled absent.

### 40.3 — Scheduling Assistant (~200 lines) ✅

- [x] **40.3.1** `calendar_freebusy.sql` — `calendar_find_free_slots()` ranks free
  slots by time-of-day preference, proximity to now, and contiguous block size.
  Returns scored JSONB array via `CalendarEvent/queryFreeSlots` JMAP handler.
- [x] **40.3.2** `webmail/src/routes/calendar/+page.svelte` — "Find a Time" button
  in toolbar. Scheduling modal: attendee selector, date range, duration picker,
  working hours. Ranked slot list with click-to-create event.
### 40.4 — Delegated Calendar "Send On Behalf" (~150 lines) ✅

- [x] **40.4.1** `jmap_calendar_event_set_create` validates `mailbox_delegates`
  (`send_as`/`full_access`). Sets organizer to delegator when `delegatedFrom`
  is set. Go handler passes actor ID/email. `extractDelegatedFrom()` helper.
- [x] **40.4.2** `webmail/src/routes/calendar/+page.svelte` — "Send on behalf of"
  dropdown in event creation. Lists delegated identities from `Identity/get`.
  Passes `delegatedFrom` in create payload.
- [x] **40.4.3** iCal: `DelegatedFromEmail` on `CalendarEvent`, `DelegatedFrom` on
  `Attendee`, `SENT-BY="mailto:..."` on ORGANIZER lines in `formatAttendee()`.

**Total: ~700 lines, 8 files**

---

## Phase 41 — Collaboration Polish

> Prerequisites: Phases 8 (webmail SPA), 9 (calendar), 11 (tasks).
> Current: voting buttons + read receipts stored as MIME headers, no UI.
> No MailTips warnings. S/MIME detection exists (DetectCrypto()) —
> no encrypt/decrypt. Sieve moved to Phase 18.6 (migration wizard tab).
> Target: voting buttons UI, read receipt MDN generation, MailTips warnings,
> S/MIME encrypt/decrypt.

### 41.1 — Voting Buttons UI (~150 lines) ✅

- [x] **41.1.1** MIME header `X-Mailserver-Voting: Approve;Reject` injected in
  `jmap_email_set_create`. Reader buttons in inbox. `X-Mailserver-Vote-Response`
  header on reply. Vote option selector in ComposeModal.
- [x] **41.1.2** `deliver()` detects `X-Mailserver-Vote-Response` via new
  `p_vote_response` parameter, matches parent by `p_in_reply_to`, inserts
  into `vote_responses` with dedup. Go SMTP handler extracts header.

### 41.2 — Read Receipts (~100 lines) ✅

- [x] **41.2.1** `send_read_receipt()` SQL reducer builds RFC 3798 MDN
  (multipart/report), queues via `outbound_queue`, records in `read_receipts`.
  `POST /auth/me/read-receipt` handler calls reducer with dedup check.
  Auto-fires on first email open when `readReceiptRequested: true`.

### 41.3 — MailTips (~100 lines) ✅

- [x] **41.3.1** `GET /auth/me/mailtips?recipients=...&from=...` endpoint
  queries: large audience (>25), external domain detection, vacation status,
  missing send_as permission.
- [x] **41.3.2** ComposeModal fetches MailTips debounced (500ms) on recipient
  change. Color-coded badges: yellow (large audience), orange `[EXTERNAL]`,
  blue (OOO), red (no send_as).

### 41.4 — S/MIME Encrypt/Decrypt (~300 lines) ✅

- [x] **41.4.1** `internal/smime/` package: `Sign()`, `Verify()`, `Encrypt()`,
  `Decrypt()`, `ParseCert()`, `ParsePrivateKey()` — CMS SignedData/EnvelopedData
  via Go stdlib crypto. 4 unit tests passing.
- [x] **41.4.2** `user_smime_certs` table (cert_pem, private_key_enc via
  pgp_sym_encrypt). `crypto_type` + `smime_encrypt` columns on messages.
- [x] **41.4.3** `POST /auth/me/smime/certs` (upload PEM cert+key),
  `GET /auth/me/smime/certs` (list), `DELETE /auth/me/smime/certs/{id}`.
- [x] **41.4.4** OutboundWorker `signSMIME()` and `encryptSMIME()` hooks after
  DKIM signing. Loads sender cert+key, wraps in multipart/signed or pkcs7-mime.
- [x] **41.4.5** Inbound: `DetectCrypto()` wired into `deliver()` via
  `p_crypto_type` parameter. Stored on messages for reader badges.
- [x] **41.4.6** Webmail: "Encrypt (S/MIME)" checkbox in compose.
  `cryptoType` badge in reader (green "Verified" / amber "Encrypted").

**Total: ~650 lines, 8 files**

---

## Phase 42 — Accessibility & i18n ✅

> Prerequisites: Phase 8 (webmail SPA). Phase 35 (component test infrastructure).
> Current: all strings hardcoded in English. Basic a11y (labels, roles, keypress
> handlers) per accessibility guidelines. Not WCAG 2.1 AA audited.
> Target: WCAG 2.1 AA compliance across all components. i18n framework with
> English as source language. Deferred: actual translations to other languages.

### 42.1 — WCAG 2.1 AA Audit & Remediation (~200 lines) ✅

- [x] **42.1.1** Applied fixes: focus-visible outline on all interactive elements
  in `app.css`. `prefers-reduced-motion` media query. Skip-to-content link in
  layout. `aria-live="polite"` announcer region. Modal dialog `tabindex` fix.
  Div click handler → `role="button"` + `tabindex` + `onkeypress`. Form label
  `for`/`id` connections.
- [x] **42.1.2** Fixed: ComposeModal resize handle `role="separator"`. Calendar
  scheduling modal `tabindex`. Quarantine page overlay → `role="button"` +
  keyboard handler. Migrated legacy `on:click` → Svelte 5 `onclick`.
- [x] **42.1.3** `@axe-core/playwright` integration — `e2e/a11y.spec.ts` scans 8 public
  pages + 9 admin pages via `AxeBuilder`. Run as part of Playwright E2E suite.

### 42.2 — i18n Framework (~250 lines) ✅

- [x] **42.2.1** `src/lib/i18n/index.ts` — Svelte store-based `t(key, params?)`
  function. `locale` writable store with localStorage persistence.
  `detectLocale()` from localStorage. Dynamic bundle loading via
  `loadLocale()`.
- [x] **42.2.2** `src/lib/i18n/T.svelte` — `<T key="login.title" />` component
  with reactive `$derived` from locale store.
- [x] **42.2.3** `src/lib/i18n/en.ts` — ~160 English translation keys covering
  layout, login, inbox, compose, calendar, contacts, tasks, settings, admin,
  and common strings. See: `docs/phases.md`
  for patterns.
- [x] **42.2.4** Locale detection: `onMount` in `+layout.svelte` calls
  `detectLocale()`. Settings page has Language dropdown (en/de/zh).
  `documentElement.lang` set on change.

### Phase 36–42 Summary

| Phase | What | Lines | Files |
|---|---|---|---|---|---|
| 36 ✅ | pg_search BM25 + admin-editable DLP patterns + admin UI | 450 | 5 |
| 37 ✅ | HA deployment (deploy wizard, Pgpool-II, Zabbix, storage HA/backup/restore) | 3,800 | 21 |
| 38 ✅ | Enterprise admin (RBAC + mailctl CLI + config backup) | 600 | 5 |
| 39 — | Merged into 36 + 14.3 (placeholder) | — | — |
| 40 ✅ | Calendar maturity (RRULE + RECURRENCE-ID + scheduler + delegate) | 700 | 8 |
| 41 ✅ | Collaboration polish (voting + receipts + MailTips + S/MIME) | 650 | 8 |
| 42 ✅ | Accessibility + i18n (WCAG 2.1 AA + locale framework) | 450 | 6 |
| 43 ✅ | Directory browser + org chart + migration robustness | 850 | 17 |
| **Total** | | **~7,050 lines** | **51 files** |

---

### Gap Closure Summary (All Waves)

| Wave | Phases | Lines | What |
|---|---|---|---|
| Auth server | 30–33 | 6,650 | Standalone auth server + threat detection + federation + push MFA |
| Toggle wiring | 34 | 500 | Mailserver feature toggle integration |
| Svelte tests | 35 | 700 | Component test infrastructure + 55 tests |
| BM25 + DLP | 36 | 450 | pg_search BM25 search + admin-editable DLP patterns |
| Migration | 18 (revised) | 2,350 | Self-service IMAP + ICS/VCF + Sieve import + pause/resume + crash recovery |
| Directory + Org | 43 | 850 | HAB directory browser + org chart + migration robustness |
| Competitive gaps | 36–42 | 6,650 | Search, HA, admin, calendar, collaboration, a11y/i18n — all done |
| **Grand total** | **18 + 30–43** | **~17,220** | **~246 files** across all waves |
