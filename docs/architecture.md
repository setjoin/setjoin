# Setjoin architecture — current authority and target composition

## Whole-project direction (planned)

Setjoin is adopting a composable workplace architecture: small explicit module
interfaces, declared dependencies and owned lifecycle, with third-party replacement
only at designated extension points. Protected system apps retain reducer authority;
startup composition is default and live replacement requires qualification.

The refactor program
maps `authserver/`, `shared/`, `mailserver/` (including SQL and webmail), `mailctl/`,
`clients/`, `asrbot/`, catalogs and deployment/test tooling. Its
reconciliation ledger
preserves domain ownership and existing evidence. This is future architecture, not
an assertion that public system-app APIs or a generic extension runtime exist today.

For as-built paths and execution contracts, root and child `AGENTS.md` are canonical.
The mail-focused diagrams and repository sketch below are historical implementation
notes, not the current whole-project module inventory. In particular, scheduling is
owned by Go workers, desktop uses Electron, mobile uses Tauri WebView hosts, and
HarmonyOS uses ArkWeb. Do not recreate obsolete paths or `pg_cron` from these notes.

## Concept

The core idea is borrowed from SpaceTimeDB: **the database is the application server**.

- All business logic lives as PL/pgSQL stored procedures (reducers) inside PostgreSQL
- Clients never talk to a traditional app server — they talk to a thin Go gateway that
  translates their requests directly into PostgreSQL function calls
- PostgreSQL `LISTEN/NOTIFY` replaces a message broker — the DB pushes state changes
  to all connected clients the moment they happen
- The WAL (Write-Ahead Log) is the commit log — crash recovery and durability are free
- Hot state (sessions, presence, queues) lives in unlogged tables (in shared_buffers,
  no WAL overhead); cold state (messages, calendars, contacts) in logged tables

---

## System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLIENTS                                │
│  Web (SvelteKit)  iOS (Swift)  Android (Kotlin)                 │
│  Thunderbird/Apple Mail (IMAP)  Apple Calendar (CalDAV)         │
│  Outlook/any LDAP client (LDAP GAL)                             │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │  JMAP/HTTPS + WebSocket (primary, all clients)
       │  IMAP4 / CalDAV / CardDAV (legacy bridge only)
       │  LDAP (read-only GAL)
       │  SMTP port 25 (inbound from other mail servers)
       │  SMTP port 587 (submission from authenticated users)
       │
┌──────▼──────────────────────────────────────────────────────────┐
│                    GO GATEWAY LAYER (stateless)                 │
│                                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  JMAP    │ │  SMTP    │ │  IMAP4   │ │  LDAP (read-only)│  │
│  │ HTTP/WS  │ │ MTA+MSA  │ │  bridge  │ │  CalDAV/CardDAV  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬─────────┘  │
│       │            │            │                 │            │
│  • TLS termination (ACME/Let's Encrypt)                        │
│  • JWT auth + WebAuthn/Passkeys + OIDC                         │
│  • Translate protocol commands → PG function calls             │
│  • Subscribe LISTEN/NOTIFY → push events to WebSocket clients  │
│  • No business logic — gateway is purely I/O                   │
└──────┬──────────────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────────────┐
│                       PgBouncer                                 │
│              (transaction-mode connection pooling)              │
│                                                                 │
│   NOTE: transaction-mode pooling breaks LISTEN/NOTIFY because   │
│   each transaction lands on a different backend. The gateway    │
│   opens ONE direct pgx connection to PostgreSQL (bypassing      │
│   PgBouncer) exclusively for LISTEN, and continues to route     │
│   all other queries through PgBouncer. See gateway/internal/db/ │
│   pool.go (DatabaseDirect DSN) and db/listen.go.                │
└──────┬──────────────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────────────┐
│                   PostgreSQL PRIMARY                            │
│                                                                 │
│  ┌─ Unlogged tables (hot / in shared_buffers) ───────────────┐  │
│  │  sessions  ws_subscriptions  outbound_queue_hot           │  │
│  │  greylist  rate_limit_counters  smtp_sessions             │  │
│  │  (outbound_queue_hot is the fast 10s-drain staging buffer │  │
│  │   in front of the LOGGED outbound_queue — see 0.7)        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ Logged tables (durable / WAL-backed) ────────────────────┐  │
│  │  domains          users           mailboxes               │  │
│  │  messages         folders         attachments             │  │
│  │  aliases          rules           transport_rules         │  │
│  │  calendars        events          attendees               │  │
│  │  addressbooks     contacts        contact_groups          │  │
│  │  tasks            devices         departments             │  │
│  │  audit_log        message_trace   archive_policies        │  │
│  │  litigation_holds retention_tags  journal_queue           │  │
│  │  spam_tokens      dkim_keys       dmarc_reports           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ PL/pgSQL Reducers (all business logic) ──────────────────┐  │
│  │  deliver()       send()          move()                   │  │
│  │  search()        flag()          thread()                 │  │
│  │  rule_engine()   spam_score()    free_busy()              │  │
│  │  archive()       hold()          journal()                │  │
│  │  retention()     book_resource() expand_group()           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ LISTEN/NOTIFY channels ──────────────────────────────────┐  │
│  │  mailbox:{user_id}    calendar:{user_id}                  │  │
│  │  tasks:{user_id}      admin:events                        │  │
│  │  outbound:queue       (triggers gateway push to WS)       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  WAL = commit log (crash recovery + streaming replication)      │
│  pg_cron = scheduled jobs (archiving, retention, retry queue)   │
└──────┬──────────────────────────────────────────────────────────┘
       │ Streaming Replication
  ┌────▼──────────┐   ┌────────────────┐
  │  Replica 1    │   │  Replica 2     │   Pgpool-II auto-failover
  │  (read/hot    │   │  (read/backup) │   Pgpool-II VIP
  │   standby)    │   └────────────────┘
  └───────────────┘
       │
  ┌────▼──────────────────────────────────┐
  │  SeaweedFS (self-hosted, S3-compatible) │
  │  • Attachment blobs (SHA-256 dedup)    │
  │  • pgBackRest WAL archive (PITR)       │
  │  • Daily full backups                  │
  └────────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Database + app logic | PostgreSQL 16+ | All reducers in PL/pgSQL; LISTEN/NOTIFY push; WAL durability |
| Scheduled jobs | pg_cron (PG extension) | Retry queue, archiving, retention — no external scheduler |
| Connection pool | PgBouncer (transaction mode) | Multiplex thousands of clients over few PG connections |
| Gateway + all servers | Go 1.26 | Single language for SMTP/IMAP/JMAP/LDAP/CalDAV/CardDAV servers; fast, single binary |
| Object storage | SeaweedFS (self-hosted) | S3-compatible API; Raft-based HA; runs on same hardware |
| Virus scan | ClamAV | Free, Go subprocess call at delivery |
| Push notifications | APNs (Apple free) + FCM (Google free tier) | No paid service; Web Push for browser |
| HA + failover | Pgpool-II + HAProxy | Automatic PostgreSQL primary failover |
| Backup + PITR | pgBackRest | WAL archiving to SeaweedFS; point-in-time recovery |
| Webmail frontend | SvelteKit | Fast, small bundle; SSR for initial load; component model fits mail UI |
| Mobile | Swift (iOS) + Kotlin (Android) | Native apps using JMAP over HTTPS; no special protocol |
| Monitoring | Prometheus + Grafana | pg_stat_* + custom gauges; dashboards for mail queue, spam rates |
| Dev deployment | systemd | `bash scripts/dev.sh` starts full stack as background processes |
| Prod deployment | systemd | systemctl start/stop for all services; journald logging |
| Small team option | Single Go binary | For < 20 users: one binary + external PG + SeaweedFS |

---

## Client Protocol Stack

```
PRIMARY — all clients (web, iOS, Android, desktop)
  JMAP (RFC 8620 core + RFC 8621 mail + drafts for calendar/contacts)
  Transport: HTTPS POST /jmap  +  WebSocket wss://.../jmap
  Push: PostgreSQL LISTEN/NOTIFY → gateway → WebSocket push
  Auth: JWT bearer + WebAuthn/Passkeys + OIDC (RP + IdP — login via external providers, act as SSO provider for other apps)

LEGACY BRIDGES — third-party clients only
  IMAP4rev2 (RFC 9051)    ← Thunderbird, Apple Mail
  CalDAV (RFC 4791)       ← Apple Calendar, third-party calendar apps
  CardDAV (RFC 6352)      ← Apple Contacts, third-party contact apps
  LDAP (read-only)        ← Outlook GAL, Thunderbird address book, any LDAP client

SERVER FEDERATION
  SMTP inbound  port 25   ← receiving mail from the internet
  SMTP outbound port 587  ← authenticated submission from users/apps
```

Dropped intentionally:
- ActiveSync (EAS) — JMAP covers mobile
- AutoDiscover — JMAP service discovery (/.well-known/jmap)
- MAPI/HTTP — JMAP covers desktop
- EWS — client protocol dropped (JMAP covers it); EWS SOAP now used for migration connector only
- POP3 — JMAP covers it, better

---

## Rules Engine Design

Each rule has a `run_on` field controlling where it executes:

| `run_on` | Execution point | Available actions |
|---|---|---|
| `server` | PL/pgSQL at delivery time, before message hits inbox | move, copy, forward, redirect, flag, categorize, mark-read, delete, discard, stop-processing |
| `client` | Client app after JMAP sync, in JS/Swift/Kotlin | highlight color, play sound, desktop notification, local folder move |
| `both` | Server executes delivery actions, client executes presentation actions | all of the above |

Rule schema in PostgreSQL:
```sql
rules (
  id, user_id, name, enabled, priority,
  run_on  TEXT CHECK (run_on IN ('server','client','both')),
  conditions  JSONB,   -- [{field, op, value}, ...]
  actions     JSONB,   -- [{type, params}, ...]
  stop_processing BOOL
)
```

The PL/pgSQL `rule_engine(message_id, mailbox_id)` function evaluates all
`run_on IN ('server','both')` rules at delivery. The JMAP client syncs all
rules and evaluates `run_on IN ('client','both')` rules locally after each sync.

---

## LDAP GAL — OU Structure

The Go LDAP server is read-only, backed by PostgreSQL. The OU tree mirrors
the `departments` hierarchy defined in the admin console:

```
dc=company,dc=com
├── ou=People
│   ├── ou=Engineering
│   │   └── ou=Backend
│   ├── ou=Sales
│   └── ou=Finance
├── ou=Groups          ← distribution lists + mailing lists
├── ou=Resources       ← room + equipment mailboxes
└── ou=Contacts        ← external contacts
```

- Admin defines OU tree in admin UI → stored in `departments` table in PostgreSQL
- Users assigned a `department_id` → placed in correct OU automatically
- LDAP server computes DN on the fly from PostgreSQL joins — no separate LDAP data store
- Webmail autocomplete queries the same PostgreSQL view, results grouped by department
- Any LDAP-capable client (Outlook, Thunderbird, Apple Mail, custom app) reads it

---

## Data Flow: Inbound Email

```
1. External MTA connects to port 25
2. Go SMTP server: STARTTLS, receive EHLO/MAIL FROM/RCPT TO/DATA
3. Go: SPF check (DNS lookup) → result
4. Go: DKIM verify → result
5. Go: DMARC evaluate (SPF+DKIM results) → policy decision
6. Go: greylisting check → call PG greylist_check(ip, sender, rcpt)
7. Go: parse MIME message → extract body text, attachment refs
8. Go: upload attachments to SeaweedFS (via S3 API) → get SHA-256 refs
9. Go: call PG deliver(raw_message, spf_result, dkim_result, ...)
10. PG deliver():
    a. Insert into messages table
    b. Run spam_score() → assign spam score
    c. Run rule_engine() for server-side rules (move/flag/discard/etc.)
    d. Run transport_rule_engine() for admin rules
    e. NOTIFY mailbox:{user_id} with new message event
11. Gateway receives NOTIFY → pushes JMAP StateChange to connected WebSocket clients
12. Client receives push → fetches new messages via JMAP Email/get
```

---

## Data Flow: Client Sends Email

```
1. Client calls JMAP EmailSubmission/set (POST /jmap or WebSocket)
2. Gateway: validate JWT → call PG send(submission)
3. PG send():
    a. Validate sender is authorized for mailbox
    b. Run outbound transport_rule_engine() (DLP, disclaimers)
    c. Insert into outbound_queue (unlogged table for speed)
    d. Insert into messages (Sent folder)
    e. NOTIFY mailbox:{user_id} (Sent folder update)
4. pg_cron job picks up outbound_queue every 10s
5. Go SMTP client: DKIM-sign message → connect to recipient MX → deliver
6. On success: mark queue item delivered, update message status
7. On failure: exponential backoff retry; after max retries → DSN bounce to sender
```

---

## Repo Structure

```
mailserver/
├── TODO.md                    ← to-do list
├── ARCHITECTURE.md            ← this file
│
├── docs/
│   ├── CRASH_RECOVERY.md      ← startup_recovery(), health_check(), queue drains
│   ├── JMAP.md                ← JMAP methods + state-token semantics
│   ├── LDAP_IDENTITY.md       ← LDAP GAL + AD/OIDC/SAML identity design
│   ├── RULES.md               ← server + client rule engine spec
│   ├── SECURITY.md            ← SPF/DKIM/DMARC/antispam/DLP/TLS
│   └── DEPENDENCIES.md        ← version tracker and upgrade policy
│
├── sql/
│   ├── schema/                ← CREATE TABLE statements (one file per domain)
│   │   ├── 001_domains.sql
│   │   ├── 002_departments.sql
│   │   ├── 003_users.sql
│   │   ├── 004_mailboxes.sql
│   │   ├── 005_folders.sql
│   │   ├── 006_messages.sql           ← partitioned by month
│   │   ├── 007_blobs_attachments.sql
│   │   ├── 008_aliases_groups.sql
│   │   ├── 009_rules.sql
│   │   ├── 010_calendar.sql
│   │   ├── 011_contacts.sql
│   │   ├── 012_tasks.sql
│   │   ├── 013_queues.sql             ← outbound_queue (LOGGED), journal_queue
│   │   ├── 014_system.sql
│   │   ├── 015_compliance.sql
│   │   ├── 016_identity_sync.sql
│   │   ├── 017_unlogged.sql           ← sessions, ws_subs, outbound_queue_hot, …
│   │   ├── 018_fk_and_extensions.sql
│   │   ├── 020_vacation.sql
│   │   ├── 021_greylist.sql
│   │   ├── 022_rate_limit.sql
│   │   ├── 023_dkim.sql
│   │   ├── 024_dlp.sql
│   │   └── 025_calendar_resources.sql
│   │
│   ├── reducers/              ← PL/pgSQL stored procedures
│   │   ├── deliver.sql
│   │   ├── deliver_group_vacation.sql
│   │   ├── send.sql
│   │   ├── rule_engine.sql
│   │   ├── rule_engine_or.sql
│   │   ├── startup_recovery.sql
│   │   ├── health_check.sql
│   │   ├── journal.sql
│   │   ├── retention.sql
│   │   ├── jmap_email.sql
│   │   ├── jmap_mailbox.sql
│   │   ├── jmap_email_submission.sql
│   │   ├── jmap_thread.sql
│   │   ├── jmap_calendar.sql
│   │   ├── jmap_contact.sql
│   │   ├── jmap_task.sql
│   │   ├── calendar_freebusy.sql
│   │   ├── calendar_itip.sql
│   │   └── utils.sql
│   │
│   ├── migrations/
│   │   ├── V001__initial_schema.sql   ← seeds extensions, runs schema + reducers, creates partitions
│   │   └── V002__calendar_phase9.sql
│   │
│   └── tests/                 ← pgTAP tests
│       ├── deliver.pg
│       ├── send.pg
│       └── rule_engine.pg
│
├── gateway/                   ← Go binary (thin protocol gateway, no business logic)
│   ├── go.mod                 ← Go 1.26; pgx, gorilla/websocket, minio-go (S3 client), etc.
│   ├── go.sum
│   ├── cmd/mailserverd/
│   │   └── main.go            ← Entry point: DB pools, startup recovery, routes, HTTP/2 + SMTP + IMAP + LDAP servers
│   ├── deploy/
│   │   └── pgbouncer.ini      ← Transaction-mode pooling config
│   └── internal/
│       ├── config/            ← Env-driven Config
│       ├── db/                ← pgxpool + direct LISTEN connection
│       ├── auth/              ← JWT, bcrypt, WebAuthn, TOTP, Kerberos, SAML, OIDC, chain
│       ├── middleware/        ← RequireAuth, RequireAdmin, metrics, rate limit, security headers
│       ├── handlers/          ← HTTP handlers (auth, jmap, ws, blob, health, rules, admin)
│       ├── notify/            ← LISTEN/NOTIFY dispatcher → WebSocket fan-out
│       ├── startup/           ← SeaweedFS/S3 bootstrap, recovery report
│       ├── migration/         ← IMAP/EWS/M365 connectors, orchestrator, credentials encryption
│       ├── smtp/              ← Inbound MTA, submission MSA, SPF/DKIM/DMARC/antispam/ClamAV
│       ├── imap/              ← IMAP4rev2 bridge
│       ├── ldap/              ← Read-only LDAP GAL server
│       ├── caldav/            ← CalDAV bridge (RFC 4791)
│       ├── carddav/           ← CardDAV bridge (RFC 6352)
│       ├── storage/           ← Backup/restore driver interface (S3, OSS)
│       ├── backup/            ← Manifest-based incremental blob backup
│       ├── restore/           ← Disaster recovery engine
│       ├── scim/              ← SCIM 2.0 server (RFC 7644) — IdP-driven user/group provisioning
│       └── deploy/            ← SeaweedFS systemd unit generation, HA planner
│
├── webmail/                   ← SvelteKit SPA — inbox, compose, calendar, contacts, tasks, admin
├── deploy/
│   ├── mailserver.service     ← systemd unit with security hardening
│
└── mobile/
    ├── ios/                   ← (empty placeholder — Phase 12.1)
    └── android/               ← (empty placeholder — Phase 12.2)
```

Directories `admin/` (standalone admin app, now merged into `webmail/src/routes/admin/`) and `scripts/` exist but are empty placeholders.

---

## Protocol Compliance

The project underwent a comprehensive protocol audit (May 2026) covering 24 protocols.
Findings (587 total: 148 HIGH, 230 MEDIUM, 209 LOW) have been systematically remediated
across 9 implementation waves. Current per-protocol compliance:

| Protocol | Before Audit | After (as of Wave 9) | Key Fixes |
|---|---|---|---|
| **ClamAV** | 28% (non-functional) | ✅ 95% | Fixed `z`→`n` command prefix |
| **DKIM** | 18% | ✅ 75% | Wired SignDKIM, body hash validation, Ed25519, key size enforcement |
| **SPF** | 30% | ✅ 85% | Case-insensitive, NXDOMAIN→none, macro expansion, ptr+exists, DNS limits |
| **DMARC** | 32% | ✅ 70% | Relaxed alignment, tree walk, pct enforcement, temperror handling |
| **TLS** | 54% | ✅ 85% | STARTTLS on 587/25, cert loading on 465/993, MinVersion enforcement |
| **SMTP** | 58% | ✅ 85% | STARTTLS, Received/Return-Path, state machine, MX fallback, dotStuff fix |
| **OIDC** | 53% | ✅ 100% | Full RP (login via external IdPs) + full OP/IdP (other apps login via us). OpenID Foundation certified (zitadel/oidc v3). |
| **TOTP** | 67% | ✅ 85% | Replay protection, per-account lockout, Kerberos TOTP bypass fixed |
| **Kerberos** | 58% | ✅ 70% | Realm enforcement, RequireHostAddr, MaxClockSkew; enctype limited by library |
| **SAML** | 48% | ✅ 75% | Login route registered, SHA-256 signing, assertion replay detection, signing |
| **JMAP Core** | 76% | ✅ 90% | RFC 7807 errors, ResultReference, URL templates, missing methods |
| **iCalendar/CalDAV** | 47% / 40% | ✅ 65% | Value escaping, DTSTAMP, SEQUENCE, UTF-8 folding, MKCALENDAR, DAV:error |
| **vCard** | 22% | ✅ 55% | ADR 7-field, value escaping, REV format, false v4.0 ad removed |
| **LDAP** | 38% | ✅ 70% | Filter parser (AND/OR/NOT), scope enforcement, DN escaping, STARTTLS |
| **IMAP4rev2** | 18% | ✅ 85% | All 23/27 commands: UIDVALIDITY, UIDNEXT, ESEARCH, FETCH/STORE ranges, MOVE/COPY/CLOSE/UNSELECT/NAMESPACE, STARTTLS+AUTHENTICATE |
| **DMARC** | 32% | ✅ 85% | Aggregate reporting (XML + outbound delivery), rua/ruf parsing, per-domain config |
| **MTA-STS** | 0% | ✅ 100% | Policy fetch/parse/cache, MX validation, VerifyConnection enforcement |
| **TLS-RPT** | 0% | ✅ 100% | Session recording, JSON reports, HTTPS POST, DNS discovery |
| **DANE** | 0% | ✅ 100% | DNSSEC resolver (miekg/dns), TLSA 4-mode validation, mandatory STARTTLS |

### Compliance infrastructure

- **Rules:** `.opencode/rules/` — 9 protocol rule files auto-loaded per session
- **RFC references:** `docs/rfcs/` — concise extracts of critical normative sections
- **Compliance tests:** `internal/{smtp,caldav}/` — 34 protocol compliance tests
- **Audit baseline:** original audit findings and improvement plan (private working notes, not in this repository)
- **Checklist:** `TODO.md` — all findings integrated as actionable `[x]`/`[ ]` checkboxes


## SCIM Provisioning (RFC 7644)

SCIM 2.0 server at `/scim/v2/{Users,Groups}` for IdP-driven lifecycle management. Entra ID and Okta provisioning agents push user CRUD and group membership operations via static Bearer tokens (separate from JWT auth).

- **Gateway-led** — all user/group CRUD flows through PL/pgSQL reducers (`scim_upsert_user`, `scim_disable_user`, etc.) which are the single canonical path for provisioning. The authserver is contacted only for session revocation on disable/delete.
- **Idempotent** — `scim_external_id` columns on `users` and `distribution_groups` make repeated PATCH/PUT ops safe.
- **Token auth** — `scim_tokens` table stores bcrypt-hashed API keys with per-token deletion policy (soft/hard) and configurable attribute mapping.
- **Incremental sync** — `GET /Users?syncToken=...` returns only changed resources since the cursor timestamp.
- **Feature toggle** — gated behind `SCIM_ENABLED` (default false). Admin UI for token management deferred to Phase 13.
- **CLI** — `mailctl scim create-token` / `mailctl scim list-tokens` for initial token provisioning.

See `docs/design/` for full design.

---

## Monitoring Infrastructure

### Admin Live Monitor (Wave 15)

Unified polling-based monitoring with no WebSocket dependency. All pages use 30s auto-refresh (default OFF, tab-session only, no persistence).

**Backend:** `gateway/internal/handlers/admin_monitor.go`
- `GET /admin/monitor/live?sections=dmarc,queue,volume,threats,system` — returns `LiveStats` struct
- Each section queries one table with indexed columns, sub-5ms response time
- System stats via `runtime.NumGoroutine()`

**Endpoints:**
| Endpoint | Purpose | Source Table |
|---|---|---|
| `/admin/monitor/live` | Unified live stats (all sections) | Multiple |
| `/admin/dmarc/live` | DMARC pass/fail/none today + per-domain | `dmarc_reports` |
| `/admin/dmarc/failures` | Last 100 failures + SPF/DKIM details | `message_trace` |
| `/admin/dmarc/trend` | 30-day DMARC trend data | `dmarc_reports` |

**Webmail pages:**
- `/admin` — Dashboard with live stats bar (volume, goroutines, RBL, auth failures)
- `/admin/dmarc` — DMARC monitor (stats cards, domain table, trend chart, failures list)
- `/admin/reports` — Daily report (mail flow + DMARC + virus + attack stats + email delivery config)
