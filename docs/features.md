# SetJoin Features

Merged from `docs/phases.md`, `docs/design/operations/competitive-roadmap.md`, and `docs/design/clients/feature-and-dependency-research.md`.

✅ Done · 📝 Planned · 🔨 In Progress · ⏸ Deferred · ❌ Not Started

These marks describe implementation inventory, not production maturity. The target
first-release GA/Beta/Experimental boundary is defined in
`docs/designs/release-maturity-and-first-ga-boundary.md`; no ✅ item inherits GA,
support, certification or production enablement from this catalog.

---

## Composable Workplace / 可组合工作平台

**A composable workplace. Choose your apps and providers. Keep control of your data.**
**集合：可组合的企业办公平台。应用按需选，服务可替换，数据自主掌控。**

- ✅ Existing foundations: reducer-authoritative domain data, provider-neutral Office
  interfaces and the closed Collabora CODE install/recovery path. These are not a
  general public marketplace; provider qualification/activation remain separate.
- 📝 Protected system apps: Mail, Drive, Calendar, Contacts and Tasks expose stable
  public commands, queries and events while retaining protected data authority.
- 📝 Optional apps and qualified providers: supported extension points for Office,
  AI, ASR and integrations, with compatibility and permission checks.
- 📝 Coordinated lifecycle: dependency-aware readiness, generation-fenced operations,
  owned-resource cleanup and accepted-work drain. Startup composition is default;
  live replacement needs per-capability qualification.
- 📝 Unified graphical management: dependencies, permissions, affected work, restart
  requirements, version compatibility and recovery in existing Apps/Sources/Updates UI.
- 📝 Community developer path: small manifest, SDK/examples, local conformance harness
  and automated submission; isolation and resource grants remain required.

Disabling an app is not data rollback, changing a storage provider is not migration,
and plugin interfaces do not make core security replaceable. No blanket zero-downtime,
offline-web, provider compatibility, licensing or certification claim is made.
See [positioning/claim matrix](product-positioning.md),
refactor program, and
existing-plan reconciliation.

## Mail Core

- ✅ PostgreSQL-as-app-server — PL/pgSQL reducers: deliver(), send(), apply_rules(), ~200 total (Phase 1)
- ✅ JMAP Core + Mail (RFC 8620/8621) — Mailbox, Email, Thread, SearchSnippet, Submission (Phase 3)
- ✅ JMAP Push (RFC 8887) + WebSocket (Phase 3.3)
- ✅ JMAP Calendar + Contacts (drafts) — CalendarEvent, ContactCard, AddressBook (Phase 3.4-3.5)
- ✅ SMTP Inbound MTA (:25) + Submission MSA (:587) — SPF/DKIM/DMARC/DANE/RBL/ClamAV (Phase 4)
- ✅ IMAP4rev2 Bridge (RFC 9051) (Phase 4)
- ✅ CalDAV (RFC 4791) + CardDAV (RFC 6352) (Phase 9-10)
- ✅ LDAP GAL Server — read-only global address list (Phase 10)
- ✅ Tag System (Gmail-style labels) — multi-label, exclusive groups, snooze (Phase 17)
- ✅ Rules Engine — eval_condition() + apply_action(), OR grouping, run_on (Phase 5)
- ✅ Distribution Groups + Shared Mailboxes (Phase 6)
- ✅ Vacation Auto-Reply — per-user, date-bounded (Phase 6)
- ✅ Migration Connectors — IMAP, EWS (NTLM+Basic), M365 Graph (OAuth2) (Phase 18)
- ✅ Storage Backups + Disaster Recovery — S3/OSS, manifest-based, integrity check (Phase 15)
- ✅ Go Cron Worker — 24 scheduled tasks, replaces pg_cron (Phase 15.2)
- ✅ Content Search + eDiscovery — KQL, PST/mbox export, case holds (Phase 14)
- ✅ Journaling — full envelope capture, BCC included (Phase 14)
- ✅ WORM Immutability — S3 Object Lock, SEC/FINRA/CFTC (Phase 14)
- ✅ DLP — pattern matching, admin UI, quarantine (Phase 7.9)
- ✅ Retention Policies + MRM templates (Phase 14.3)
- ✅ Full-Text Search — plain GIN + tsquery/ts_rank/ts_headline (Phase 36; the ParadeDB/BM25 index this line originally claimed never installed on any live deployment and was reverted 2026-07-04, see Phase 36 note)
- ✅ SMTP Pipeline — composable Check/Modify/Deliver, 9 checks, Milter (Phase 36)
- ✅ Per-User FTRL Spam Classifier — ML, PG NOTIFY training, 12 tests, admin dashboard + CLI (Phase 36)
- ✅ Undo Send + Snooze + Pin-to-Top (Phase 1.5)
- 🔨 Transport Rules (admin disclaimers) — add_header action, client-side rendering deferred (Phase 5.4)
- ⏸ Sieve Filtering (RFC 5228) — PL/pgSQL Rules engine covers use case; parser deferred
- ⏸ AI Email Features — local LLM vs cloud API needs further discussion (Phase 20.3)

## Security

- ✅ SPF / DKIM / DMARC — inbound + outbound (Phase 7)
- ✅ DNSSEC + DANE (SMTP TLSA) — inbound + outbound (Phase 7)
- ✅ MTA-STS + TLS-RPT (Phase 7)
- ✅ ARC (Authenticated Received Chain) (Phase 7)
- ✅ Anti-Spam — weighted rules, RBL, greylisting, ClamAV (Phase 7)
- ✅ Anti-Phishing — display-name spoofing, lookalike domains, contact graph (Phase 2.4)
- ✅ TOTP + WebAuthn/Passkeys (FIDO2) (Phase 2.3)
- ✅ Push MFA (number-match) — ECIES 2-digit challenge via APNs/FCM/HMS (Phase 12.2)
- ✅ Backup Codes — 10 single-use (Phase 2.3)
- ✅ SAML 2.0 SP + OIDC RP — enterprise SSO, JIT provisioning (Phase 2.3)
- ✅ OIDC IdP — zitadel/oidc v3, OpenID certified (Phase 31)
- ✅ Kerberos/SPNEGO — domain-joined Windows (Phase 2.3)
- ✅ LDAP/AD Identity Sync — TLS LDAPS, paged search (Phase 16)
- ✅ SCIM Provisioning (RFC 7644) — user lifecycle, group push (Phase 2.5)
- ✅ National Crypto (SM2/SM3/SM4) — config-level alternative (Phase 3.2)
- ✅ Threat Pipeline — 8-step: feed→IP→geo→lockout→spray→CAPTCHA→tarpit→rate (Phase 32)
- ✅ Rate Limiting — per-IP, per-user, per-protocol (Phase 7)
- ✅ Session Ticket Key Rotation — 24h, DB-persisted (Phase 7)
- ✅ App Passwords — per-app tokens, scope-limited (Phase 19)
- ✅ ACME TLS Automation (TLS-ALPN-01/HTTP-01) — autocert.Manager (Phase 7)
- ✅ Conditional Access Policy Engine — IP/location/device policies in shared/threat/ (Phase 3.5)
- ✅ MAM Policy Engine — 3-layer resolution (global→group→device), pg_notify push, device identity
- ✅ Cryptographic Agility — EK01 envelope format, AES-256-GCM/SM4-GCM hot-swap, always-on enforcement
- 📝 S3 Blob Encryption — deterministic AES/SM4 helpers exist but are not called by
  the live object path; the production streaming envelope and migration are held in
  `retired-docs:superpowers/plans/2026-09-01-storage-encryption-and-provider-migration.md`.
- ✅ PG Column Encryption — application-level envelope-wrapped, nil-safe, backward compatible
- ✅ Key Management — NIST SP 800-57 hierarchy, LoadCredential, rotation, compromise response
- ✅ 等保 Readiness — L2/L3 self-assessment checklist at /admin/compliance/dengbao
- ✅ Spam Enhancement — 16 detectors: OSB tokenizer, multi-class FTRL, fuzzy hashing, HTML fingerprinting
- ✅ RFC 7807 Error Handling — Problem Details for HTTP APIs, localized error messages (en/zh/de)
- ✅ Validation Layer — 3-tier (JS→Go→DB) with 7 validators; Conditional Email Address Policy engine: condition→template→priority via `email_address_policy_apply`, PG-native CJK pinyin transliteration via `cjk_to_ascii` (curated surname table + per-codepoint Unihan dict)
- ✅ ACME DNS-01 Challenge — Lego, 3 providers, air-gap (Phase 36)
- ✅ Link Protection — URL rewriting + Safe Browsing/Spamhaus scanning (handlers + routes live, Phase 1.3)
- ✅ Attachment Sandbox — CAPE behavioral analysis, pipeline check exists (Phase 1.4)

## Clients

- ✅ Webmail SPA — SvelteKit, Liquid Glass, inbox/compose/calendar/contacts/tasks/admin (Phase 8)
- ✅ Liquid Glass Design System — tokens.css (478 lines), cross-platform spec (Phase 8)
- ✅ Desktop App (Electron) — macOS/Windows/Linux; Tauri desktop is retired. Current
  client ownership and platform evidence: [clients/AGENTS.md](../clients/AGENTS.md).
- ✅ mail-core Rust Crate — JMAP client, SQLite cache, sync, 12 tests (Phase 12-A)
- ✅ guard-core Rust Crate — TOTP, ECDH, vault, 10 tests (Phase 12-A)
- ✅ desktop-core Rust Crate — updater, platform, 9 tests (Phase 12-A)
- ✅ Apple SwiftUI App — Liquid Glass shell, SF Symbols, Xcode project, compiles (Phase 12-B)
- ✅ Android App (Compose) — Gradle project, Theme, NavigationBar, builds in AS (Phase 12-C)
- ✅ UniFFI Bindings — Swift + Kotlin generation tooling (Phase 12-A)
- ✅ Auth Server Push Dispatchers — APNs/FCM/HMS, 80 tests (Phase 12-A)
- ✅ Contacts SPA — GAL + personal, org chart (Phase 10)
- ✅ Calendar SPA — scheduling assistant, room finder (Phase 9)
- ✅ Tasks SPA — Kanban + list, subtasks (Phase 11)
- ✅ User Safe/Blocked Sender Lists — GET/PUT /settings/senders (Phase 12)
- ✅ External Sender Warning Banners — GET/PUT /settings/external-sender, handler live (Phase 1.6)
- ✅ Undo Send + Snooze/Pin — undo_send handler live, UndoToast component (Phase 1.5)
- ✅ Markdown Paste (TipTap) — auto-converts **bold**, *italic*, `code`, [text](url) on paste, 10 tests
- ✅ Command Palette — Ctrl+K modal with fuzzy search, 17 actions, glass popover
- ✅ Shadow DOM Email — sandboxed HTML rendering, script stripping, link rewriting
- ✅ Keyboard Shortcuts — Gmail-style j/k nav, r/e/#/c, useKeyboard hook
- ✅ Contact Frequency Ranking — localStorage-based send count, autocomplete sorting
- ✅ Reduced Transparency/Motion — CSS fallbacks for accessibility (WCAG 2.2 §8.1)
- ✅ Per-Alias Signatures — CRUD at /settings/signatures, handler live (Phase 1.7)
- ✅ Internal Message Recall — POST /messages/{id}/recall, 5-min window (Phase 1.7)
- ✅ iOS App (native) — Liquid Glass, UniFFI 0.31.1 bindings, Release builds (Phase 12.1)
- ✅ Android App (native) — APK produced, Kotlin 2.3.21, AGP 9.2.1 (Phase 12.2)
- ✅ MAM (Mobile Application Management) — server-driven policy engine, device checkin, remote wipe/lock, notification profiles, per-platform enforcement, crypto agility (Phase 12.3)
- ✅ App Drawer — 钉钉-style slide-out workspace on all platforms (SwiftUI, Compose, Svelte, Tauri)
- ✅ User Settings — login devices, login history, TOTP management, notification preferences, security score
- ✅ HarmonyOS NEXT Port — ArkTS UI, NAPI bridge, HMS Push Kit, MAM enforcement, HAP build
- ✅ Permission-Based RBAC — 21 granular permissions, 6 predefined role groups, RequirePerm middleware, domain scoping
- 📝 Chinese Admin Console — zh-CN strings exist, pages not fully localized (Phase 12.9)
- ⏸ Offline/PWA Webmail — on-prem JMAP clients handle offline natively

## Admin Portal

- ✅ Dashboard — health, storage, message counts (Phase 13)
- ✅ User Management — CRUD, quotas, aliases, impersonation (Phase 13)
- ✅ Domain Management — DNS wizard (MX/SPF/DKIM/DMARC/MTA-STS/TLSA) (Phase 13)
- ✅ Mailbox Management — create, quota, delegates, import/export (Phase 13)
- ✅ Rule Templates — server-wide rules, visibility control (Phase 5)
- ✅ eDiscovery Cases + Content Search — KQL, PST/mbox export (Phase 14)
- ✅ Quarantine Management — virus/spam, release/delete (Phase 7.9)
- ✅ System — upgrade, maintenance windows, auto-update (Phase 15)
- ✅ RBAC — 21 granular permissions, 6 predefined roles, RequirePerm middleware, domain-scoped authorization (Phase 38)
- ✅ MAM Device Management — /admin/mam/devices list/detail, policy overrides, event timeline, lock/unlock
- ✅ MAM Policy Management — /admin/mam/policies global/group, templates save/load/export/import
- ✅ Role Management — /admin/roles CRUD, member assignment, permission editor, builtin protection
- ✅ Feature Toggles — per-feature enable/disable, DB-backed (Phase 30)
- ✅ DLP Pattern Management (Phase 7.9)
- ✅ TLS Certificate Management — /admin/tls, cert expiry + DNS-01 provider (Phase 36)
- ✅ Spam Classifier Dashboard — /admin/spam, model stats + FP rate + reset (Phase 36)
- ✅ Welcome email on mailbox creation — configurable, admin-editable, per-locale (en/zh/de); fires on interactive create (admin + SCIM), suppressed for bulk directory/CSV sync; `/admin/system/welcome-email`
- ✅ Admin CLI (mailctl) — restore, upgrade, DANE, SCIM, SMTP, TLS, spam
- ✅ Prometheus /metrics Endpoint — 13 metric families, TCP/TLS/method histograms (Phase 15)
- ✅ Grafana Dashboards — Gateway Overview, Protocol Breakdown, Security (Phase 15)
- ✅ Zabbix Template — 9 metrics with triggers for Chinese deployments (Phase 15)
- ✅ Domain-Scoped Authorization — DomainScope in Claims, domain-bound admin CRUD, H8 resolved (Phase 38)
- ✅ MFA Enforcement — mfa_status() policy check, BackupCodeVerify handler, password history with reuse prevention
- ✅ Common Password Check — top 10k embedded, SHA-256 lookup, integrated with all password change paths
- ✅ TOTP Audit Logging — setup, re-setup, confirmation events logged to admin_audit_log
- ✅ CJK→ASCII Transliteration — `cjk_to_ascii` PG function (surname-aware longest-match, per-codepoint Unihan fallback) used by the Email Address Policy engine to render template variables from CJK names; JIT standalone username auto-generation is not wired
- — JIT Email Verification — Not applicable. Self-hosted mail server (M6 closed as N/A)

## Collaboration Suite

- ✅ Meet (Pillar B1) — WebRTC conferencing on a self-hosted LiveKit SFU sidecar (`setjoin-sfu.service`), all business logic (create/join/lock/roles/end/attendance) in PL/pgSQL reducers; members join via reducer-authorized short-TTL LiveKit tokens, guests pass an app-level lobby before any token exists; a meeting's chat is an ordinary Chat channel; license-free codecs (VP9-SVC/AV1-opportunistic/VP8-fallback + Opus); client-side background blur. Guests get audio/video + reactions; **in-meeting chat is member-only (the guest-accounts program will lift this)**. `feature.meet`, DEFAULT OFF.
- ✅ Meet recording (Pillar B2) — host-initiated meeting recording to a meeting-bound Drive space, on a self-hosted LiveKit Egress sidecar (`setjoin-egress.service`) + a loopback Valkey bus (`setjoin-valkey.service`). Consent-first: the recording fact commits to the database, and a non-dismissible server-state banner shows for every participant, BEFORE a single frame is captured. **Guest-exclusive by construction**: no admitted guest is ever recorded and no recording can start while a guest is admitted — a fail-closed, race-free invariant, not a policy note. Recordings are WebM/VP8+Opus (royalty-free, browser-playable — the real LiveKit API cannot express VP9, a disclosed limitation). Playback is attendees-only (including after the meeting ends); an org admin registry (`GET /admin/meet/recordings`) lists every recording regardless of the toggle's state, for findability. Keep-forever by default in v1 (no auto-delete) — retention/disposition, sharing beyond attendees, and org-level retention knobs are explicit deferred seams, never silent behavior. `feature.meet_recording`, DEFAULT OFF (additionally requires `feature.meet` + `feature.drive` ON).
- ✅ Meet QoL (Pillar B3) — breakout rooms (host opens/assigns/closes, members auto-redirect on assignment, kick evicts from wherever the target actually is) with polls/Q&A/whiteboard riding the meeting's existing bridged chat and data-channel rails (zero new toggle for those three) behind `feature.meet_breakouts`, DEFAULT OFF; live captions — a self-hosted room-bot (`setjoin-asr-bot.service`) streams voice-active audio to a pinned FunASR runtime container (`setjoin-funasr.service`) and publishes attested per-speaker caption frames, a server-state toggle + finals-only transcript, guest-visible, captions retain no transcript anywhere (D4: coexists freely with recording, no BZ199-style exclusion) — behind `feature.meet_captions`, DEFAULT OFF (both toggles additionally require `feature.meet` ON; the two ASR systemd units are `install.sh`'s optional `MEET_CAPTIONS_ENABLED`-gated leg). Deferred: moderated/webinar Q&A, transcript persistence, breakout recording, guest breakouts/polls/Q&A/whiteboard (guest-accounts program), caption translation/meeting summaries, whiteboard persistence, timed breakouts, per-meeting caption language/additional ASR models, per-breakout attendance reporting.

## Platform / Infrastructure

- ✅ Koanf Config Migration — TOML-based, hot reload, 500 lines in shared/config/ (Phase 37.4)
- ✅ PgBouncer Connection Pooling — transaction mode (Phase 2.2)
- ✅ SeaweedFS / S3 Object Storage — SHA-256 dedup (Phase 1.5)
- ✅ Chinese i18n (en/de/zh) — detectLocale(), zh-CN, Noto Sans SC (Phase 42)
- ✅ Chinese Admin Docs — deployment, compliance, FAQ in zh-CN (Phase 1.8)
- ✅ Air-Gap Asset Bundling — fonts, icons, translations in binary (Phase 12)
- ✅ Cross-Arch Build — arm64/loong64, QEMU smoke tests (Phase 20.1)
- ✅ Go Workspace (go.work) — multi-module dev (Phase 37.4)
- ✅ HA Deployment — 3-node design, Pgpool-II config + failover scripts, HAProxy template (Phase 15)
- ✅ Self-Signed Certificate — mailctl cert generate-self-signed for dev/test/setup
- 🟡 S3 Storage Volume Migration — maintenance-only Provider byte-copy skeleton;
  no supported `mailctl storage-migrate`, online dual-write/fence, or on-the-fly
  encrypt/decrypt exists. Future work is review-held in
  `retired-docs:superpowers/plans/2026-09-01-storage-encryption-and-provider-migration.md`.
- ✅ Encryption Key Extraction — emergency runbook + integration test
- ✅ 39 RFCs Downloaded — full IMAP/SMTP/JMAP/CalDAV/LDAP/DKIM/SPF/DMARC/DANE/JWT/TOTP/SCIM reference set
- ✅ Shared Packages — validate, spam, permissions, httputil (RFC 7807), middleware (RequestID), i18n



## Deferred / Not Needed

- Mailet-Style Pluggable Processors — pipeline + Milter covers use cases
- Murder-Style Horizontal Scaling — not needed at 300-10k users
- Encrypted Search (Blind Indexing) — RLS already isolates tenant data
- External Search Index (Bleve/Meilisearch) — pg_search BM25 is a better fit
- Sieve Standalone Library — P2, Rules engine already covers use case
- Archive Mailbox — SeaweedFS/S3 tiered storage handles aging natively
- WeChat/WeCom Integration — WeChat is a competitor, not a partner
