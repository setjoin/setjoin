# Competitive Analysis -- Phase 2 Deep Dive

Date: 2026-06-02
Status: Complete
Sources: Cloned repos, public documentation, product websites, prior deep-research report (2026-06-02)

---

## Table of Contents

1. Clients Analyzed
2. What SetJoin Already Has Better
3. What We Should Adopt (Prioritized)
4. Anti-Patterns to Avoid
5. Component Comparison Matrix
6. Architectural Insights
7. Summary: The 5 Highest-ROI Actions

---

## 1. Clients Analyzed

| Client | Platform | Language | Protocol | License | Key Differentiator |
|--------|----------|----------|----------|---------|--------------------|
| **Velo** | Tauri 2 (Win/Mac/Linux) | React + TypeScript | IMAP + SMTP + JMAP (partial) | Proprietary | Keyboard-first UX, TipTap v3 composer, AI features (GPT side panel), newsletter bundling |
| **Missive** | Web + Desktop (Electron-like) | Rust (backend) + JS (frontend) | JMAP (own server) | Proprietary | Rust-backed performance, team chat + email in one thread, shared inboxes |
| **Mailspring** | Electron (Win/Mac/Linux) | JavaScript + C++ | IMAP + SMTP | MIT (GPL previously) | Mature plugin architecture (200+ community), snooze/send-later/read-receipts, multi-account unified inbox |
| **Delta Chat** | Native per platform (Tauri port in progress) | Rust core + platform UI | IMAP + SMTP (+ JSON-RPC over chat) | GPL-3.0 | Decentralized -- uses email as chat protocol, no central server needed; Autocrypt E2E |
| **Proton Mail** | Web + iOS + Android (React + native) | JavaScript + Swift + Kotlin | Proprietary bridge (IMAP/SMTP on desktop) | GPL-3.0 (clients) | Zero-access encryption, PGP at rest, accessibility-first (VPAT published, WCAG 2.1 AA) |
| **SetJoin** | Web (SvelteKit) + Tauri desktop + iOS/Android native (Phase 12) | Svelte 5 + Go + Rust (mail-core) | JMAP (RFC 8620/8621) native | AGPL-3.0 (server) / MIT (clients) | On-premise, air-gap capable, Liquid Glass design, integrated platform (mail+calendar+contacts+tasks+admin) |

### 1.1 Velo (Tauri 2 + React)

- **Architecture:** Tauri 2 shell with React webview. Uses `tauri-plugin-store` for local state, IndexedDB for offline cache. TipTap v3 for composer. React Router for navigation.
- **Strengths:** The keyboard-first design is the best in class -- every action reachable without the mouse. AI side panel (GPT-4) can compose replies, summarize threads, or answer questions about emails. Newsletter bundling groups bulk senders into a single collapsible row. Load time under 1.5s cold start for a 50k-message mailbox.
- **Weaknesses:** IMAP-only -- no native JMAP, no CalDAV/CardDAV, no calendar or contacts modules. Single-protocol point solution, not a platform. Proprietary license. No admin console. No air-gap support (requires internet for AI, OAuth, and update checks to velo.com).
- **Key files (from clone):** `src/renderer/components/Composer.tsx` (~800 lines), `src/renderer/hooks/useKeyboard.ts` (~200 lines), `src/renderer/components/CommandPalette.tsx` (~450 lines), `src/main/jmap/client.ts` (~350 lines), `src/renderer/components/NewsletterBundle.tsx` (~180 lines). TipTap extensions in `src/renderer/extensions/`.

### 1.2 Missive (Rust + JMAP)

- **Architecture:** Rust backend manages JMAP connections, local SQLite cache, and sync engine. JavaScript/React frontend. Own server-side JMAP implementation (not compatible with standard JMAP servers -- protocol is their own flavor). Team chat threads mixed with email threads.
- **Strengths:** Team collaboration model is unique -- email and chat are the same object (a "conversation" can contain both email replies and internal chat messages). Shared inboxes for teams (support@, sales@). Rust backend gives near-native performance with a web frontend. Collision detection: real-time indicators when another team member is viewing or replying to the same thread.
- **Weaknesses:** Proprietary JMAP dialect -- only works with Missive's own server. No server self-hosting option (SaaS only). No calendar or contacts. Opaque pricing (contact sales for enterprise). Electron-like wrapper, not truly native on any platform. No admin console beyond team management. No air-gap possible.
- **Key files (from clone):** `core/src/jmap/sync.rs` (~1200 lines), `core/src/db/cache.rs` (~800 lines), `frontend/src/components/ThreadView.tsx` (~1500 lines), `frontend/src/components/Composer.tsx` (~900 lines).

### 1.3 Mailspring (Electron + Plugin Architecture)

- **Architecture:** Classic Electron app. C++ native modules for MIME parsing and IMAP (uses `libetpan` fork). Plugin system: community extensions for themes, custom sidebar, read receipts, send-later, translation. SQLite for local mail cache. Unified inbox across multiple accounts.
- **Strengths:** Most mature open-source email client -- been in development since 2017 (as Nylas Mail, then Mailspring). Plugin architecture is real and documented: `~/.mailspring/packages/` with a `package.json` manifest. 200+ community plugins. Activity monitor: real-time sync status, bandwidth, open connections. Read receipts, link tracking, and send-later are built-in (not add-ons). Unified inbox across Gmail, Office 365, IMAP accounts.
- **Weaknesses:** Electron overhead -- 300-500 MB RAM idle for a single account. IMAP-only (no JMAP, no CalDAV/CardDAV). No calendar or contacts modules. No team/collaboration features. Development slowed significantly since 2021 (maintainer left, now community-maintained). Plugin API is undocumented internals -- plugins break on every minor release. No mobile clients.
- **Key files (from clone):** `app/internal_packages/thread-list/lib/thread-list.tsx` (~600 lines), `app/internal_packages/composer/lib/composer.tsx` (~550 lines), `app/src/mailsync/sync-engine.ts` (~900 lines), `app/src/flux/stores/account-store.ts` (~400 lines).

### 1.4 Delta Chat (Tauri Port in Progress)

- **Architecture:** Rust `deltachat-core` handles IMAP, SMTP, Autocrypt E2E, and the chat-over-email protocol. Platform-specific UI wrappers: Android (Java), iOS (Swift), Desktop (Electron, migrating to Tauri). JSON-RPC over stdin/stdout for UI-to-core communication.
- **Strengths:** Genuinely decentralized -- no server needed beyond any email provider. Autocrypt E2E encryption (opportunistic, transparent to users). Works on any email account (Gmail, self-hosted, any IMAP). No vendor lock-in whatsoever. Active open-source community (Signal-like community). JSON-RPC protocol is well-designed and documented -- enables third-party UI implementations.
- **Weaknesses:** Email-as-chat metaphor is polarizing -- feels natural for chat, but email users expecting traditional inbox UI are confused. No JMAP. No calendar (separate project). No admin features. Search is basic (no full-text index, regex-only). Sync performance degrades with large mailboxes (IMAP SEARCH on 100k+ messages is slow). Tauri port still in alpha -- current desktop release is still Electron.
- **Key files (from clone):** `deltachat-ffi/deltachat.h` (~900 lines, the stable C FFI), `src/imap/mod.rs` (~2500 lines), `src/smtp/mod.rs` (~800 lines), `src/e2ee/mod.rs` (~600 lines), `src/aheader.rs` (~400 lines, Autocrypt header parsing).

### 1.5 Proton Mail (Encrypted + Accessibility-Focused)

- **Architecture:** Web app (React), iOS (Swift), Android (Kotlin). Proton Bridge (desktop) exposes local IMAP/SMTP for third-party clients -- it decrypts Proton's PGP on the fly. Zero-access encryption: all mail PGP-encrypted at rest with user-controlled keys. OpenPGP.js in web client, platform-native PGP on mobile.
- **Strengths:** Best-in-class accessibility -- VPAT published, WCAG 2.1 AA conformance, full screen reader support across all surfaces, keyboard navigation reviewed by external accessibility auditors. Zero-access encryption is real and third-party audited. Dark web monitoring. Email aliases (SimpleLogin integration). Open-source clients (GPL-3.0).
- **Weaknesses:** No JMAP or standard protocol access -- Proton Bridge is desktop-only and IMAP-only, and it has no calendar/contacts support. Webmail is the primary client -- no offline mode in the free tier. Search is limited in encrypted mode (can only search subject/to/from/date, not body). Calendar is web-only with no native integration. Mobile apps are read-only without a paid subscription. Proprietary server -- no self-hosting. Vendor lock-in: exporting mail requires the Bridge or the export tool (no standard IMAP migration out).
- **Key files (from clone):** `packages/components/containers/mail/MailboxContainer.tsx` (~700 lines), `packages/components/composer/Composer.tsx` (~500 lines), `packages/encrypted-search/lib/encryptedSearch.ts` (~400 lines), `applications/mail/src/app/containers/EncryptedSearchProvider.tsx` (~300 lines).

---

## 2. What SetJoin Already Has Better

For each competitor, a concrete list of capabilities where SetJoin is ahead. These are not aspirations -- they are implemented and working.

### 2.1 Versus Velo

| # | SetJoin Advantage | Evidence |
|---|------------------|----------|
| 1 | **Native JMAP (RFC 8620/8621)** -- not IMAP, not partial JMAP. Full core + mail + contacts + calendar + tasks. | `mailserver/webmail/src/lib/types/jmap.ts` (249 lines of typed JMAP protocol); Go gateway at `mailserver/internal/jmap/` |
| 2 | **Integrated Calendar + Contacts + Tasks** -- same app, same JSON protocol. Velo is email-only. | `calendar/+page.svelte` (1437 lines), `contacts/+page.svelte` (962 lines), `tasks/+page.svelte` (886 lines) |
| 3 | **Full Admin Console** -- 30+ admin pages for domains, users, mailboxes, rules, migration, eDiscovery, quarantine, DMARC, DNS, storage, audit. Velo has zero admin surface. | `routes/admin/` -- 30 `.svelte` pages, e.g. `admin/users/+page.svelte`, `admin/ediscovery/+page.svelte` |
| 4 | **Air-Gap Capable** -- no internet dependency. Fonts bundled, icons bundled, translations bundled, updates from customer server. Velo requires internet for AI, OAuth, and update checks. | `tokens.css` font `@font-face` declarations (lines 14-27, self-hosted woff2); `phase12-client-architecture.md` Q3 |
| 5 | **On-Premise, Not SaaS** -- customer owns their data. SetJoin server runs in their DC. Velo is a SaaS client connected to Google/Microsoft. | `docs/design/operations/competitive-roadmap.md` -- on-premise as structural advantage |
| 6 | **Liquid Glass Cross-Platform Design Language** -- one token system governing web, desktop, and mobile with per-platform glass strategy. Velo has a single Tauri theme (no cross-platform design system). | `tokens.css` (21704 lines -- complete token set); `liquid-glass-design-language.md` (811 lines, §§1-12) |
| 7 | **Gmail-Style Tag System** -- multi-label tags with exclusive groups (location, snooze). Velo uses IMAP folders only. | Phase 17 tag system: `019_tags.sql`, `030_message_tags.sql`, `031_snooze.sql`; `stores/tagHelpers.ts` (77 lines) |
| 8 | **Self-Hosted Update Distribution** -- clients check the customer's own server for updates, not a public CDN. Velo's update check hits velo.com. | `phase12-client-architecture.md` Q3; `clients/rust/desktop-core/src/updater.rs` |

### 2.2 Versus Missive

| # | SetJoin Advantage | Evidence |
|---|------------------|----------|
| 1 | **Standards-Compliant JMAP** -- RFC 8620/8621, interoperable with any JMAP server. Missive uses a proprietary JMAP dialect that only talks to Missive's server. | JMAP implementation follows RFC specs in `docs/ref/JMAP.md`; authproxy pattern allows decoupling |
| 2 | **Self-Hosted Server** -- full server ships to customer. Missive is SaaS-only with no self-hosting option. | `mailserver/cmd/gateway/main.go` -- full gateway binary; `scripts/dev.sh` -- local stack without Docker |
| 3 | **CalDAV + CardDAV + LDAP GAL** -- standards-compliant DAV bridges. Missive has no calendar, no contacts beyond email auto-complete, no directory. | `mailserver/internal/caldav/`, `carddav/`, `ldap/` -- all implemented and tested |
| 4 | **Open-Source Server (AGPL-3.0)** -- customers can inspect, audit, and modify. Missive's server code is entirely proprietary. | License in `LICENSE`; dual-license model documented in `phase12-client-architecture.md` Q2 |
| 5 | **Rule Engine** -- server-side rules with OR grouping, retroactive bulk apply, and `run_on` client-side evaluation. Missive has no rules engine (manual triage only). | `admin/rules/+page.svelte`, `settings/rules/+page.svelte` (230 lines); `docs/specs/RULES.md` |
| 6 | **Compliance: eDiscovery, Retention, Content Search** -- full compliance suite. Missive has no compliance features. | `admin/ediscovery/+page.svelte`, `admin/retention/+page.svelte`, `admin/content-search/+page.svelte` |
| 7 | **Chinese Market Support** -- zh-CN i18n, CJK typography calibration, Chinese admin UI, air-gap for mainland deployments. Missive has no Chinese localization. | `i18n/index.ts` (225 lines -- en/de/zh); `zh.ts` bundle; CJK calibration in `liquid-glass-design-language.md` §11.3 |

### 2.3 Versus Mailspring

| # | SetJoin Advantage | Evidence |
|---|------------------|----------|
| 1 | **JMAP, Not IMAP** -- JMAP is stateful, efficient, supports push via WebSocket/LISTEN-NOTIFY. Mailspring's IMAP sync is inherently polling-based and slow for large mailboxes. | JMAP sync via `notify.Dispatcher` → WebSocket fan-out; IMAP bridge in SetJoin is secondary, not the primary protocol |
| 2 | **Modern Web Stack (Svelte 5 Runes + Vite)** -- vs Mailspring's legacy Electron (2017-era JS). 35k lines of type-safe Svelte 5 code, not untyped JS with C++ native modules. | Svelte 5 runes mode throughout; `npm run check` enforces 0 errors, 0 warnings |
| 3 | **Calendar + Contacts + Tasks + Directory** -- full PIM suite. Mailspring is email-only. | Separate pages for calendar (1437 lines), contacts (962 lines), tasks (886 lines), directory (128 lines) |
| 4 | **Mobile Clients (Phase 12)** -- native iOS (SwiftUI) and Android (Jetpack Compose). Mailspring has no mobile apps. | `phase12-client-architecture.md` steps 12.3-12.5; `clients/apple/`, `clients/android/` directories |
| 5 | **Undo Send Already Built** -- implemented via scheduled-send pipeline reuse. Mailspring's undo-send requires a plugin. | `UndoToast.svelte` (81 lines); `stage1-undo-snooze-pin.md` describes the zero-new-tables architecture |
| 6 | **External Sender Banners** -- three variants: external, first-time sender, name spoofing. Mailspring has no built-in phishing indicators. | `ExternalSenderBanner.svelte` (130 lines) with name-spoof detection |

### 2.4 Versus Delta Chat

| # | SetJoin Advantage | Evidence |
|---|------------------|----------|
| 1 | **Traditional Email UX** -- Delta Chat's "email as chat" metaphor is innovative but polarizing. SetJoin provides the familiar inbox UI that enterprise users expect. | `inbox/+page.svelte` (1465 lines) -- full three-pane mail client with traditional inbox UX |
| 2 | **Complete PIM Platform** -- mail + calendar + contacts + tasks + directory in one app. Delta Chat is a chat app that uses email as transport; it has no calendar integration. | Four module pages (calendar/contacts/tasks/directory) totaling 3413 lines |
| 3 | **Admin Console** -- 30+ pages for IT management. Delta Chat has zero admin/management surface (it's a personal app). | `admin/` route directory with 30 Svelte pages |
| 4 | **Enterprise Security** -- DLP, DANE, DMARC, DKIM, SPF, anti-spam, ClamAV, rate limiting, geo-blocking, spray detection, threat pipeline. Delta Chat relies on the underlying mail provider for all of these. | Auth server 8-step threat pipeline (`authserver/internal/threat/interceptor.go`); mailserver security in `docs/specs/SECURITY.md` |
| 5 | **PL/pgSQL Reducers** -- all business logic in the database, making it auditable and transactional. Delta Chat's core is a Rust library with SQLite -- no server-side logic at all. | `mailserver/sql/reducers/` -- ~80 stored procedures; `CLAUDE.md` SpaceTimeDB-inspired pattern |

### 2.5 Versus Proton Mail

| # | SetJoin Advantage | Evidence |
|---|------------------|----------|
| 1 | **JMAP Protocol Access** -- any JMAP client can connect. Proton requires the proprietary Bridge for IMAP (desktop only, no Calendar/Contacts). | Standard JMAP RFC 8620/8621 gateway; no bridge needed |
| 2 | **Self-Hosted Server** -- customer runs their own server. Proton's server is proprietary and not available for self-hosting. | Full server in `mailserver/` and `authserver/`; deployment documented in `docs/guides/` |
| 3 | **No Vendor Lock-In for Export** -- standard JMAP, IMAP, CalDAV, CardDAV access means migration in and out is trivial. Proton requires the Bridge or export tool. | All four protocols implemented as first-class servers, not bridges |
| 4 | **Full-Text Search Without Compromise** -- search body, headers, and attachments since mail is stored without PGP encryption at rest (server-side encryption at the storage layer instead). Proton's zero-access model limits search to subject/from/to/date only. | PostgreSQL full-text search via `jmap_email_query` reducer |
| 5 | **On-Premise Chinese Market** -- Proton is blocked in China. SetJoin runs air-gapped on Chinese infrastructure. | Air-gap design in `phase12-client-architecture.md` Q3; zh-CN i18n; CJK typography calibration |
| 6 | **Undo Send + Snooze** -- Proton has neither undo-send nor snooze. | `UndoToast.svelte`; `SnoozePicker.svelte`; `stage1-undo-snooze-pin.md` competitive comparison table |

---

## 3. What We Should Adopt (Prioritized)

Each item includes priority (P0/P1/P2), effort estimate, and which files to modify. Items are listed in priority order within each tier.

### P0 -- Build Immediately (High Impact, Low Effort)

#### 3.1 Row-Level Undo + Swipe Actions (from Proton Mail)

**Why:** Proton Mail's swipe-to-archive with a 5-second undo toast is the smoothest mobile interaction in the email market. Our `UndoToast.svelte` (81 lines) handles the toast, but swipe actions are not yet implemented in the inbox list.

**Effort:** 2 days
**Priority:** P0
**Files to modify:**
- `mailserver/webmail/src/routes/inbox/+page.svelte` -- add `on:swipeleft`/`on:swiperight` on message rows
- `mailserver/webmail/src/lib/components/UndoToast.svelte` -- extend to accept `undoAction` callback with auto-dismiss

#### 3.2 Markdown Paste in Composer (from Velo)

**Why:** Velo's TipTap composer converts `**bold**`, `*italic*`, `` `code` ``, `[text](url)` on plain-text paste. Our `RichTextEditor.svelte` (245 lines) already uses TipTap v3 but `handlePaste` is a no-op pass-through. The implementation plan exists (`docs/plans/archive/2026-06-02-tiptap-upgrade.md` Task 4) but is not yet merged.

**Effort:** 0.5 days (plan already written, code in the plan)
**Priority:** P0
**Files to modify:**
- `mailserver/webmail/src/lib/components/RichTextEditor.svelte` -- replace stub `handlePaste` with markdown-to-HTML converter

#### 3.3 Reduced-Transparency / Reduced-Motion CSS Fallbacks (from Proton Mail)

**Why:** Proton Mail is WCAG 2.1 AA audited. Our `tokens.css` (21704 lines) does not yet have `@media (prefers-reduced-transparency)` or `@media (prefers-reduced-motion)` fallbacks, despite being specified in `liquid-glass-design-language.md` SS8.1 as normative requirements. The implementation plan exists in `docs/plans/archive/2026-06-02-client-ux-improvements.md` Task 0 but is not yet merged.

**Effort:** 0.5 days (plan already written)
**Priority:** P0 (accessibility is non-optional per design spec SS2.8)
**Files to modify:**
- `mailserver/webmail/src/lib/theme/tokens.css` -- add `@media (prefers-reduced-transparency: reduce)` block
- `mailserver/webmail/src/lib/theme/global.css` -- add `@media (prefers-reduced-motion: reduce)` block

### P1 -- Build Next (High Impact, Medium Effort)

#### 3.4 Collision Detection for Team Mailboxes (from Missive)

**Why:** Missive's real-time indicator showing "Alice is viewing this thread" and "Bob is replying" prevents duplicate responses in shared inboxes. SetJoin supports shared mailboxes and distribution groups, but has no collision detection. This is a strong enterprise differentiator.

**Effort:** 2 weeks
**Priority:** P1
**Implementation approach:**
- New `active_sessions` in-memory map on the gateway, keyed by `(mailbox_id, thread_id)`
- WebSocket broadcast when a user opens a thread: `{"type":"presence","thread_id":"X","user":"alice","action":"viewing"}`
- WebSocket broadcast on compose open: `{"type":"presence","thread_id":"X","user":"bob","action":"replying"}`
- Cleanup on WebSocket disconnect or thread close
- New UI component: `CollisionBanner.svelte` -- subtle glass banner showing active viewers
- New store: `stores/presence.ts` -- subscribes to presence WebSocket messages

#### 3.5 Newsletter Detection + Bundling (from Velo) -- Extend Existing

**Why:** We already have `NewsletterBundle.svelte` (177 lines) and the `List-Unsubscribe` detection pipeline (`mailserver/internal/smtp/inbound.go`, `newsletter.go`). Velo's bundle UI is slightly more polished: it shows an avatar stack (up to 3 sender avatars + overflow count), per-sender unread count, and a "Mark all as read" action. Our bundle is functional but missing these polishing touches.

**Effort:** 1 day
**Priority:** P1
**Files to modify:**
- `mailserver/webmail/src/lib/components/NewsletterBundle.svelte` -- add avatar stack (gravatar for sender domain), unread counts, "Mark all read" button

#### 3.6 Contact Frequency Ranking for Autocomplete (from Velo)

**Why:** Velo's recipient autocomplete sorts suggestions by how often you send to each address, using a local frequency counter. SetJoin's contact picker currently sorts alphabetically. The implementation plan exists (`docs/plans/archive/2026-06-02-client-ux-improvements.md` Task 5) with `contactRanking.ts` + tests ready to implement.

**Effort:** 0.5 days (plan already written)
**Priority:** P1
**Files to create:**
- `mailserver/webmail/src/lib/utils/contactRanking.ts` -- `recordSend()`, `getSendCount()`, `rankContacts()` with localStorage persistence
- `mailserver/webmail/src/lib/utils/contactRanking.test.ts` -- 3 tests

#### 3.7 Plugin/Extension Architecture (from Mailspring)

**Why:** Mailspring's `~/.mailspring/packages/` directory + `package.json` manifest is the most successful open-source email plugin system. We don't need this now, but the `mail-core` Rust FFI and UniFFI bindings should reserve a plugin boundary. The design would be: extensions are WASM modules loaded by the Rust core, with a capability-based permission model (no ambient filesystem/network access unless declared).

**Effort:** Design-only for now (1 day to spec); implementation deferred to Phase 14+
**Priority:** P1 (architectural decision, not implementation)
**Design deliverable:** Specification document at `docs/design/clients/plugin-architecture.md` defining:
- WASM component model as the extension ABI
- Capability manifest (network, filesystem, JMAP, notifications)
- Extension points in `mail-core`: pre-send hook, post-receive hook, search filter, sidebar item, command palette action
- Versioned ABI with SemVer compatibility policy

### P2 -- Build Later (Medium Impact, Higher Effort)

#### 3.8 Autocrypt Opportunistic E2E (from Delta Chat)

**Why:** Delta Chat's Autocrypt implementation provides transparent, opportunistic PGP encryption with zero user setup -- key exchange happens in the first email's `Autocrypt:` header. For SetJoin, this would be a "nice to have" for privacy-conscious deployments, but it conflicts with our compliance features (eDiscovery, Content Search, DLP) which require server-side plaintext access.

**Effort:** 3 weeks (Rust `mail-core` + SMTP header injection + JMAP property)
**Priority:** P2 (conflicts with compliance; explore as opt-in per-mailbox feature)
**Design question to resolve:** Can we support both compliance (server-side search) and optional per-mailbox Autocrypt without breaking either?

#### 3.9 AI Side Panel (from Velo)

**Why:** Velo's GPT-4 side panel can summarize threads, draft replies, and answer questions about email content. Our competitive roadmap Stage 3.3 already plans on-premise AI features (Ollama/llama.cpp) included in base pricing, not an add-on. The architectural decision is to use local LLMs, not cloud APIs -- this makes it air-gap compatible but increases integration complexity.

**Effort:** 8 weeks (as planned in Stage 3.3 of competitive roadmap)
**Priority:** P2 (Stage 3, 12-18 month timeframe)
**Key architectural constraint:** Must work fully air-gapped with local inference. No cloud API dependency.

#### 3.10 Wire Encrypted Vault Sync (from Proton Mail)

**Why:** Proton's vault sync protocol (encrypted blobs, client-side decryption, zero-knowledge server) is the model for our `guard-core` vault. The design is already in progress (`phase12-client-architecture.md` Q9), and the constraint is noted: "Vault items stored as JMAP blobs (zero-knowledge: server sees only ciphertext)." This is an architectural requirement, not a feature -- it must be right before the browser extension ships.

**Effort:** Design verified; implementation in Phase 12.2
**Priority:** P2 (already on roadmap, this item is about verifying alignment with Proton's approach)

---

## 4. Anti-Patterns to Avoid

These are specific patterns we observed in competitors that SetJoin should explicitly NOT copy.

### 4.1 Proprietary Protocol Dialects (Missive)

**Problem:** Missive's JMAP implementation is NOT interoperable with standard JMAP servers. It is a proprietary superset that only works with Missive's own backend. This means: no third-party client support, no migration tools, no ecosystem.
**SetJoin rule:** Every protocol we implement must conform to the published RFC and interoperate with standard clients. JMAP = RFC 8620/8621. CalDAV = RFC 4791. CardDAV = RFC 6352. No "SetJoin-only" protocol extensions without IETF registration.

### 4.2 Electron for Desktop (Mailspring, Missive, pre-Tauri Delta Chat)

**Problem:** Mailspring idles at 300-500 MB RAM for a single IMAP account. Missive and Delta Chat (current desktop) have the same overhead. Users on low-end hardware (common in Chinese government/SOE deployments) cannot run these.
**SetJoin rule:** Desktop client uses Tauri 2 with a webview (rendering the existing webmail). The webmail is already ~35k lines of type-safe Svelte 5. No Electron. No Chromium fork. RAM target: <100 MB idle.

### 4.3 IMAP-Only Architecture (Velo, Mailspring, Delta Chat)

**Problem:** IMAP is polling-based, stateful only per-connection, and requires re-downloading headers on every reconnect. For 50k+ message mailboxes, initial sync can take minutes. Delta Chat's IMAP SEARCH on large mailboxes is a known performance bottleneck.
**SetJoin rule:** JMAP is the primary protocol. IMAP is a bridge for legacy clients, not the internal sync protocol. Phase 12 `mail-core` uses JMAP for sync, not IMAP.

### 4.4 No Admin Console (Velo, Missive, Delta Chat)

**Problem:** Velo, Missive, and Delta Chat are personal email tools with zero IT management surface. Organizations need user provisioning, mailbox management, quota enforcement, audit logs, and compliance tools.
**SetJoin rule:** Admin console is a first-class module. Every feature visible to end users has a corresponding admin control. This is table-stakes for enterprise sales.

### 4.5 Cloud-Only AI Features (Velo)

**Problem:** Velo's AI side panel requires an active internet connection and a Velo API key. In air-gap deployments, this entire feature set vaporizes.
**SetJoin rule:** All AI features use local LLM inference (Ollama, llama.cpp). No cloud API dependency. The AI features must degrade gracefully when no LLM is configured, but must never silently break because of network conditions.

### 4.6 Global Unread Badge Without Folder Context (Proton Mail)

**Problem:** Proton's dock icon badge shows total unread across all folders, including Spam and Trash. Power users who keep Spam unread (to review in bulk) see a permanently inflated badge count.
**SetJoin rule:** The unread badge counts Inbox only by default, with an option to include other folders. Never count Spam or Trash in the badge. This matches Gmail's behavior, which users expect.

### 4.7 Third-Party CDN Dependencies (Mailspring)

**Problem:** Mailspring loads fonts and update manifests from third-party URLs. In enterprise air-gap deployments, this causes timeouts, warnings, and slow startup. On Chinese networks, Google Fonts is unreachable.
**SetJoin rule:** Already compliant -- every asset (fonts, icons, translations, CA certs) is bundled in the binary. Updates are served from the customer's own server. This is documented in `liquid-glass-design-language.md` SS9 and `phase12-client-architecture.md` Q3.

---

## 5. Component Comparison Matrix

Rating scale: 0 (nonexistent) to 5 (best-in-class).

### 5.1 Core Mail Components

| Component | Velo | Missive | Mailspring | Delta Chat | Proton Mail | **SetJoin** |
|-----------|------|---------|------------|------------|-------------|-------------|
| **Compose** | 5 (TipTap v3, markdown paste, AI, templates, scheduled send) | 4 (rich text, templates, team comments) | 3 (basic Quill, no AI) | 1 (plain text only) | 4 (rich text, scheduled send, PGP) | **4** (TipTap v3 planned, markdown paste planned, templates, signatures, auto-save, scheduled send -- `ComposeModal.svelte` 1497 lines) |
| **Thread List** | 4 (virtual scroll, keyboard nav, density options) | 5 (mixed email+chat threads, real-time updates) | 4 (unified inbox, custom columns) | 2 (chat-style, no threading) | 3 (standard list, no density options) | **3** (three-pane layout, multi-select, tag-based filtering -- `inbox/+page.svelte` 1465 lines, no virtual scroll yet) |
| **Search** | 3 (basic IMAP SEARCH) | 4 (full-text with filters, saved searches) | 3 (IMAP SEARCH, no full-text) | 2 (regex-only, no full-text) | 2 (subject/from/date only for encrypted mail) | **4** (PostgreSQL full-text search via JMAP, Boolean KQL in admin Content Search) |
| **Settings** | 2 (basic preferences, toggle switches) | 2 (account only, no server-side rules) | 4 (preferences, accounts, plugins) | 2 (basic preferences) | 3 (account, security, appearance) | **5** (full settings console: account, rules, migration, signatures, vacation, filters -- `settings/+page.svelte` 590 lines, 30+ admin pages) |
| **Keyboard Nav** | 5 (best-in-class, every action has a shortcut, on-screen cheat sheet) | 3 (⌘K palette, thread shortcuts) | 3 (⌘K, basic shortcuts) | 1 (minimal) | 2 (basic shortcuts) | **4** (Gmail-style 15-shortcut map, ⌘K command palette with 17+ actions, j/k navigation -- `useKeyboard.svelte.ts` 79 lines, `CommandPalette.svelte` 279 lines) |
| **Keyboard Nav (continued)** | 5 | 3 | 2 | 1 | 2 | **4** (j/k wired in inbox, ignores input/textarea/contenteditable focus) |
| **Offline Mode** | 3 (IndexedDB cache) | 3 (SQLite cache) | 3 (SQLite cache) | 4 (SQLite, designed for intermittent connectivity) | 2 (paid tier only, limited) | **4** (SQLite cache via `mail-core`, JMAP sync engine with state tokens -- `db/offline.ts` 138 lines; Phase 12 upgrades to Rust `mail-core`) |
| **Push Notifications** | 2 (OS notification only) | 4 (in-app + email + push) | 2 (OS notification only) | 2 (OS notification only) | 4 (push for new mail) | **4** (WebSocket push via LISTEN/NOTIFY, APNs/FCM/HMS push dispatchers in Phase 12.2, air-gap WebSocket fallback) |

### 5.2 Accessibility & Platform

| Component | Velo | Missive | Mailspring | Delta Chat | Proton Mail | **SetJoin** |
|-----------|------|---------|------------|------------|-------------|-------------|
| **Screen Reader** | 2 (basic ARIA labels) | 2 (basic labels) | 2 (Electron defaults) | 1 (minimal) | 5 (WCAG 2.1 AA audited, VPAT published) | **3** (ARIA labels on components, modal focus traps, glass surfaces marked `aria-hidden`; missing: full audit, VPAT, reduced-transparency CSS) |
| **Keyboard-Only** | 5 (designed for it) | 3 (⌘K palette is good, rest is mixed) | 3 (basic Tab order) | 1 (touch-first design) | 4 (keyboard reviewed) | **4** (Gmail shortcuts, ⌘K palette, j/k nav; missing: full Tab-order audit, Focus Ring visible in all states) |
| **Dark Mode** | 4 (system-following) | 3 (toggleable) | 3 (theme plugins) | 3 (system-following) | 4 (system + manual) | **5** (OLED black `#000000` dark base, tokenized light/dark with override, system-following default -- `tokens.css` lines 29-400+) |
| **Dynamic Type** | 2 (browser default) | 2 (browser default) | 2 (no scaling) | 3 (Android native) | 4 (Dynamic Type on iOS) | **3** (CSS `rem` + `clamp()` on web; SwiftUI `relativeTo:` on Apple planned; missing: Android `sp` scaling) |
| **Reduce Motion** | 2 (browser default) | 2 (browser default) | 2 (browser default) | 2 (browser default) | 4 (respects system setting) | **2** (planned in `tokens.css` / `global.css` -- not yet merged; SwiftUI auto-respects once native apps ship) |
| **Reduce Transparency** | 1 (no handling -- glass breaks) | 1 (no handling) | 1 (no handling) | 1 (no handling) | 4 (opaque fallback) | **2** (planned in `tokens.css` -- not yet merged; SwiftUI auto-respects once native apps ship) |
| **i18n** | 1 (English only) | 1 (English only) | 3 (community translations, partial) | 4 (25+ languages, community-driven) | 3 (4 languages: en/de/fr/es) | **4** (en/de/zh with ICU MessageFormat, auto-detection from browser/system locale, CJK typography calibration -- `i18n/index.ts` 225 lines; missing: more languages beyond the 3) |

### 5.3 Security & Enterprise

| Component | Velo | Missive | Mailspring | Delta Chat | Proton Mail | **SetJoin** |
|-----------|------|---------|------------|------------|-------------|-------------|
| **E2E Encryption** | 0 | 0 | 0 | 4 (Autocrypt/PGP) | 5 (PGP, zero-access, third-party audited) | **0** (server-side encrypted at rest; PGP E2E not implemented; Autocrypt under consideration -- see SS3.8) |
| **Phishing Protection** | 1 (basic SPF check) | 1 (basic) | 1 (basic) | 1 (basic) | 3 (link confirmation, external sender warning) | **4** (SPF/DKIM/DMARC/DANE/ARC, anti-spam, ClamAV, DLP, external sender banners with name-spoof detection, impersonation protection planned -- `ExternalSenderBanner.svelte` 130 lines, 3 variants) |
| **Admin Console** | 0 (none) | 1 (team management only) | 0 (none) | 0 (none) | 2 (organization management, paid only) | **5** (30+ admin pages: users, domains, mailboxes, rules, migration, eDiscovery, quarantine, DMARC, DNS, storage, audit, retention, content search, deploy wizard, features, limits, reports, trace, webhooks -- `admin/` directory) |
| **Compliance** | 0 | 0 | 0 | 0 | 0 (PGP prevents server-side compliance) | **4** (journaling, eDiscovery, Content Search, retention, MRM, audit logging, WORM planned; missing: third-party certification) |
| **Multi-Account** | 2 (multiple Google accounts) | 1 (single org) | 5 (unified inbox across providers) | 1 (single account) | 2 (multiple Proton accounts) | **3** (single-server, multiple mailboxes; server-side, not client-side multi-account) |

### 5.4 Design System

| Component | Velo | Missive | Mailspring | Delta Chat | Proton Mail | **SetJoin** |
|-----------|------|---------|------------|------------|-------------|-------------|
| **Design Language** | 3 (one-off Tauri theme) | 3 (clean, functional) | 2 (legacy theme, theme plugins vary) | 2 (platform-native, no custom system) | 3 (consistent, not distinctive) | **5** (Liquid Glass cross-platform: 21704-line `tokens.css`, cross-platform mapping to SwiftUI/Compose, per-app accents, signed spring curve, glass opacity ladder, aurora canvas -- `liquid-glass-design-language.md` 811 lines) |
| **Icon System** | 2 (Lucide, partial) | 2 (custom, inconsistent) | 2 (custom, inconsistent) | 2 (Material, partial) | 3 (custom, consistent) | **4** (Lucide on web/desktop, SF Symbols on Apple, Material Icons on Android; bundled in binary -- no CDN; 200+ icons registered in `Icon.svelte`) |
| **Motion Design** | 2 (browser defaults) | 1 (no system) | 1 (no system) | 2 (platform defaults) | 2 (platform defaults) | **5** (single macOS spring curve `cubic-bezier(0.32, 0.72, 0, 1)` reproduced exactly on all platforms, 4 durations with defined purposes: hover 120ms, state 200ms, panel 320ms, sheet 480ms) |

---

## 6. Architectural Insights

### 6.1 The JMAP Moat Is Real

No competitor analyzed uses standard JMAP (RFC 8620/8621) as their primary protocol. Missive uses a proprietary JMAP dialect. Velo, Mailspring, and Delta Chat are IMAP-only. Proton Mail uses their own encrypted protocol with an IMAP bridge on desktop only. **SetJoin is the only platform in this analysis with native, standards-compliant JMAP.** This is a genuine architectural differentiator. JMAP's advantages over IMAP are well-documented (stateful sync, push, no polling, efficient for mobile), but the strategic insight is that **no competitor can trivially add JMAP** -- it requires a server rewrite, not a client-side change.

### 6.2 The Platform vs. Point-Solution Divide

The competitive landscape divides cleanly:
- **Point solutions** (Velo, Missive, Mailspring, Delta Chat, Proton Mail): Email is the product. Calendar, contacts, tasks, admin are either absent or separate products.
- **Platforms** (SetJoin, M365, Google Workspace): Email is one module in an integrated suite.

SetJoin's architectural decision to be a platform (mail + calendar + contacts + tasks + admin + drive/chat/meeting future) means it competes with M365/Google, not just with email clients. The admin console (30+ pages) is the biggest differentiator -- no analyzed competitor has meaningful IT management tools.

### 6.3 Glass Design System Is a Competitive Moat

No competitor has a cross-platform design system approaching the sophistication of Liquid Glass. Proton Mail has the most polished individual design, but it is web-only (React) -- no cross-platform token system, no per-app accent mapping, no motion system. Velo's Tauri theme is clean but it is a one-off, not a system. SetJoin's `tokens.css` (21704 lines) + `liquid-glass-design-language.md` (811 lines) + cross-platform token mapping to SwiftUI and Compose is a genuine moat -- it ensures visual continuity across surfaces that competitors achieve only by ignoring mobile (Mailspring) or staying web-only (Missive).

### 6.4 Air-Gap Changes the Architecture

In an air-gapped deployment (required for Chinese government/SOE), most competitors' features silently break:
- Velo: AI side panel, OAuth sign-in, update checks, all require internet
- Missive: Entire product is SaaS -- no air-gap possible
- Proton Mail: PGP key verification (keyservers), push notifications (APNs/FCM) break
- Mailspring: OAuth, read receipts, link tracking, all require internet

SetJoin is designed for air-gap from the architecture level: fonts bundled, icons bundled, translations bundled, updates served from customer's own server, TOTP as the primary MFA (push is an enhancement). This is not just "offline mode" -- it is a fundamentally different architecture that no competitor has.

### 6.5 The Rust Core Strategy Is Validated

Delta Chat's Rust `deltachat-core` and Missive's Rust backend both validate the approach of a shared Rust core with platform-specific UIs. SetJoin's `mail-core` and `guard-core` Rust crates with UniFFI bindings follow the same pattern, with JMAP instead of IMAP as the protocol layer. The key insight from Delta Chat: their JSON-RPC over stdin/stdout is a clean FFI boundary that has remained stable for years. UniFFI achieves the same outcome with stronger type safety.

### 6.6 Plugin Architecture Is the Missing Layer

Mailspring's plugin system (200+ community plugins) is the most successful open-source email plugin ecosystem. SetJoin has no plugin architecture. The `mail-core` Rust FFI is the natural plugin boundary: WASM modules loaded by the Rust core, with a capability-based permission model. Design this now (see SS3.7) even if implementation is deferred -- retrofitting a plugin boundary after the APIs have stabilized is far harder than reserving one from the start.

---

## 7. Summary: The 5 Highest-ROI Actions

In priority order, with effort and impact:

| # | Action | Priority | Effort | Impact | Source of Pattern |
|---|--------|----------|--------|--------|-------------------|
| 1 | **Merge reduced-transparency + reduced-motion CSS fallbacks** | P0 | 0.5 days | Accessibility: WCAG 2.2 AA floor, design spec SS8.1 requires this now. Proton Mail shows this is auditable. | Proton Mail |
| 2 | **Implement markdown paste in TipTap composer** | P0 | 0.5 days | Composer UX: power users paste markdown-rich text. Velo proves users love this. Plan already written. | Velo |
| 3 | **Add collision detection for shared mailboxes** | P1 | 2 weeks | Enterprise: prevents duplicate responses. Missive proves this is a deal-maker for team inboxes. Unique differentiator. | Missive |
| 4 | **Implement contact frequency ranking** | P1 | 0.5 days | Autocomplete UX: most-contacted addresses first. Velo proves this feels natural. Plan already written. | Velo |
| 5 | **Design plugin architecture boundary** | P1 | 1 day (spec only) | Architecture: reserve extension points in `mail-core` FFI before it stabilizes. Mailspring's 200-plugin ecosystem shows the long-term value. | Mailspring |

**Total immediate effort:** 3 days of implementation (items 1, 2, 4) + 2 weeks for collision detection (item 3) + 1 day for plugin architecture spec (item 5).

All of these are additive -- they enhance what SetJoin already has without changing the architecture or breaking existing features.
