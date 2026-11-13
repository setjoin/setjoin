# Competitive Roadmap — 3-Stage Plan to Win the On-Premise Email Market

> **Date:** 2026-05-31 | **Source:** 7-platform feature comparison matrix (104 features, 8 categories)
> **Existing specs integrated:** Phase 12 client architecture, SSO group provisioning, OIDC IdP mode, compliance/content search, forgot-password flow

---

## Market Context

We compete across two distinct markets from a single on-premise codebase:

| Market | Primary Competitors | Key Requirement |
|--------|-------------------|-----------------|
| **Western on-premise** | Self-hosted Exchange, Zimbra, Kolab | Replace M365/Google without losing enterprise features |
| **Chinese sovereign** | NetEase 网易, Tencent 腾讯, DingTalk 钉钉 | National crypto, domestic stack |

**Our structural advantages over all competitors:**
- **JMAP (RFC 8620/8621)** — no other platform, Western or Chinese, offers native JMAP
- **Standalone on-prem IdP + MFA** — self-contained, air-gap capable, no cloud dependency
- **CalDAV + CardDAV built in** — EXO and most Chinese platforms lack DAV entirely
- **Gmail-style labels + JMAP compliance** — multi-label tags with IETF-standard sync
- **No per-seat licensing** — on-prem deployment model eliminates recurring user fees
- **SeaweedFS/S3 tiered storage** — old mail automatically moves to cheaper storage; no separate archive product needed

---

## Stage 1 — "Enterprise Deal-Qualifier" (0–6 months)

**Theme:** Close the gaps that get us disqualified from RFPs before the demo even starts. Every feature here is a checkbox that procurement and security teams look for.

### 1.1 — Native iOS + Android Apps

**Status:** Spec exists (`docs/design/`), plan exists (`docs/plans/2026-05-27-phase12-foundation.md`)

**Why:** #1 deal-breaker. Email must work on phones with:
- Push notifications (APNs / FCM)
- Offline mail access (local SQLite cache synced via JMAP)
- MDM hooks (remote wipe, PIN enforcement, app-level policies)
- Native UX (SwiftUI on iOS, Jetpack Compose on Android)
- JMAP as the native protocol (not IMAP — full efficiency)

**Competitive position:** No Chinese platform supports JMAP mobile. EXO requires Intune license for MDM. Gmail mobile is cloud-only. Our native clients + JMAP + on-premise = unique.

### 1.2 — Number-Match Push MFA

**Why:** EXO permanently enforces number matching for all Microsoft Authenticator push notifications since May 2023. Tap-to-approve is vulnerable to MFA fatigue attacks. Number matching is the industry-standard defense.

**What to do:** Replace our current tap-to-approve push MFA (`push.go`) with a 2-digit number challenge. User sees number on login screen, types it into the push notification. ~1 week of work.

### 1.3 — Link Protection (Time-of-Click URL Rewriting)

**Why:** Gmail includes Safe Browsing link protection in ALL editions at no extra cost. EXO gates it behind Defender for Office 365 P1 (add-on). Security teams flag its absence immediately. This is the single most visible security gap.

**What to do:** Rewrite URLs in inbound emails through a scanning proxy. On click, check the URL against threat intelligence (Safe Browsing API, Spamhaus DBL, or similar). Block/warn on malicious destinations. ~3 weeks.

### 1.4 — Attachment Sandbox / Detonation

**Why:** Both incumbents offer it. EXO requires Defender add-on — we can offer it built-in as a competitive advantage. Detonate attachments in an isolated sandbox before delivery.

**What to do:** Integrate with an open-source sandbox (CAPE, Cuckoo) or commercial API. Focus on Office docs, PDFs, executables, and archives. ~4 weeks.

### 1.5 — Undo Send + Snooze / Pin-to-Top

**Why:** Every competitor has undo send. Every competitor except Gmail has pin-to-top. Snooze is already modeled as an exclusive tag group in our Phase 17 tag system — we just need the UI. Combined ~1 week.

### 1.6 — External-Sender Warning Banners

**Why:** All 7 platforms have configurable external-sender indicators. Table-stakes for phishing defense. ~3 days.

### 1.7 — Per-Alias Signatures + Internal Message Recall

**Why:** All 4 Chinese platforms support message recall (NetEase up to 30 days Premier). EXO has cloud-based internal recall. Per-alias signatures are supported by Gmail and partially by EXO. ~2 weeks.

### 1.8 — Chinese-Language Admin Console + Documentation

**Why:** Table-stakes for Chinese market entry. All 4 Chinese competitors provide Chinese-first admin UIs and documentation. Without this, we cannot sell in China regardless of technical capability. ~4 weeks of translation + i18n infrastructure.

---

## Stage 2 — "Regulated-Industry Ready" (6–12 months)

**Theme:** Finance, healthcare, and government won't buy without these. EXO charges E5 pricing for the full compliance stack; we offer it at no per-seat markup.

### 2.1 — Journaling with Full Envelope Capture

**Why:** Mandatory for regulated industries. Captures every message (including BCC recipients, full headers, and delivery metadata) in a structured journal report per RFC standards. EXO includes this in all plans.

**What to do:** Add journaling hook to the SMTP delivery path. Journal reports wrapped in MIME envelopes with full recipient list (including BCC). Journal mailbox destination configurable per-domain. ~3 weeks.

### 2.2 — eDiscovery + Content Search

**Why:** Legal/HR must be able to search across all mailboxes. EXO Premium (E5) includes Predictive Coding and Review Sets — but EXO Standard (E3) has basic content search. We target E3-parity at minimum.

**What to do:** Admin Boolean search (KQL subset) across all mailboxes. Export to PST/mbox. Case management with holds. Existing Phase 14 Content Search provides foundation. Builds on existing `admin_ediscovery.go`. ~6 weeks.

### 2.3 — WORM Immutability

**Why:** SEC 17a-4(f), FINRA Rule 4511(c), and CFTC Rule 1.31(c)-(d) require non-rewritable, non-erasable record storage. EXO achieves this via Purview Preservation Lock (E5). Third-party auditors (Cohasset Associates) certify compliance.

**What to do:** Implement at the SeaweedFS/S3 storage layer using S3 Object Lock (retention periods + legal hold). Objects become immutable until retention expires. Since we're on-premise, the customer also controls physical access. Certification path: Cohasset Associates or similar auditor. ~8 weeks + certification process.

### 2.4 — Advanced Anti-Phishing / Impersonation Protection

**Why:** Gmail includes user/domain impersonation detection in all editions. EXO gates it behind Defender P1. We should match Gmail's "included in base" model.

**What to do:** Display-name spoofing detection, lookalike domain detection (homoglyph analysis), mailbox intelligence (contact graph to detect novel senders impersonating known contacts). ~4 weeks.

### 2.5 — SCIM Provisioning

**Why:** Automated user lifecycle management from Entra ID, Okta, etc. Table-stakes for enterprise IdP integration. Both EXO and Gmail support SCIM (EXO natively, Gmail via third-party bridges).

**What to do:** SCIM 2.0 server endpoint. Create/update/disable/delete user lifecycle. Group push. ~3 weeks.

### 2.6 — OIDC/OAuth Client-Type Discrimination

**Why:** All OIDC clients currently return `AuthMethodBasic` — even public clients (SPAs) that should use PKCE with `AuthMethodNone`. Partially addressed in our Phase C OIDC hardening fixes.

**What to do:** Add client type field to storedClient. Public clients → PKCE required + `AuthMethodNone`. Confidential clients → `AuthMethodBasic`. ~1 week.

### 2.7 — SMTP Inbound DANE + DNSSEC

**Why:** EXO is the only major provider with full inbound + outbound DANE (GA October 2024). Gmail is outbound-only. Being the SECOND provider with inbound DANE is a meaningful transport security differentiator.

**What to do:** DNSSEC-aware resolver. Publish TLSA records for mail server. Inbound: validate sending server's DANE records. Outbound: already have MTA-STS; add DANE validation. ~4 weeks.

---

## Stage 3 — "Global Platform" (12–18 months)

**Theme:** Chinese market entry + AI features + platform polish. We become the only email platform that serves Western regulated industries AND Chinese government/SOE procurement from the same codebase.

### 3.2 — National Cryptographic Standards (国密 SM2/SM3/SM4)

**Why:** Required for classified government communications and financial services in China. SM2 for digital signatures, SM3 for cryptographic hashing, SM4 for symmetric encryption.

**What to do:** Add SMx algorithm support to shared/cryptokey package. SM2 for JWT signing (alternative to HMAC-SHA256), SM3 for password hashing (alternative to bcrypt), SM4 for data-at-rest encryption (alternative to AES). ~6 weeks.

### 3.3 — AI Email Features

**Why:** DingTalk and NetEase already ship AI compose, smart reply, auto-tagging, and tone adjustment in premium tiers. This is a current differentiator in China, not a future roadmap item. We need parity.

**What to do:** Integrate with local LLM (Ollama, llama.cpp) for on-premise AI — no cloud dependency. Smart compose (draft suggestions), smart reply (one-click responses), auto-tagging (classify incoming mail), tone adjustment. ~8 weeks.

### 3.4 — Conference/Room Booking Calendar UI

**Why:** Gmail and EXO have scheduling assistants with side-by-side availability grids. Our CalDAV backend supports free/busy but the web UI lacks the scheduling grid.

**What to do:** Scheduling assistant UI in SvelteKit webmail. Attendee availability grid with free/busy color coding. Room Finder with capacity, equipment, and location. ~4 weeks.

### 3.5 — Conditional Access Policy Engine

**Why:** EXO requires Entra ID P1/P2 for Conditional Access. Gmail's Context-Aware Access requires Enterprise editions. We can offer basic conditional access as a built-in feature.

**What to do:** Extend our 8-step threat pipeline into a configurable policy engine. Device state (managed/unmanaged), IP/location (geo-blocking already exists), risk-based step-up (require MFA from new locations). ~6 weeks.

### 3.6 — Enhanced Mobile MDM

**Why:** EXO offers Intune (requires separate license). Gmail has built-in Endpoint Management. Our Phase 12 mobile apps need companion MDM capabilities.

**What to do:** Remote wipe (account-level + device-level). PIN/passcode enforcement. App-level policies (block copy/paste to personal apps, block screenshots). Jailbreak/root detection. ~4 weeks.

---

## Features REMOVED from Consideration

These were in the initial analysis but removed per strategic decisions:

| Feature | Reason for Removal |
|---------|-------------------|
| Archive mailbox | Our SeaweedFS/S3 tiered storage natively handles old email migration to cheaper storage. No separate archive product needed — this is an architectural advantage, not a gap. |
| Offline/PWA webmail | On-premise deployment means the server is always local. JMAP clients (including our native mobile apps) handle offline sync natively. Webmail PWA adds complexity without user value for our deployment model. |
| WeChat/WeCom integration | Strategic decision: integrating with WeChat drives users to the WeChat ecosystem rather than our platform. WeChat is a competitor (Tencent Exmail), not a partner. Our value proposition is independence from ecosystem lock-in. |

---

## Dependency Graph

```
Stage 1 (parallel):
  1.1 Native Apps ───── already spec'd, execute Phase 12 plan
  1.2 Push MFA ──────── independent
  1.3 Link Protection ── independent
  1.4 Sandbox ────────── independent
  1.5 Undo/Snooze ────── depends on Phase 17 tag system (already done)
  1.6 Ext-Sender ─────── independent
  1.7 Recall/Signatures ─ independent
  1.8 Chinese UI ─────── independent (needs i18n infra first)

Stage 2 (journaling→eDiscovery→WORM sequential; rest parallel):
  2.1 Journaling ─────── independent
  2.2 eDiscovery ─────── builds on 2.1 (journal store is primary search target)
  2.3 WORM ───────────── independent (storage-layer feature)
  2.4 Anti-Phishing ──── independent
  2.5 SCIM ───────────── independent
  2.6 OIDC Clients ───── independent (partially done in Phase C)
  2.7 SMTP DANE ──────── independent

Stage 3 (Chinese market items depend on 1.8 Chinese UI):
  3.2 SMx Crypto ─────── independent
  3.3 AI Features ────── independent
  3.4 Room Booking ───── independent
  3.5 Cond. Access ───── extends existing threat pipeline
  3.6 Enhanced MDM ───── depends on 1.1 (native apps)
```

---

## Key Metrics

| Stage | Features | Est. Total Effort | Target |
|-------|----------|-------------------|--------|
| Stage 1 | 8 | ~22 weeks (parallelizable to ~12) | Month 6 |
| Stage 2 | 7 | ~30 weeks (parallelizable to ~16) | Month 12 |
| Stage 3 | 6 | ~40 weeks (parallelizable to ~20) | Month 18 |

---

## Integration with Existing Specs

| Roadmap Item | Existing Spec | Status |
|-------------|---------------|--------|
| 1.1 Native Apps | `2026-05-27-phase12-client-architecture-design.md` | ✅ Design complete, plan exists |
| 1.2 Push MFA | New | Needs spec + plan |
| 1.3 Link Protection | New | Needs spec + plan |
| 1.4 Sandbox | New | Needs spec + plan |
| 1.5 Undo/Snooze | New | Needs spec + plan |
| 1.6 Ext-Sender | New | Needs spec + plan |
| 1.7 Recall/Signatures | New | Needs spec + plan |
| 1.8 Chinese UI | New | Needs spec + plan |
| 2.1 Journaling | `2026-05-22-compliance-polish-content-search-design.md` | Partially covers |
| 2.2 eDiscovery | `2026-05-22-compliance-polish-content-search-design.md` | Partially covers |
| 2.3 WORM | New | Needs spec + plan |
| 2.4 Anti-Phishing | New | Needs spec + plan |
| 2.5 SCIM | New | Needs spec + plan |
| 2.6 OIDC Clients | `2026-05-25-oidc-provider-idp-mode-design.md` | Partially covers |
| 2.7 SMTP DANE | New | Needs spec + plan |
| 3.2 SMx Crypto | New | Needs spec + plan |
| 3.3 AI Features | New | Needs spec + plan |
| 3.4 Room Booking | New | Needs spec + plan |
| 3.5 Cond. Access | New | Needs spec + plan |
| 3.6 Enhanced MDM | New | Needs spec + plan |
