# External-Sender Warning Banners — Design Spec

> **Phase:** Stage 1.6 — Enterprise Deal-Qualifier
> **Status:** Draft
> **Scope:** SMTP inbound pipeline (Go) + webmail UI (Svelte); no authserver changes

## Goal

Reduce phishing risk by surfacing a yellow/amber warning banner on every message from outside the organization, with an escalation pill when the sender's display name matches an internal user (name-spoofing) and a softer "first-time sender" notice for unknown addresses.

## Architecture

The check runs **at delivery time** in the SMTP inbound path — `inConnState.deliver()` already parses `fromAddr` from the `From` header via `extractHeaders()`. After extracting headers, query the `domains` table (`WHERE is_local = TRUE`) to classify the sender's domain as internal or external. Store a boolean `is_external` and a `sender_display_name` on the message record. Name-spoofing detection (display name matches an internal user but the email domain is external) runs as a second lightweight lookup. Webmail reads the flag from the JMAP `Email` response and renders a configurable amber banner in the thread view.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `mailserver/sql/schema/040_external_sender_flags.sql` | New | Add `is_external BOOL NOT NULL DEFAULT FALSE` + `sender_display_name TEXT` columns to `messages` table; seed feature toggles |
| `mailserver/sql/reducers/deliver_group_vacation.sql` | Modify | Accept `p_is_external` param; set `is_external` + `sender_display_name` on INSERT |
| `mailserver/gateway/internal/smtp/inbound.go` | Modify | Add `isExternal()` domain check + `isNameLookalike()` in `deliver()`; pass flag through `storeAndDeliver()` to reducer |
| `mailserver/gateway/internal/handlers/jmap_email.go` | Modify | Expose `isExternal` + `senderDisplayName` in JMAP `Email/get` response |
| `mailserver/webmail/src/lib/types/jmap.ts` | Modify | Add `isExternal?: boolean`, `senderDisplayName?: string` to Email type |
| `mailserver/webmail/src/routes/inbox/+page.svelte` | Modify | Render external-sender banner in thread list |
| `mailserver/webmail/src/lib/components/ExternalSenderBanner.svelte` | New | Glass-surface amber banner with icon + dismissible warning text; used in thread view and compose reply |
| `mailserver/sql/tests/external_sender_banners.pg` | New | pgTAP tests for is_external flag + name-spoofing edge cases |
| **Total** | **~250 LOC** | **~8 files** |

## Key Design Decisions

1. **Store flag at delivery time, not compute at read time.** The `domains` table can change (domains added/removed). Storing the classification at delivery captures the organization's boundary as it existed when the message arrived. If the organization later onboards a domain retroactively, previously-external messages remain flagged — this is safer than hiding old warnings that users may have relied on.

2. **Domain check uses the existing `domains` table** (`WHERE is_local = TRUE`). No new config list to maintain. The admin console's domain management page (`/admin/domains`) already allows adding/removing local domains. This check reuses that authority — a domain is "internal" if and only if it is a local domain in the mailserver.

3. **Three-tier severity model.** (a) **First-time sender** — green/neutral pill, informational only. (b) **External sender** — amber banner, always shown. (c) **Name-spoofing** — amber banner + red pill, escalated warning when the display name matches an internal user but the domain is external. All three tiers are individually toggleable: `feature.external_sender_warn`, `feature.external_sender_name_spoof`, `feature.external_sender_first_time`.

4. **Configurable per-domain override.** Both Gmail and EXO allow per-domain customization of the external sender banner (custom text, custom color). We support this via `system_config` keys: `external_sender.warn_text`, `external_sender.warn_color` (default `#FFD60A` amber), and domain-scoped overrides via `domain_config` JSONB. Admins can add a custom HTML banner or disable it per domain (`external_sender.enabled: false`).

## Competitive Context

All 7 platforms in our comparison matrix have this feature. Gmail and EXO display a yellow banner with "This message is from an external sender" at the top of the message body. Gmail additionally shows a "First time sender" notice. The Chinese platforms (NetEase, Tencent, DingTalk, Lark) all include external-sender identification in their security feature set but generally with less UI polish — simple text labels rather than rich banners. Our implementation should match or exceed Gmail/EXO in visual clarity, using the Prism Liquid Glass design system (`glass-pane` with amber accent `#FFD60A`).

## Dependencies

- **Phase 0–7 (complete):** SMTP inbound pipeline, `domains` table, JMAP `Email/get`, webmail inbox
- **Phase 17 (complete):** Tag system — the first-time-sender check queries whether any prior message from this `fromAddr` exists in the recipient's mailbox
- **Feature toggle system (complete):** `shared/toggle` package for per-feature enable/disable

## Non-Goals

- Per-user opt-out of external banners (admins control this; if a user could disable it, phishing efficacy increases)
- External banner on outbound mail (only inbound)
- Banner on IMAP-retrieved mail (IMAP fetch is client-pull; the sender domain check is only meaningful in SMTP inbound where we control delivery)
- Translation to Chinese for Stage 1 (deferred to Stage 1.8)

## Effort Estimate

**~3 days** (1 engineer). Breakdown: schema migration + reducer change (0.5d), Go SMTP pipeline + JMAP exposure (1d), webmail UI component + thread view integration (1d), pgTAP tests + manual verification (0.5d).
