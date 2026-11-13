# Undo Send + Snooze / Pin-to-Top — Design Spec

> **Target:** Roadmap 1.5 — three small but high-ROI inbox features that every major email platform ships.

**Goal:** Deliver undo-send (30 s cancellation window), snooze (surfaced from existing Phase 17 model), and pin-to-top (per-message sort-order flag) across the JMAP gateway and webmail frontend.

**Architecture:** Undo-send reuses the existing scheduled-send pipeline (`scheduled_at` column, `Scheduled` tag, `process_scheduled_messages()` cron hook) — new submission targets `now() + 30s`. Snooze is already modeled as a Phase 17 exclusive tag group (`timer='snooze'`, `snooze_until`, `process_snoozed_messages()`) — only the webmail picker UI is missing. Pin-to-top adds a single nullable `pinned_at TIMESTAMPTZ` column to `messages` plus a sort-order tweak in `jmap_email_query` — pinned items sort above everything else.

---

## Files to Create/Modify

### Schema & Reducers (PostgreSQL)

| Action | File | What |
|--------|------|------|
| **New** | `mailserver/sql/migrations/V017__pin_to_top.sql` | `ALTER TABLE messages ADD COLUMN pinned_at TIMESTAMPTZ` + index |
| **Modify** | `mailserver/sql/reducers/jmap_email.sql` | `jmap_email_get`: include `pinnedAt` in output; `jmap_email_query`: prepend `m.pinned_at IS NOT NULL DESC` to sort order |
| **Modify** | `mailserver/sql/reducers/jmap_email_submission.sql` | Accept `onSendUndoWindowSeconds` (default 30) — thread submission through scheduled-send pipeline when non-zero |

### Gateway (Go)

| Action | File | What |
|--------|------|------|
| **Modify** | `mailserver/gateway/internal/jmap/handler.go` | Register `EmailSubmission/cancel` method (remove Scheduled tag + delete from queue) |
| **Modify** | `mailserver/gateway/internal/jmap/handler.go` | Pass `send_at` offset through `EmailSubmission/set` |

### Webmail (Svelte 5)

| Action | File | What |
|--------|------|------|
| **Modify** | `mailserver/webmail/src/lib/components/ComposeModal.svelte` | Post-send undo toast with countdown; wire `sendAt` to `emailSubmissionSet` |
| **Modify** | `mailserver/webmail/src/routes/inbox/+page.svelte` | Pin/unpin toggle in email toolbar; pinned sort section above inbox message list |
| **New** | `mailserver/webmail/src/lib/components/SnoozePicker.svelte` | Date/time presets ("Later today", "Tomorrow", "This weekend", "Next week", custom) |
| **Modify** | `mailserver/webmail/src/routes/inbox/+page.svelte` | Integrate SnoozePicker into email action bar; snooze count badge on Snoozed folder |
| **Modify** | `mailserver/webmail/src/lib/jmap/client.ts` | Add `emailSubmissionCancel()` and `emailSubmissionSet` send-at parameter |

### SQL Tests

| Action | File | What |
|--------|------|------|
| **New** | `mailserver/sql/tests/undo_snooze_pin.pg` | pgTAP tests for pin sort order, undo-cancel flow, snooze-until timer |

---

## Key Design Decisions

1. **Undo-send is zero-new-tables.** Rather than building a cancellation queue, submissions with a non-zero undo window set `scheduled_at = now() + window` and get the `Scheduled` tag. The existing `process_scheduled_messages()` cron hook (runs every 60 s) picks them up. Cancel = remove the Scheduled tag. The ~60 s cron granularity adds worst-case 1 min extra delay on top of the window — acceptable for V1; a follow-up can add a gateway-side timer for exact dispatch.

2. **Snooze is pure UI wiring.** Phase 17 already provides `timer='snooze'` on tags, the `snooze_until` column on `message_tags`, and the `process_snoozed_messages()` unsnooze function that restores Inbox. The webmail `snoozeUntil()` function in `inbox/+page.svelte` already calls `emailSet` with `_snoozeUntil`. The only work is the date-picker component and the snooze action button in the email toolbar.

3. **Pin-to-top uses a nullable timestamp, not a boolean.** `pinned_at` stores when the message was pinned; `NULL` means not pinned. Sorting uses `ORDER BY m.pinned_at IS NOT NULL DESC, m.received_at DESC` — pins sort first, then regular sort order takes over. Using a timestamp (not a bool) leaves the door open for "pin until" in a future phase without a migration.

4. **JMAP custom property prefix.** `pinnedAt` is surfaced as a server-set read-only property (not `_pinned` — it is a native column, not an opaque extension). `snoozeUntil` and `scheduledAt` already ship in `jmap_email_get` output. The `Email/set` mutable path for pin-to-top uses `pinned: true | null` in the patch object — a boolean toggle that the reducer translates to `pinned_at = NOW()` or `NULL`.

---

## Competitive Context

| Feature | Gmail | Outlook | Fastmail | Proton | Hey | Zoho | Apple Mail | Prism (this task) |
|---------|-------|---------|----------|--------|-----|------|------------|-------------------|
| Undo Send | 5–30 s | 10 s | Configurable | ❌ | Undo Send | ❌ | 10–30 s | 30 s default |
| Snooze | Yes | Yes | Yes | ❌ | Set Aside | ❌ | ❌ | Yes (already modeled) |
| Pin-to-top | Star | Pin | Pin | ❌ | Sticky | ❌ | ❌ | Yes (new column) |

Gmail's "Undo" is market-standard UX — a bottom-sheet toast with countdown and a single tap to cancel. Snooze is table-stakes for Inbox Zero workflows. Pin-to-top is a power-user feature present in Fastmail, Outlook, and Hey (as "Set Aside" / "Sticky").

---

## Dependencies

- **Phase 17 (Tag System)** — snooze exclusive group and `process_snoozed_messages()` already deployed
- **V007 (Compose Features)** — `scheduled_at` column on `messages` already deployed
- **pg_cron** — `process_snoozed_messages()` and `process_scheduled_messages()` jobs already registered

No new external dependencies. No new Go packages. No auth changes.

---

## Effort Estimate

| Component | Est. |
|-----------|------|
| SQL migration (`pinned_at` column + index) | 0.5 d |
| Reducer changes (`jmap_email_get`, `jmap_email_query`, `jmap_email_submission_set`) | 1 d |
| Gateway: `EmailSubmission/cancel` + wired `sendAt` | 0.5 d |
| Webmail: undo toast + compose integration | 1 d |
| Webmail: SnoozePicker component + inbox integration | 1 d |
| Webmail: pin-to-top toggle + sort section | 1 d |
| pgTAP tests | 0.5 d |
| E2E smoke tests | 0.5 d |
| **Total** | **~6 days (1 working week)** |
