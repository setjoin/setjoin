# Per-Alias Signatures + Internal Message Recall — Design Spec

> **Roadmap:** Stage 1.7 — Enterprise Deal-Qualifier
> **Date:** 2026-05-31
> **Status:** Design
> **Effort:** ~2 weeks

## Goal

Allow different signatures per send-as alias, and let users recall unread internally-delivered messages within the same organization.

## Architecture

**Per-alias signatures** are mostly backend-complete: the `aliases` table already carries a `signature` column and `send()` applies it at submit time (lines 93-120 of `send.sql`). The work here is exposing per-alias signature management through JMAP Identity objects and the webmail compose UI. No new schema tables required.

**Internal message recall** follows the Exchange Online model: sender issues a recall against a message ID; the system finds all unread internal copies (same-org recipients), moves them to Trash, inserts a stub notice, and notifies affected mailboxes. External recipients and already-read copies are untouched — the sender learns which ones could not be recalled. A new `recall_message()` reducer plus a JMAP `EmailSubmission/recall` method handle this. No audit-trail suppression — the original message metadata remains for compliance even after recall.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `mailserver/sql/reducers/recall.sql` | Create (~120 lines) | `recall_message()` reducer: find unread internal copies by message_id, move to Trash, insert recall notice, return per-recipient status |
| `mailserver/gateway/internal/jmap/handler.go` | Modify (~40 lines) | Register `EmailSubmission/recall` method; parse args, call reducer, return result |
| `mailserver/sql/reducers/jmap_identity.sql` | Modify (~30 lines) | Extend `jmap_identity_get()` to return per-alias `signature` and `replyTo` from `aliases` table |
| `mailserver/webmail/src/lib/types/jmap.ts` | Modify (~10 lines) | Add `signature` and `replyTo` fields to `Identity` interface |
| `mailserver/webmail/src/routes/mail/compose/+page.svelte` | Modify (~30 lines) | Signature dropdown scoped to selected send-as alias; recall button on sent messages (visible only for internal recipients, unread) |
| `mailserver/sql/migrations/V026__recall.sql` | Create (~20 lines) | `message_recalls` UNLOGGED table (message_id PK, recalled_by, recalled_at, copy_count); feature toggle seeds |
| **Total** | **~250 lines** | **6 files** |

## Key Design Decisions

- **Recall is internal-only, matching EXO model.** Only copies delivered to local recipients (same-org domains) are recalled. External recipients are reported as `cannotRecall` in the result. This is identical to Exchange Online behavior and avoids the impossibility of recalling email that has left the organization's mail infrastructure.
- **Recall respects read state.** Only unread (`is_read = FALSE`) copies are moved to Trash. Already-read copies return `alreadyRead` status. This matches EXO's behavior and avoids the UX disaster of yanking read mail from under a recipient.
- **Recall leaves a stub.** Instead of silently deleting, a short system message ("This message was recalled by the sender") is inserted into the recipient's mailbox. This preserves the conversation context and avoids "ghost" thread gaps. The original message metadata (subject, from, timestamp) is embedded in the stub for compliance audit trail.
- **Per-alias signatures reuse the existing `aliases.signature` column** rather than creating a new junction table. The `signatures` table (V007) remains the user-facing signature library; the `aliases.signature` column stores the rendered signature text for that specific alias. When no per-alias signature is set, the mailbox default from `signatures` applies — matching Gmail's "signature per address" model.

## Dependencies

- **Phase 17 tag system** — recall uses `set_message_location()` to move to Trash and `pg_notify('tag:{mailbox_id}', ...)` for client fan-out. Both are complete.
- **`get_mailbox_delegates()`** (V007) — compose UI uses this to populate the send-as selector. Already done.
- **No dependency on authserver** — recall is purely a JMAP/mailserver feature. Per-alias signatures touch only the gateway + schema.

## Competitive Context

All 4 Chinese platforms (NetEase, Tencent Exmail, DingTalk, Feishu) support message recall — NetEase Premier allows recall up to 30 days. Exchange Online supports internal recall. Per-alias signatures are supported by Gmail and partially by EXO. These are table-stakes features for enterprise RFPs in both Western and Chinese markets.

## Non-Goals

- Cross-organization recall (IMAP `CANCEL` — no major platform supports this)
- Recall of messages already forwarded or replied to
- Signature rich-text editor changes (existing HTML editor serves both per-mailbox and per-alias signatures)
- Recall window configuration (hardcoded to "until read"; configurable time-window deferred)
