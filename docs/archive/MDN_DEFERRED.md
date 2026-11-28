# MDN Inbound Auto-Processing — Deferred (S14)

> **Status: DEFERRED.** This document captures the current state, the deferred
> piece, future entry points, and the S14 rationale so the next engineer has a
> clear contract to implement against.

---

## Current state (shipped)

Read-receipt *request* and MDN *generation* are fully implemented:

- **`HandleReadReceipt`** (`mailserver/internal/jmap/handler.go:2288`) — handles
  `POST /auth/me/read-receipt`; called by the client when the user opens a message
  that carries a `Disposition-Notification-To` header.
- **`send_read_receipt(p_account_id, p_message_id, p_to_address)`** reducer
  (`mailserver/sql/reducers/send.sql:285`) — queues an outbound MDN message via
  the standard delivery pipeline; bumps `jmap_email_submission_state`.

From the *sender's* perspective, the MDN email arrives as a normal message in
their Sent/inbox thread. There is no automatic rollup of per-recipient read
status on the original sent message.

---

## Deferred piece

**Automatic sender-visible read-status rollup** — the feature colloquially
described as "Read · 12 Jun 10:42" shown on the original sent message.

To implement this, the following must be built:

1. **Inbound MDN parse** — when an inbound message arrives whose content-type is
   `multipart/report; report-type=disposition-notification`, parse the
   `message/disposition-notification` MIME part to extract the original
   `Message-ID` and the disposition action (`displayed` / `deleted`).  
   Entry point: `mailserver/internal/smtp/pipeline_deliver_store.go` — the final
   deliver stage, after blob storage and before `deliver()` reducer call.

2. **Per-recipient read-status rollup** — a new table
   `message_read_status(message_id, recipient_address, read_at, action)` storing
   one row per inbound MDN received. The original outbound message's
   `Message-ID` (stored in `messages.message_id`) is the join key.

3. **Vendor `Email/get` property** — expose a `readReceipts` array property on
   the original sent `Email` object (via the JMAP `Email/get` method) that lists
   per-recipient `{address, readAt, action}` structs, visible only to the sender.

---

## Future implementation entry points

| Layer | File / function | What to add |
|---|---|---|
| Inbound SMTP pipeline | `smtp/pipeline_deliver_store.go` | Detect `multipart/report; report-type=disposition-notification`; call a new reducer `record_mdn_receipt(p_original_message_id, p_recipient, p_action, p_read_at)` |
| SQL schema | New migration `V079__message_read_status.sql` | `message_read_status` table keyed by `(original_message_id TEXT, recipient_address TEXT)` |
| SQL reducer | `sql/reducers/record_mdn_receipt.sql` | Upsert into `message_read_status`; bump `jmap_email_state` for the sender |
| JMAP `Email/get` | `jmap/handler.go` `emailGet` method | Add `readReceipts` to the property projection when the caller is the message sender |

---

## S14 rationale

Per spec §7 B7 and S14: this is a **polish feature — blocks nothing**. All
surfaces that would consume per-recipient read-receipt information (M3 inbox
thread view "Read · 12 Jun 10:42", M4 compose preview) are downstream of the
M-series UI work, which is itself downstream of the B-series backend wave.
Deferring to a subsequent wave avoids scope creep on the already-complex wave-2
delivery while ensuring the contract is fully documented and ready for
implementation.
