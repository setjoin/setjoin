# Virus Quarantine System

> **Phase:** Wave 12 (May 2026)  
> **Status:** ✅ Implemented  
> **Files:** `sql/schema/033_quarantine.sql`, `gateway/internal/handlers/admin_quarantine.go`, `quarantine.go`, `inbound.go`, webmail routes

---

## Overview

The quarantine system replaces SMTP-level rejection of virus-infected messages with a **store-review-release** workflow. Instead of rejecting virus emails with a 550 error (which causes the sender to retry and the admin to never see the message), infected messages are accepted, stored in quarantine, and made available for admin and user review.

---

## Architecture

```
Inbound SMTP (port 25)
    │
    ├── ClamAV scan (nINSTREAM)
    │       │
    │       ├── Clean → deliver() → Inbox (normal flow)
    │       └── Virus detected → continue to deliver()
    │                │
    │                ├── INSERT messages table (normal)
    │                ├── INSERT quarantined_messages table
    │                ├── REMOVE Inbox tag
    │                ├── ADD Quarantined tag (exclusive group: quarantine)
    │                └── ACCEPT 250 (no SMTP rejection)
    │
    ▼
Admin Portal (/admin/quarantine)          User Portal (/quarantine)
    │                                          │
    ├── List all users' items                  ├── List own items
    ├── Preview (sanitized HTML)               ├── Preview (sanitized HTML)
    ├── Release → move to Inbox               ├── Release → move to Inbox
    ├── Reject → permanent delete             └── Reject → soft-delete
    └── Stats (active/released/rejected)
```

---

## Schema

### `quarantined_messages` table

| Column | Type | Purpose |
|---|---|---|
| `id` | BIGSERIAL PK | |
| `message_id` | BIGINT FK → messages | The stored message |
| `mailbox_id` | BIGINT FK → mailboxes | Which mailbox it was addressed to |
| `original_tag` | TEXT | The tag the message had before quarantine (e.g., "Inbox") |
| `reason` | TEXT | Human-readable reason (e.g., "Virus detected: Win.Trojan.Agent") |
| `reason_type` | TEXT | 'virus', 'dlp', or 'admin' |
| `virus_name` | TEXT | ClamAV virus name (optional) |
| `preview_token` | TEXT UNIQUE | UUID v4 for safe preview URL |
| `quarantined_at` | TIMESTAMPTZ | |
| `released_at` / `released_by` | TIMESTAMPTZ / BIGINT | |
| `rejected_at` / `rejected_by` | TIMESTAMPTZ / BIGINT | |

### `mailboxes.quarantine_self_service` column
- `BOOL NOT NULL DEFAULT TRUE`
- Per-mailbox toggle: can this user manage their own quarantine?
- Admin can toggle per-mailbox; planned bulk-apply feature (Phase 19)

### Tag system
- `exclusive_group` extended with `'quarantine'` value (in addition to 'location' and 'snooze')
- Quarantined tag seeded per-mailbox on migration (`tag_type='system'`, `imap_expose=FALSE`)
- All Mail virtual view excludes messages with Quarantined tag (same as Trash/Spam)

---

## API Endpoints

### Admin (requires `isAdmin`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/quarantine` | List (paginated, searchable by from/subject, filterable by status) |
| GET | `/admin/quarantine/stats` | Counts: `{active, released, rejected}` |
| GET | `/admin/quarantine/{id}/preview` | Sanitized HTML preview with subject/from/quarantined_at |
| POST | `/admin/quarantine/{id}/release` | Swap Quarantined→original tag, set released_at |
| POST | `/admin/quarantine/{id}/reject` | DELETE FROM messages, set rejected_at |

### User (requires auth)

| Method | Path | Purpose |
|---|---|---|
| GET | `/quarantine?limit=50` | List own quarantined items |
| GET | `/quarantine/count` | Active count `{count}` for sidebar badge |
| POST | `/quarantine/{id}/release` | Release to inbox (scoped to own mailbox) |
| POST | `/quarantine/{id}/reject` | Soft-delete (scoped to own mailbox) |

---

## Safety

| Concern | Mitigation |
|---|---|
| **XSS in email HTML** | Server-side `sanitizeHTML()` strips `<script>`, `<iframe>`, `onclick`, `onload`, `<object>`, `<embed>`. External image `src` rewritten to `data-blocked-src` |
| **Sandbox escape** | Preview iframe uses `sandbox=""` (all restrictions: no scripts, no navigation, no forms, no popups) |
| **Cross-user access** | User APIs check `mailboxes.user_id = auth_user.id` via JOIN in SQL |
| **Brute-force preview tokens** | UUID v4 (122 bits entropy). Concurrent request rate-limiting via auth middleware |
| **User releases malware** | Confirmation dialog warns: "Only release messages you recognize and trust" |
| **Preview of active content** | All `on*` event handlers rewritten to `data-blocked-*`. External resources blocked |

---

## Flow Diagrams

### Release
```
Admin clicks Release
  → UPDATE quarantined_messages SET released_at = now(), released_by = admin_id
  → DELETE FROM message_tags WHERE tag = Quarantined
  → INSERT INTO message_tags (tag = original_tag, e.g., "Inbox")
  → Message appears in user's Inbox
```

### Reject
```
Admin clicks Reject
  → UPDATE quarantined_messages SET rejected_at = now(), rejected_by = admin_id
  → DELETE FROM messages WHERE id = msg_id (hard delete)
  → Message permanently removed from SeaweedFS + DB

User clicks Reject
  → UPDATE quarantined_messages SET rejected_at = now(), rejected_by = user_id
  → UPDATE messages SET is_deleted = TRUE WHERE id = msg_id (soft delete)
  → User can recover from Trash within purge window
```
