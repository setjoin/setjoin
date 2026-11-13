# Newsletter Bundling — Design Doc

> **Date:** 2026-06-02 | **Status:** Implemented | **Reference:** Velo email client bundling pattern

## Overview

Newsletter bundling groups subscription/bulk emails into a single collapsible row in the inbox instead of showing each message individually. When a user receives 8 newsletters from different senders, they see **1 bundle row** that expands to show individual senders with per-sender unsubscribe buttons.

This pattern was pioneered by Velo and is now table stakes for modern email clients (Superhuman does it too).

## Architecture

```
SMTP Inbound
  │
  ├─ extractHeaders() parses List-Unsubscribe header (RFC 2369 / RFC 8058)
  │  └─ deliverHeaders.listUnsubscribe set
  │  └─ deliverHeaders.isNewsletter = true
  │
  ├─ deliver() stores list_unsubscribe in messages table
  │
  └─ Inbox UI
     └─ NewsletterBundle.svelte groups messages by bundle
     └─ Per-sender "Unsubscribe" button
        └─ POST /messages/{emailId}/unsubscribe
           └─ newsletter.go: proxies POST to List-Unsubscribe URL (RFC 8058)
           └─ Inserts into user_sender_list as 'blocked'
           └─ Audit log entry
```

## Files

| File | Purpose |
|------|---------|
| `mailserver/internal/user/newsletter.go` | Unsubscribe handler — `POST /messages/{emailId}/unsubscribe` |
| `mailserver/internal/user/newsletter_test.go` | 6 tests: URL parsing (4 cases), unauth, missing emailId |
| `mailserver/internal/smtp/inbound.go` | SMTP detection — `listUnsubscribe` + `isNewsletter` fields |
| `mailserver/sql/migrations/V052__newsletter_unsubscribe.sql` | `list_unsubscribe` column on messages table |
| `mailserver/webmail/src/lib/components/NewsletterBundle.svelte` | Collapsible bundle UI with per-sender unsubscribe |

## RFC 8058 One-Click Unsubscribe Flow

1. User clicks "Unsubscribe" on a sender row in the bundle
2. Client sends `POST /messages/{emailId}/unsubscribe`
3. Server looks up the `List-Unsubscribe` header stored at delivery time
4. Server POSTs `List-Unsubscribe=One-Click` to the URL
5. Server inserts the sender into `user_sender_list` as `blocked` (future emails auto-archived)
6. Server logs the action to `admin_audit_log`

## Newsletter Detection

A message is classified as a newsletter when it has a `List-Unsubscribe` header (RFC 2369). This header is mandatory for bulk senders per Gmail/Yahoo 2024 requirements, so coverage should be near-universal for legitimate bulk mail.

The detection happens at SMTP ingest time (`inbound.go:extractHeaders()`), not at display time — this means the flag persists in the database and can be used for server-side rules, filtering, and analytics.

## Bundle UI

The `NewsletterBundle.svelte` component:
- Shows a collapsible header row with sender count, total message count, and avatar stack (up to 3 avatars + overflow count)
- Expands to show per-sender rows with name, subject, message count, and an "Unsubscribe" button
- The unsubscribe button turns red on hover as a safety signal
- Transitions use Svelte `fly` animation

## Future Work

- **Auto-archive past newsletters on unsubscribe** — currently only blocks future emails
- **Bundle in search results** — search currently shows individual messages
- **Newsletter digest view** — dedicated "Newsletters" tab/section
- **Sender reputation integration** — flag senders with high unsubscribe rates
