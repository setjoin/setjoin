# Shared-mail productivity operations

Search intent, Sender Control, Mail Work, private comments, notifications,
analytics, integrations, and shared drafts are independent OFF-by-default
features. Run `bash scripts/verify-webmail-productivity.sh list` to see the
scoped gates and `bash scripts/verify-webmail-productivity.sh quick` before a
canary. Enable only one bounded cohort at a time.

PostgreSQL reducers own permissions, generations, immutable events, receipts,
rate limits, and retention. The Go worker only claims bounded outbox rows and
retries. A stale generation is a refresh-and-review event, never a blind retry.
Private comments must not enter MIME, IMAP, ordinary exports, search indexes, or
offline message caches.

The shared list reads work rows in one bounded `MailWork/get` call and shows
Unassigned, Mine, Owned, Waiting, and Done filters plus text-and-dot status
badges. The activity rail selects mentions and handoff recipients from the live
directory; it never accepts raw identity IDs. Comment edits append a replacement
and leave the prior row as a visible audit tombstone. The lead view shows only
the latest bounded daily aggregates (threads, average first reply, completed and
SLA-breached counts), never actor-level results.

Full-access delegates may edit the mailbox business calendar in the work rail:
an IANA timezone, active weekdays, local start/end time, comma-separated ISO
holiday dates, and the first-response target. Save is generation-fenced and
idempotent; a stale save must refresh before retry. Existing work keeps its
immutable policy snapshot, so a later calendar change affects only newly created
work and never rewrites historical SLA evidence.

Shared drafts keep one stable collaboration-session ID while message content
continues to use Email authority. Autosave replacement is atomic. A lease,
permission, sender, DLP, attachment, or revision conflict preserves the local
editor contents and makes the compose window read-only until it is reopened.

Notification delivery is authorization-first, obeys DND and preference state,
and caps immediate notifications at six per ten minutes. Analytics is aggregate
only and suppresses results below five actors or twenty conversations. External
integrations may emit only the approved event catalog and opaque identifiers;
message bodies, comments, recipients, subjects, and attachment metadata are not
allowed in egress payloads.

Internal actions use `MailWork/action` and the same expected-generation and
operation-UUID fence as other work mutations. “Create personal task” targets the
actor's primary mailbox; Chat and Drive targets come only from the caller's live
visible catalog. PostgreSQL rechecks collaboration plus target access both before
enqueue and at worker dispatch. Task/Chat receive only a bounded internal locator;
Drive records an association rather than copying content. The completion receipt
and `mail_work_action_links` row make response-loss replay idempotent and block
mailbox purge until retention policy permits their removal.

The webhook console reads `/admin/webhooks/events` instead of maintaining a
client-side catalog. Subscription creation rejects unknown, duplicated or over-cap
event scopes. Mail-work previews show the exact opaque payload class and delivery
logs retain status/code/latency without response bodies or mail content.
