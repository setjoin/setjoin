-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Vacation auto-reply settings per mailbox.
CREATE TABLE vacation_settings (
  mailbox_id      BIGINT      PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
  enabled         BOOL        NOT NULL DEFAULT FALSE,
  subject         TEXT        NOT NULL DEFAULT 'Out of office',
  body_text       TEXT        NOT NULL DEFAULT '',     -- reply body for internal (in-org) senders
  body_html       TEXT,
  -- A5 (V086): separate reply body for senders OUTSIDE the organization (Outlook OOO parity).
  -- NULL body_external = reuse the internal body for external senders.
  body_external      TEXT,
  body_external_html TEXT,
  -- Who outside the org is replied to: all | contacts | none. Enforced in deliver().
  external_audience  TEXT     NOT NULL DEFAULT 'all'
    CHECK (external_audience IN ('all', 'contacts', 'none')),
  start_date      DATE       CHECK (start_date IS NULL OR end_date IS NULL OR start_date <= end_date),
  end_date        DATE,       -- NULL = indefinite
  only_contacts   BOOL        NOT NULL DEFAULT FALSE,  -- only reply to known contacts
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rate-limit tracking for vacation auto-replies.
-- PK allows one reply per sender per mailbox per vacation period.
-- Cleaned up by pg_cron after 90 days.
CREATE TABLE vacation_replies (
  sender_email    TEXT        NOT NULL,
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  vacation_start  DATE        NOT NULL,  -- start of the vacation period this reply belongs to
  replied_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (sender_email, mailbox_id, vacation_start)
);

CREATE INDEX vacation_replies_at_idx ON vacation_replies(replied_at);

-- Clean up old vacation reply records after 90 days.
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-vacation-replies', '0 4 * * *',
--     $$ DELETE FROM vacation_replies WHERE replied_at < now() - interval '90 days'; $$
-- );
