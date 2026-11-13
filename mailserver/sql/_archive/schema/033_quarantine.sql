-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 033_quarantine.sql: Virus/malware quarantine system.
-- Messages flagged by ClamAV are stored in quarantine instead of rejected.
-- Admins and end users can preview and release/reject quarantined messages.

-- Per-mailbox toggle for self-service quarantine management
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS quarantine_self_service BOOL NOT NULL DEFAULT TRUE;

-- Add 'quarantine' to the exclusive_group CHECK constraint on tags
ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_exclusive_group_check;
ALTER TABLE tags ADD CONSTRAINT tags_exclusive_group_check 
    CHECK (exclusive_group IN ('location','snooze','quarantine'));

CREATE TABLE IF NOT EXISTS quarantined_messages (
    id              BIGSERIAL PRIMARY KEY,
    message_id      BIGINT      NOT NULL,  -- soft reference to messages(id); no FK due to partitioned PK
    mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    original_tag    TEXT        NOT NULL,
    reason          TEXT        NOT NULL,
    reason_type     TEXT        NOT NULL DEFAULT 'virus'
                    CHECK (reason_type IN ('virus','dlp','admin')),
    virus_name      TEXT,
    preview_token   TEXT        NOT NULL UNIQUE DEFAULT gen_random_uuid()::text,
    quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at     TIMESTAMPTZ,
    released_by     BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    rejected_at     TIMESTAMPTZ,
    rejected_by     BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    notified_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS quarantined_mailbox_idx ON quarantined_messages(mailbox_id);
CREATE INDEX IF NOT EXISTS quarantined_status_idx ON quarantined_messages(released_at, rejected_at) 
    WHERE released_at IS NULL AND rejected_at IS NULL;
CREATE INDEX IF NOT EXISTS quarantined_preview_token_idx ON quarantined_messages(preview_token);
