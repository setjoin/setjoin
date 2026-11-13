-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V009: Deleted Items Recovery, Quota Exclusion, Auto-Purge, Deduplication Safety

-- Reload updated jmap_email reducer (destroy fix + new deleted/recover/purge functions)
\i ../reducers/jmap_email.sql

-- 1. Add deleted_at timestamp for tracking when a message was soft-deleted
ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS messages_deleted_at_idx ON messages(mailbox_id, deleted_at) WHERE is_deleted;

-- 2. Queue table for orphaned message raw_refs (dedup-safe MinIO cleanup)
CREATE TABLE IF NOT EXISTS orphaned_message_blobs (
    raw_ref TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS orphaned_message_blobs_created_at_idx ON orphaned_message_blobs(created_at);

-- 3. Recalculate mailboxes.used_bytes to exclude already-soft-deleted messages
UPDATE mailboxes SET used_bytes = (
    SELECT COALESCE(SUM(m.size_bytes), 0)
    FROM messages m
    WHERE m.mailbox_id = mailboxes.id AND NOT m.is_deleted
);

-- 4. Add pg_cron job for daily auto-purge of soft-deleted messages (> 30 days)
-- [pg_cron→Go cron worker] SELECT cron.schedule('purge-deleted-messages', '30 2 * * *',
--     $$ SELECT count(*) FROM purge_deleted_messages(); $$
-- );
