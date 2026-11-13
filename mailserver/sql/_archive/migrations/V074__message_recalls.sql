-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V074: message_recalls — recall audit/idempotency table (Stage 1.7).
--
-- The recall_message() reducer (mailserver/sql/reducers/recall.sql) records every
-- completed recall here and uses it for idempotency, but no migration or schema
-- file ever created the table, so a fresh database failed recall.pg with
-- "relation message_recalls does not exist". Columns mirror exactly what
-- recall.sql writes/reads:
--   - INSERT ... (message_id, recalled_by, recalled_at, copy_count, cannot_count)
--   - EXISTS (SELECT 1 FROM message_recalls WHERE message_id = ...)
--   - ON CONFLICT (message_id) DO NOTHING   → needs a UNIQUE/PK on message_id
--   - SELECT copy_count FROM message_recalls WHERE message_id = ...  (recall.pg)
--
-- message_id is the RFC 5322 Message-ID (TEXT, matching messages.message_id), not
-- a numeric FK; it is the natural key and primary key. recalled_by references the
-- initiating user.
CREATE TABLE IF NOT EXISTS message_recalls (
    message_id   TEXT        PRIMARY KEY,                 -- RFC 5322 Message-ID of the recalled message
    recalled_by  BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    recalled_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    copy_count   INT         NOT NULL DEFAULT 0,          -- internal unread copies moved to Trash
    cannot_count INT         NOT NULL DEFAULT 0           -- copies that could not be recalled (already read, errors)
);

CREATE INDEX IF NOT EXISTS message_recalls_recalled_by_idx ON message_recalls (recalled_by);
