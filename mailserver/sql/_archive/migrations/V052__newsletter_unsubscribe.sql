-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V052: Newsletter detection + one-click unsubscribe support (RFC 8058).
-- Adds list_unsubscribe column to messages for storing the List-Unsubscribe header,
-- enabling one-click unsubscribe and newsletter auto-detection in the SMTP pipeline.

ALTER TABLE messages ADD COLUMN IF NOT EXISTS list_unsubscribe TEXT;

COMMENT ON COLUMN messages.list_unsubscribe IS
'RFC 8058 List-Unsubscribe header value. Non-NULL means this message is a newsletter/bulk email eligible for one-click unsubscribe.';
