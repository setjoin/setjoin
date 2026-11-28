-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 018: Add rotated_at to oauth_tokens for refresh grace window.
-- When a refresh token is rotated, the old row is kept briefly (rotated_at IS NOT NULL)
-- instead of deleted immediately. A 30-second grace window allows the client to
-- retry a failed refresh without triggering false-positive theft detection.
ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS oauth_rotated_cleanup_idx
    ON oauth_tokens(rotated_at)
    WHERE rotated_at IS NOT NULL;
