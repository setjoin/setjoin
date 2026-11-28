-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V079: Add totp_enabled_at timestamp to users table.
-- Records when TOTP was last enabled (NULL if never enabled or disabled).
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_enabled_at TIMESTAMPTZ;
