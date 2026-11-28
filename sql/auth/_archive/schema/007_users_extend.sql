-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 007: Extend users table with auth-server-specific columns.
-- All new columns have safe defaults — no data migration needed.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS push_mfa_enabled       BOOL  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS totp_backup_codes_enc  TEXT[],
    ADD COLUMN IF NOT EXISTS saml_idp_entity_id     TEXT,
    ADD COLUMN IF NOT EXISTS last_login_country     TEXT;

CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(lower(email));
