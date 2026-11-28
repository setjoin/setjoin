-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V056: Password history table for preventing password reuse.
-- Stores bcrypt hashes of previously used passwords per user.
-- The number of entries retained is controlled by system_config
-- key 'password_history_depth' (default: 5).

CREATE TABLE IF NOT EXISTS password_history (
    id            BIGSERIAL    PRIMARY KEY,
    user_id       BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS passhist_user_idx ON password_history(user_id, created_at DESC);
