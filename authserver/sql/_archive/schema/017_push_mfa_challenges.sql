-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 017: Push MFA challenge table.
-- Stores active number-matching push challenges with 120-second TTL.
-- Single-use: deleted after verification or expiry.
CREATE TABLE push_mfa_challenges (
    id              BIGSERIAL   PRIMARY KEY,
    user_id         BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_code  TEXT        NOT NULL,            -- 2-digit number the user must enter
    nonce           BYTEA       NOT NULL,            -- 32 random bytes for verification
    session_id      TEXT,                            -- correlates to the login session
    expires_at      TIMESTAMPTZ NOT NULL,
    verified_at     TIMESTAMPTZ,
    failed_attempts INT         NOT NULL DEFAULT 0,  -- rate limit: max 3 incorrect attempts per challenge
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE push_mfa_challenges ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;

CREATE INDEX push_mfa_user_idx ON push_mfa_challenges(user_id, expires_at)
    WHERE verified_at IS NULL;
