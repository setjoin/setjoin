-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 003: Normalized passkey (WebAuthn) credentials per user.
-- Replaces users.webauthn_credentials JSONB for per-credential lifecycle management.
CREATE TABLE passkey_credentials (
    id                BYTEA       PRIMARY KEY,            -- WebAuthn credential ID
    user_id           BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key        BYTEA       NOT NULL,
    attestation_type  TEXT        NOT NULL DEFAULT 'none',
    sign_count        INT         NOT NULL DEFAULT 0,
    device_name       TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at      TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ
);
CREATE INDEX passkey_user_idx ON passkey_credentials(user_id) WHERE revoked_at IS NULL;
