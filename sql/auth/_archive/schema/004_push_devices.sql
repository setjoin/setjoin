-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 004: Push notification device registrations per user.
CREATE TABLE push_devices (
    id              BIGSERIAL   PRIMARY KEY,
    user_id         BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    push_provider   TEXT        NOT NULL CHECK (push_provider IN ('webpush','apns','fcm')),
    push_token_enc  BYTEA       NOT NULL,                -- AES-256-GCM encrypted push token
    device_name     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX push_user_idx ON push_devices(user_id) WHERE revoked_at IS NULL;
