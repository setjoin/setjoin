-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 012: Device registry — per-user device fingerprint tracking.
-- Composite hash = SHA-256(user_agent || ip_prefix) for dedup.
-- Flags new devices and country changes for admin alerting.
CREATE TABLE device_registry (
    id              BIGSERIAL   PRIMARY KEY,
    user_id         BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash     TEXT        NOT NULL,
    user_agent      TEXT,
    ip_prefix       TEXT,
    country         TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    auth_count      INT         NOT NULL DEFAULT 1,
    flagged         BOOL        NOT NULL DEFAULT FALSE,
    UNIQUE (user_id, device_hash)
);

CREATE INDEX device_registry_user_idx ON device_registry (user_id);
