-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 009: Auth lockout state — per-IP, per-username, per-IP+username.
-- Three independent lockout dimensions. Each key locks independently.
-- Exponential escalation: double the duration on each repeat offense.
CREATE TABLE auth_lockouts (
    lockout_key       TEXT        PRIMARY KEY,   -- ip:{ip} / user:{username} / ip_user:{ip}:{username}
    failed_count      INT         NOT NULL DEFAULT 1,
    locked_until      TIMESTAMPTZ NOT NULL,
    escalation_level  INT         NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
