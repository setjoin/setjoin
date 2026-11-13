-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 008: Auth attempts — records every authentication event.
-- Partitioned by month for efficient querying and retention.
-- Indexed for IP-based spray detection and per-username lockout lookups.
CREATE TABLE auth_attempts (
    id              BIGSERIAL,
    source_ip       INET        NOT NULL,
    target_username TEXT        NOT NULL,
    protocol        TEXT        NOT NULL DEFAULT 'http',
    outcome         TEXT        NOT NULL CHECK (outcome IN ('success','failure','captcha_needed','threat_blocked','geo_blocked','lockout','spray_detected','rate_limited')),
    failure_reason  TEXT,
    geo_country     TEXT,
    device_fingerprint TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX auth_attempts_ip_time_idx ON auth_attempts (source_ip, occurred_at DESC);
CREATE INDEX auth_attempts_user_time_idx ON auth_attempts (target_username, occurred_at DESC);

-- Seed first monthly partition
CREATE TABLE auth_attempts_2026_05 PARTITION OF auth_attempts
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
