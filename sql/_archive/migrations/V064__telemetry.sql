-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V064: Privacy-first device telemetry
-- Stores anonymous, opt-in usage data. No PII, no email content, no IPs.
-- Admin must enable via feature toggle: device_telemetry = true.

CREATE TABLE IF NOT EXISTS device_telemetry (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app_version TEXT,                        -- e.g. "1.2.3"
    os_version TEXT,                         -- e.g. "iOS 18.1"
    crash_count INT NOT NULL DEFAULT 0,
    uptime_hours INT,                        -- hours since last report
    feature_usage JSONB NOT NULL DEFAULT '{}', -- {"mail": 42, "calendar": 3, ...}
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_telemetry_device ON device_telemetry(device_id, reported_at DESC);
CREATE INDEX idx_telemetry_reported_at ON device_telemetry(reported_at);

-- Telemetry toggle — disabled by default. Admin must explicitly opt in.
INSERT INTO feature_toggles (key, enabled, description)
VALUES ('device_telemetry', false, 'Enable anonymous device telemetry collection (no PII, no email content, no IPs)')
ON CONFLICT (key) DO NOTHING;

-- Auto-purge: delete telemetry older than 90 days.
INSERT INTO system_config (key, value, encrypted, updated_at)
VALUES ('telemetry_retention_days', '90', false, now())
ON CONFLICT (key) DO NOTHING;
