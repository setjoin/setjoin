-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V008: Device-identity registry (`devices`)
-- Authoritative per-user device registry used by the device-identity / MAM
-- subsystem (internal/device/{identity,checkin}.go). Columns mirror that code's
-- INSERT/SELECT/UPDATE exactly; UNIQUE(user_id, fingerprint) backs the
-- ON CONFLICT (user_id, fingerprint) upsert in RegisterDevice.
--
-- NOTE: an earlier revision of this migration began with `ALTER TABLE devices`,
-- but no migration ever created `devices`, so it aborted with "relation devices
-- does not exist" on every database (the device feature could not work). This
-- creates the table first. The push-token table (push_devices, schema/004) is
-- intentionally retained — internal/authn/push.go and handlers/device.go still
-- read/write it; merging push tokens into `devices` and dropping push_devices is
-- deferred to a follow-up migration once those call sites are repointed.

CREATE TABLE IF NOT EXISTS devices (
    id                BIGSERIAL   PRIMARY KEY,
    user_id           BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name       TEXT,
    platform          TEXT,
    os_version        TEXT,
    app_version       TEXT,
    fingerprint       TEXT        NOT NULL,
    hmac_secret       TEXT        NOT NULL,
    compliance_status TEXT        NOT NULL DEFAULT 'unknown',
    wipe_requested    BOOLEAN     NOT NULL DEFAULT FALSE,
    last_seen         TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices (user_id);

-- Forward-compat push columns for the eventual push_devices merge. They stay
-- nullable/defaulted and unused until push.go is repointed onto `devices`.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS push_token_enc BYTEA;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS push_provider TEXT;       -- 'apns', 'fcm', 'hms', 'webpush'
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_public_key BYTEA; -- ECDH P-256 public key for ECIES
ALTER TABLE devices ADD COLUMN IF NOT EXISTS push_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Device policy: per-device overrides applied on top of global and group policies.
CREATE TABLE IF NOT EXISTS device_policy (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    policy_key TEXT NOT NULL,
    policy_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(device_id, policy_key)
);

-- Device policy groups: policies applied to all devices in a group.
CREATE TABLE IF NOT EXISTS device_policy_groups (
    id BIGSERIAL PRIMARY KEY,
    group_type TEXT NOT NULL,    -- 'department', 'role', 'security_group'
    group_id BIGINT NOT NULL,
    policy_key TEXT NOT NULL,
    policy_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(group_type, group_id, policy_key)
);

-- Device events: audit trail of device lifecycle events.
CREATE TABLE IF NOT EXISTS device_events (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT REFERENCES devices(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,    -- 'registered', 'checkin', 'quarantined', 'wiped', 'unlocked', 'policy_changed'
    event_data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_events_device ON device_events(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_policy_device ON device_policy(device_id);
CREATE INDEX IF NOT EXISTS idx_device_policy_groups_lookup ON device_policy_groups(group_type, group_id);

-- Insert default global policies.
INSERT INTO device_policy (policy_key, policy_value)
VALUES
  ('copy_paste', 'allow'),
  ('screen_capture', 'allow'),
  ('encryption', 'required'),
  ('watermark', 'false'),
  ('notification_profile', 'push'),
  ('max_offline_days', '30')
ON CONFLICT DO NOTHING;
