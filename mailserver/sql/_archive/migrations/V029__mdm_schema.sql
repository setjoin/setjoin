-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V029: Mobile MDM schema
-- Tables: mdm_policies (policy definitions), mdm_device_state (per-device compliance)
-- Feature toggles: feature.mdm

-- Policy definitions — assigned at user/group/global levels
CREATE TABLE mdm_policies (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    priority        INT NOT NULL DEFAULT 0,          -- higher = wins when multiple match
    scope_type      TEXT NOT NULL CHECK (scope_type IN ('global','group','user')),
    scope_id        BIGINT,                           -- user_id or group_id (NULL for global)
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    -- Passcode
    passcode_min_length     INT NOT NULL DEFAULT 6,
    passcode_complexity     TEXT NOT NULL DEFAULT 'numeric'
                            CHECK (passcode_complexity IN ('none','numeric','alphanumeric','complex')),
    passcode_max_age_days   INT NOT NULL DEFAULT 90,
    passcode_history_count  INT NOT NULL DEFAULT 5,
    max_failed_attempts     INT NOT NULL DEFAULT 10,
    inactivity_lock_mins    INT NOT NULL DEFAULT 5,
    -- App-level restrictions
    block_screenshots       BOOLEAN NOT NULL DEFAULT FALSE,
    block_copy_paste        BOOLEAN NOT NULL DEFAULT FALSE,
    require_device_encryption BOOLEAN NOT NULL DEFAULT TRUE,
    min_os_version_ios      TEXT NOT NULL DEFAULT '',   -- e.g. "17.0"
    min_os_version_android  TEXT NOT NULL DEFAULT '',   -- e.g. "14"
    -- Jailbreak/root
    jailbreak_action        TEXT NOT NULL DEFAULT 'quarantine'
                            CHECK (jailbreak_action IN ('block','quarantine','warn_log','none')),
    -- General
    heartbeat_interval_secs INT NOT NULL DEFAULT 3600,
    grace_period_mins       INT NOT NULL DEFAULT 60,    -- delay before quarantine after violation
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_mdm_policies_scope ON mdm_policies (scope_type, scope_id) WHERE enabled;
CREATE INDEX idx_mdm_policies_priority ON mdm_policies (priority DESC);

-- Per-device compliance state
CREATE TABLE mdm_device_state (
    device_id           UUID PRIMARY KEY,              -- client-generated UUID v4, stable per install
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform            TEXT NOT NULL CHECK (platform IN ('ios','android')),
    device_name         TEXT NOT NULL DEFAULT '',
    os_version          TEXT NOT NULL DEFAULT '',
    app_version         TEXT NOT NULL DEFAULT '',
    -- Passcode compliance
    passcode_set        BOOLEAN NOT NULL DEFAULT FALSE,
    passcode_compliant  BOOLEAN NOT NULL DEFAULT FALSE,
    -- Encryption
    encryption_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    -- Jailbreak/root
    jailbroken          BOOLEAN NOT NULL DEFAULT FALSE,
    jailbreak_method    TEXT NOT NULL DEFAULT '',       -- detected method (e.g. "Magisk", "Cydia")
    -- Compliance
    compliance_status   TEXT NOT NULL DEFAULT 'unknown'
                        CHECK (compliance_status IN ('compliant','non_compliant','quarantined','grace')),
    non_compliance_reasons TEXT[] NOT NULL DEFAULT '{}',
    grace_until         TIMESTAMPTZ,                   -- NULL when not in grace period
    -- Wipe
    wipe_requested      TEXT NOT NULL DEFAULT 'none'
                        CHECK (wipe_requested IN ('none','pending','acknowledged','executed')),
    wipe_level          TEXT CHECK (wipe_level IN ('account','device')),
    wipe_requested_at   TIMESTAMPTZ,
    wipe_acked_at       TIMESTAMPTZ,
    -- Check-in
    last_checkin_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_mdm_device_user ON mdm_device_state (user_id);
CREATE INDEX idx_mdm_device_status ON mdm_device_state (compliance_status);
CREATE INDEX idx_mdm_device_wipe ON mdm_device_state (wipe_requested) WHERE wipe_requested = 'pending';

-- Feature toggle
INSERT INTO feature_toggles (key, enabled) VALUES
    ('feature.mdm', TRUE)
ON CONFLICT (key) DO NOTHING;

-- Seed default global policy (permissive — admins tighten)
INSERT INTO mdm_policies (name, description, priority, scope_type, scope_id, enabled)
VALUES ('Default', 'Built-in default policy — permissive baseline', 0, 'global', NULL, TRUE)
ON CONFLICT DO NOTHING;
