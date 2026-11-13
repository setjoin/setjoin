-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V060: MAM Policy Engine — multi-layer policies, events, device identity
--
-- NOTE: in the shared cluster, authserver migration V008 (unified_devices) may
-- have already created device_policy / device_policy_groups / device_events with
-- an earlier, narrower shape (event_data/created_at instead of severity/details/
-- occurred_at, and no CHECK on group_type). Because that authserver migration
-- loads first, a bare `CREATE TABLE IF NOT EXISTS` here silently skips and the
-- MAM columns/constraints/indexes this engine requires (and the mdm Go package
-- reads: severity, details, occurred_at) are missing — which previously aborted
-- this migration at `CREATE INDEX ... (occurred_at)`. So this migration now
-- CREATEs the tables for the standalone-mailserver case AND additively reconciles
-- any pre-existing authserver version with ADD COLUMN IF NOT EXISTS / a guarded
-- CHECK, making it idempotent and load-order-independent.
BEGIN;

-- device_policy holds per-device and global policy key/value pairs.
-- device_id IS NULL → global default. Non-NULL → per-device override.
CREATE TABLE IF NOT EXISTS device_policy (
    id          BIGSERIAL PRIMARY KEY,
    device_id   BIGINT,  -- FK to device_registry.id; NULL = global default
    policy_key  TEXT NOT NULL,
    policy_value TEXT NOT NULL,  -- JSON scalar: true, false, 6, "wipe"
    updated_at  TIMESTAMPTZ DEFAULT now(),
    applied_at  TIMESTAMPTZ,  -- set by client on next checkin
    UNIQUE (device_id, policy_key)
);
-- Reconcile a pre-existing (authserver V008) device_policy.
ALTER TABLE device_policy
    ADD COLUMN IF NOT EXISTS policy_key   TEXT,
    ADD COLUMN IF NOT EXISTS policy_value TEXT,
    ADD COLUMN IF NOT EXISTS applied_at   TIMESTAMPTZ;

-- device_policy_groups maps group-type policies (department, role, domain).
CREATE TABLE IF NOT EXISTS device_policy_groups (
    id          BIGSERIAL PRIMARY KEY,
    policy_key  TEXT NOT NULL,
    policy_value TEXT NOT NULL,
    group_type  TEXT NOT NULL CHECK (group_type IN ('department', 'role', 'domain')),
    group_id    BIGINT NOT NULL DEFAULT 0,  -- 0 = all members of that type
    updated_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (policy_key, group_type, group_id)
);
-- Reconcile a pre-existing (authserver V008) device_policy_groups: it lacks the
-- group_type CHECK that the MAM engine (and V060 pgTAP) require. Add it only when
-- absent so re-runs and the native-V060 path are both no-ops.
DO $v060$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'device_policy_groups_group_type_check'
          AND conrelid = 'device_policy_groups'::regclass
    ) THEN
        ALTER TABLE device_policy_groups
            ADD CONSTRAINT device_policy_groups_group_type_check
            CHECK (group_type IN ('department', 'role', 'domain', 'security_group'));
    END IF;
END
$v060$;

-- device_events logs detection events, policy changes, admin actions per device.
CREATE TABLE IF NOT EXISTS device_events (
    id          BIGSERIAL PRIMARY KEY,
    device_id   BIGINT NOT NULL,
    event_type  TEXT NOT NULL CHECK (event_type IN (
                    'screenshot_detected', 'jailbreak_detected', 'root_detected',
                    'debugger_detected', 'vpn_detected', 'emulator_detected',
                    'policy_applied', 'policy_violation', 'wipe_completed',
                    'device_locked', 'device_unlocked', 'crypto_profile_changed'
                )),
    severity    TEXT NOT NULL DEFAULT 'info'
                    CHECK (severity IN ('info', 'warn', 'critical')),
    details     JSONB DEFAULT '{}',
    occurred_at TIMESTAMPTZ DEFAULT now()
);
-- Reconcile a pre-existing (authserver V008) device_events, which has
-- event_data/created_at but not the severity/details/occurred_at columns the mdm
-- package (mailserver/internal/mdm/events.go) writes and reads.
ALTER TABLE device_events
    ADD COLUMN IF NOT EXISTS severity    TEXT DEFAULT 'info',
    ADD COLUMN IF NOT EXISTS details     JSONB DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ DEFAULT now();

-- Extend device_registry with device identity columns.
-- device_fingerprint: UUID from OS keychain, stable identifier.
-- device_secret: HMAC key for signed checkins.
ALTER TABLE device_registry
    ADD COLUMN IF NOT EXISTS device_fingerprint UUID,
    ADD COLUMN IF NOT EXISTS device_secret     TEXT;

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_device_policy_device ON device_policy(device_id);
CREATE INDEX IF NOT EXISTS idx_device_policy_key   ON device_policy(policy_key);
CREATE INDEX IF NOT EXISTS idx_device_policy_groups_lookup
    ON device_policy_groups(group_type, group_id);
CREATE INDEX IF NOT EXISTS idx_device_events_device ON device_events(device_id);
CREATE INDEX IF NOT EXISTS idx_device_events_type   ON device_events(event_type);
CREATE INDEX IF NOT EXISTS idx_device_events_time   ON device_events(occurred_at);

COMMIT;
