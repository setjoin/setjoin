-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 021: Managed devices — MDM-enrolled devices for conditional access.
-- Managed = highest trust tier. Gated behind native mobile apps (Phase 12).
-- Only compliant devices are considered "managed"; non-compliant fall back
-- to known/unknown/risky via device_registry.

CREATE TABLE managed_devices (
    device_hash      TEXT        PRIMARY KEY,
    user_id          BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name      TEXT        NOT NULL DEFAULT '',
    os_type          TEXT        NOT NULL DEFAULT ''
                                  CHECK (os_type IN ('', 'ios', 'android', 'macos', 'windows', 'linux')),
    os_version       TEXT        NOT NULL DEFAULT '',
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checkin_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- TRIAGE FENCE (D-AUTHSERVER-SQL--ARCHIVE-005, 2026-09): this fail-open
    -- trust default must NOT be resurrected. DEFAULT 'compliant' means an
    -- inserted row with no evidence rides free at any RequireDeviceCompliance
    -- gate — and even a defaulted-'unknown' row needs the gate to treat
    -- unknown as NON-compliant (fail closed). The Phase-12 enrollment writer
    -- must set compliance_status explicitly from evidence; never restore a
    -- 'compliant' default on any successor of this table.
    compliance_status TEXT       NOT NULL DEFAULT 'compliant'
                                  CHECK (compliance_status IN ('compliant', 'non_compliant', 'unknown'))
);

CREATE INDEX managed_devices_user_idx ON managed_devices (user_id);
