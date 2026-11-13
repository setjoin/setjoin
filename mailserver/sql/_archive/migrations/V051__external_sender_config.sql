-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V051: External sender warning config — per-user toggle + domain-level overrides.
-- The per-message columns (is_external, sender_display_name, is_name_spoof, is_first_time)
-- are created in 049_external_sender_flags.sql. This migration adds the admin-config side.

-- Domain-level external sender banner overrides (per-domain custom text/color, enable/disable).
CREATE TABLE external_sender_config (
    domain_id  BIGINT       NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    enabled    BOOL         NOT NULL DEFAULT TRUE,
    warn_text  TEXT,                                     -- NULL = use system_config default
    warn_color TEXT         NOT NULL DEFAULT '#FFD60A',  -- amber
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id)
);

COMMENT ON TABLE external_sender_config IS
'Per-domain external sender banner overrides. NULL warn_text → use system_config external_sender.warn_text.';

-- Per-user opt-out toggle for external sender warning banners.
-- Default TRUE: show banners. Users who find them distracting can disable them.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_sender_warning BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN users.external_sender_warning IS
'Per-user toggle for external sender warning banners. TRUE = show amber warning on messages from outside the organization.';

-- Global defaults for banner text, color, and master enable/disable.
-- Admins can override these via the admin console or SQL.
INSERT INTO system_config (key, value) VALUES
  ('external_sender.warn_text',  '"This message is from an external sender. Use caution when clicking links or opening attachments."'),
  ('external_sender.warn_color', '"#FFD60A"'),
  ('external_sender.enabled',    'true')
ON CONFLICT (key) DO NOTHING;
