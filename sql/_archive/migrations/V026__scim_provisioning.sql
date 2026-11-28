-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V026: SCIM Provisioning — scim_tokens, external IDs, source column expansion.
-- RFC 7644 SCIM 2.0 server for IdP-driven user/group lifecycle management.

-- 1. SCIM external IDs on users
ALTER TABLE users ADD COLUMN IF NOT EXISTS scim_external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_scim_external_id_idx
  ON users(scim_external_id) WHERE scim_external_id IS NOT NULL;

-- 2. SCIM external IDs on distribution_groups
ALTER TABLE distribution_groups ADD COLUMN IF NOT EXISTS scim_external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS dg_scim_external_id_idx
  ON distribution_groups(scim_external_id) WHERE scim_external_id IS NOT NULL;

-- 3. Update updated_at triggers for both tables to include the new columns
-- (triggers are in 002_triggers.sql and already use NEW.* — they auto-include new columns.
-- Verify by checking trigger definition; no ALTER needed for row-level BEFORE UPDATE triggers.)

-- 4. Expand source column on distribution_group_members to include 'scim'
ALTER TABLE distribution_group_members
  DROP CONSTRAINT IF EXISTS distribution_group_members_source_check;
ALTER TABLE distribution_group_members
  ADD CONSTRAINT distribution_group_members_source_check
  CHECK (source IN ('manual', 'sso', 'scim'));

-- 5. scim_tokens table — named API keys for IdP provisioning agents
CREATE TABLE scim_tokens (
  id                BIGSERIAL    PRIMARY KEY,
  name              TEXT         NOT NULL UNIQUE,
  token_hash        TEXT         NOT NULL,
  expires_at        TIMESTAMPTZ,
  deletion_policy   TEXT         NOT NULL DEFAULT 'soft'
                      CHECK (deletion_policy IN ('soft', 'hard')),
  attribute_mapping JSONB        NOT NULL DEFAULT '{}',
  last_used_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by        TEXT,
  revoked_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS scim_tokens_hash_idx ON scim_tokens(token_hash);
