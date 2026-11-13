-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V023: SSO stable identity matching + group provisioning.

-- 1. Stable identity columns on users
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS saml_name_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS saml_idp_entity_id TEXT;

-- Partial unique indexes — only enforce uniqueness when the column is set
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_subject_idx
  ON users(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL AND oidc_issuer IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_saml_name_id_idx
  ON users(saml_idp_entity_id, saml_name_id) WHERE saml_name_id IS NOT NULL AND saml_idp_entity_id IS NOT NULL;

-- 2. SAML group attribute config (default 'memberOf')
ALTER TABLE saml_sp_registrations ADD COLUMN IF NOT EXISTS group_attribute TEXT DEFAULT 'memberOf';
ALTER TABLE saml_sp_registrations ADD COLUMN IF NOT EXISTS group_mappings JSONB;

-- 3. Track auto-assigned distribution group memberships
ALTER TABLE distribution_group_members ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'manual'
  CHECK (source IN ('manual', 'sso'));
