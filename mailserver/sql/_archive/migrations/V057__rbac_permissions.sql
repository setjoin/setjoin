-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V057: Permission-based RBAC — role groups, permissions, assignments
BEGIN;

-- Reference table: all available permissions
CREATE TABLE IF NOT EXISTS admin_permissions (
    permission_key  TEXT PRIMARY KEY,
    category        TEXT NOT NULL,
    description     TEXT NOT NULL,
    is_sensitive    BOOLEAN DEFAULT false
);

-- Role groups bundle permissions into named roles
CREATE TABLE IF NOT EXISTS admin_role_groups (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    domain_scope    BIGINT REFERENCES domains(id),  -- NULL = global
    is_builtin      BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- Which users have which roles
CREATE TABLE IF NOT EXISTS admin_role_assignments (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_group_id   BIGINT NOT NULL REFERENCES admin_role_groups(id) ON DELETE CASCADE,
    domain_override BIGINT REFERENCES domains(id),  -- narrower than role scope
    granted_by      BIGINT NOT NULL REFERENCES users(id),
    granted_at      TIMESTAMPTZ DEFAULT now(),
    expires_at      TIMESTAMPTZ,  -- NULL = permanent
    UNIQUE(user_id, role_group_id)
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_user ON admin_role_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role ON admin_role_assignments(role_group_id);

COMMIT;
