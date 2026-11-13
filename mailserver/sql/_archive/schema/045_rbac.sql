-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 045: Role-Based Access Control (Phase 38).
-- Replaces binary is_admin flag with granular admin roles.
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_role TEXT
  CHECK (admin_role IN ('super_admin','user_admin','read_only','auditor'));

-- Migrate existing admins to super_admin role
UPDATE users SET admin_role = 'super_admin'
WHERE is_admin = TRUE AND admin_role IS NULL;
