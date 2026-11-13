-- ════════════════════════════════════════════════════════════════════════
-- V011__backfill_admin_role_assignments.sql — forward migration (RBAC backfill).
--
-- SECURITY backfill paired with the bounded legacy IsAdmin bridge. The bridge
-- (IsAdmin + empty resolved perms ⇒ full access) is now bounded to drainable
-- legacy / super_admin tokens, so a CURRENT granular admin (user_admin /
-- auditor / read_only) with NO admin_role_assignments row would resolve to an
-- EMPTY permission set and be denied everything. This backfill ensures every
-- such admin gets the built-in role group matching their users.admin_role, so
-- their resolved permissions are non-empty and they stop depending on the bridge.
--
-- Mapping (users.admin_role → built-in admin_role_groups.name):
--   super_admin → 'Super Admin'
--   user_admin  → 'User Admin'
--   auditor     → 'Audit Reader'
--   read_only   → 'Global Reader'  (the V010 read-only-everything preset)
--
-- granted_by = the user's own id (self-granted backfill). Idempotent: only
-- inserts where the user is an admin with a named admin_role and has NO existing
-- assignment to that group (WHERE NOT EXISTS + ON CONFLICT DO NOTHING on the
-- UNIQUE (user_id, role_group_id)).
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.admin_role_assignments (user_id, role_group_id, granted_by)
SELECT u.id, g.id, u.id
FROM public.users u
JOIN (VALUES
        ('super_admin', 'Super Admin'),
        ('user_admin',  'User Admin'),
        ('auditor',     'Audit Reader'),
        ('read_only',   'Global Reader')
     ) AS m(admin_role, group_name) ON m.admin_role = u.admin_role
JOIN public.admin_role_groups g ON g.name = m.group_name
WHERE u.is_admin = true
  AND u.admin_role IS NOT NULL
  AND NOT EXISTS (
        SELECT 1 FROM public.admin_role_assignments ra
        WHERE ra.user_id = u.id AND ra.role_group_id = g.id
      )
ON CONFLICT (user_id, role_group_id) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (11, now())
    ON CONFLICT (version) DO NOTHING;
