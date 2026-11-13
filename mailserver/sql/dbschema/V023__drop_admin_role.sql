-- ════════════════════════════════════════════════════════════════════════
-- V023__drop_admin_role.sql — drop the legacy users.admin_role enum column.
--
-- The RBAC unification cut-over made governed admin_role_assignments the SINGLE
-- authority axis. Every read of users.admin_role / Claims.AdminRole has been
-- removed across all three modules (authserver, mailserver gateway, shared):
--   * JWTs no longer carry an admin_role ("role") claim.
--   * /auth/me derives is_admin from an unexpired admin_role_assignments row.
--   * impersonation rank derives from governed assignments (Super Admin group 1).
--   * SSO group→role writes target admin_role_assignments (NULL granted_by),
--     never users.admin_role.
--   * admin_sod_precheck() dropped the legacy_admin_role axis (vacuous now).
-- This migration drops the now-unread column and its CHECK constraint.
--
-- users.is_admin is INTENTIONALLY RETAINED — it still feeds Claims.IsAdmin, the
-- impersonate defense-in-depth, and auth_policy.sql's parameter. Only admin_role
-- is removed here.
--
-- Idempotent: IF EXISTS on both drops, so re-running is a no-op.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_admin_role_check;
ALTER TABLE public.users DROP COLUMN IF EXISTS admin_role;


-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (23, now())
  ON CONFLICT (version) DO NOTHING;
