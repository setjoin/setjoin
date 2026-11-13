-- V021: Make admin_role_assignments.granted_by nullable.
--
-- SSO group-mapping creates system-provisioned assignment rows on behalf of
-- the IdP — there is no human granter.  NULL granted_by means "system" (SSO
-- or any automated process).  Human-initiated grants written by the admin UI
-- continue to record the granting admin's user_id.
ALTER TABLE public.admin_role_assignments
    ALTER COLUMN granted_by DROP NOT NULL;


-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (21, now())
  ON CONFLICT (version) DO NOTHING;
