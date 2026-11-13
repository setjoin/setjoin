-- ════════════════════════════════════════════════════════════════════════
-- V057__session_revocations_insert_policy.sql — CA-3a bug-fix.
--
-- V035 added ENABLE+FORCE RLS on session_revocations with a SELECT policy
-- only (self-read). The INSERT inside revoke_user_sessions() is called
-- as setjoin_app (NOBYPASSRLS) via the admin pool; without an INSERT
-- policy PostgreSQL's default-deny fires and the handler returns 500.
--
-- Fix: explicit INSERT policy with WITH CHECK (true) — the admin-route
-- permission gate (access.policy_write) + the reducer's audit row are the
-- real auth backstops; the RLS policy just lifts the default-deny so the
-- function can run.  Matches the pattern V027 used for ca_signin_log.
-- ════════════════════════════════════════════════════════════════════════

DROP POLICY IF EXISTS session_revocations_app_insert ON public.session_revocations;
CREATE POLICY session_revocations_app_insert ON public.session_revocations
  FOR INSERT
  WITH CHECK (true);

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (57, now())
    ON CONFLICT (version) DO NOTHING;
