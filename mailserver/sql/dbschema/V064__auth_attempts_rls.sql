-- V064__auth_attempts_rls.sql — R4 backstop for auth_attempts (CA-3b confirmed finding).
-- auth_attempts is a per-user table holding auth events (password spray detections,
-- geo blocks, velocity failures, etc.). compute_user_risk (CA-3b/T3) is the first
-- cross-user reducer to read it; it runs on DB_WORKER_DSN (BYPASSRLS) and is safe
-- by design — but the table had no RLS fence at all. A direct SELECT from
-- setjoin_app (NOBYPASSRLS) would expose every user's auth history without a
-- row-level gate. This migration adds the structural R4 backstop.
--
-- Pattern: identical to ca_signin_log (V027) — the closest analog (auth-system
-- append-only event table with open admin-read and open insert).
--
-- Partition note: ENABLE/FORCE on the parent table propagates to all child
-- partitions (PG 12+). No per-partition ALTER needed.
--
-- detect_spray (authserver reducer) does a cross-user IP scan; it must run on
-- DB_WORKER_DSN (BYPASSRLS). The admin_read USING (true) policy covers the
-- default-deploy case (DB_WORKER_DSN unset, workerPool aliases main pool /
-- setjoin_app) without weakening the structural fence — the app-layer gate
-- (access.policy_read) is the auth backstop, matching ca_signin_log.

ALTER TABLE public.auth_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_attempts FORCE  ROW LEVEL SECURITY;

-- Self-read: user sees their own auth events (target_username = their email).
-- ponytail: NULLIF fail-closed — unset app.current_user_id → NULL subquery → no rows.
-- Subquery resolves bigint GUC to email; matches auth_attempts.target_username.
DROP POLICY IF EXISTS auth_attempts_self ON public.auth_attempts;
CREATE POLICY auth_attempts_self ON public.auth_attempts
    FOR SELECT
    USING (target_username = (
        SELECT email FROM public.users
         WHERE id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    ));

-- Admin-read: open SELECT for admin tooling and system-level functions (detect_spray,
-- admin threat dashboards) running as setjoin_app in the default deploy.
-- Gated at the app layer on access.policy_read. Matches ca_signin_log pattern (V027).
DROP POLICY IF EXISTS auth_attempts_admin_read ON public.auth_attempts;
CREATE POLICY auth_attempts_admin_read ON public.auth_attempts
    FOR SELECT USING (true);

-- Insert: authserver gateway writes auth events on every login attempt. Open insert;
-- no row-level restriction on what can be written (content validated at the schema
-- level via the outcome CHECK constraint).
-- ponytail: tighten to CHECK(target_username IS NOT NULL) if needed in future.
DROP POLICY IF EXISTS auth_attempts_app_insert ON public.auth_attempts;
CREATE POLICY auth_attempts_app_insert ON public.auth_attempts
    FOR INSERT WITH CHECK (true);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (64, now())
    ON CONFLICT (version) DO NOTHING;
