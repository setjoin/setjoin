-- ════════════════════════════════════════════════════════════════════════
-- V060__devices_rls.sql — R4 backstop for public.devices.
--
-- devices stores hmac_secret (device authentication key) + fingerprints.
-- V033 added RLS to device_enroll_events; V039 added it to user_devices.
-- devices itself was missed. This closes the gap.
--
-- Pattern mirrors V039 (user_devices): self-read/write via per-user policy;
-- admin reads use the worker/admin (BYPASSRLS) pool. App-layer auth
-- (account_scope, R1–R3 in reducers) remains the primary guard; this is
-- the defense-in-depth backstop per root AGENTS.md R4.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devices FORCE ROW LEVEL SECURITY;

-- Self-read/write: user sees only their own device rows (R1/R3 backstop).
-- missing_ok GUC → NULL → fail-closed (no rows; no cast error — V003 pattern).
DROP POLICY IF EXISTS devices_self ON public.devices;
CREATE POLICY devices_self ON public.devices
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- Admin-read: lets the app pool (NOBYPASSRLS) SELECT all rows for MDM/admin
-- endpoints. App-layer gate (mail.offline_policy / admin role) is the auth
-- backstop — matches the admin_read pattern in V035/V039.
DROP POLICY IF EXISTS devices_admin_read ON public.devices;
CREATE POLICY devices_admin_read ON public.devices
    FOR SELECT USING (true);

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (60, now())
    ON CONFLICT (version) DO NOTHING;
