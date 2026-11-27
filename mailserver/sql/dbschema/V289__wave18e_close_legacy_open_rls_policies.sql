-- V289__wave18e_close_legacy_open_rls_policies.sql — Wave 1.8 Phase 546e:
-- Close all 4 legacy open TO PUBLIC (`USING (true)` / `WITH CHECK (true)`) RLS
-- policies so every scoped table under `setjoin_app` (`NOBYPASSRLS`) enforces
-- strict fail-closed tenant isolation with zero permissive `true` carve-outs:
--   - V055: `session_revocations_admin_read` ON public.session_revocations (SELECT USING (true))
--   - V057: `session_revocations_app_insert` ON public.session_revocations (INSERT WITH CHECK (true))
--   - V059: `user_devices_admin_read`        ON public.user_devices        (SELECT USING (true))
--   - V060: `devices_admin_read`             ON public.devices             (SELECT USING (true))
--
-- Cross-tenant / pre-auth lookups (`DeviceResolver::verify_request`, admin MDM
-- queues, session enforcement logs, background denylist sync) run on
-- `setjoin_worker` (`DB_WORKER_DSN`, `BYPASSRLS`); authenticated user paths set
-- transaction-local `app.current_user_id` under `setjoin_app`.

BEGIN;

SET LOCAL lock_timeout = '5s';

-- Canonical alphabetical lock order across the 3 touched tables.
LOCK TABLE
  public.devices,
  public.session_revocations,
  public.user_devices
IN ACCESS EXCLUSIVE MODE;

-- 1. public.devices — drop legacy open SELECT; enforce strict user_id scope for setjoin_app.
DROP POLICY IF EXISTS devices_admin_read ON public.devices;
DROP POLICY IF EXISTS devices_self ON public.devices;
CREATE POLICY devices_self ON public.devices
  FOR ALL TO setjoin_app
  USING (
    user_id IS NOT NULL
    AND user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  )
  WITH CHECK (
    user_id IS NOT NULL
    AND user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  );

-- 2. public.user_devices — drop legacy open SELECT; enforce strict user_id scope for setjoin_app.
DROP POLICY IF EXISTS user_devices_admin_read ON public.user_devices;
DROP POLICY IF EXISTS user_devices_self ON public.user_devices;
CREATE POLICY user_devices_self ON public.user_devices
  FOR ALL TO setjoin_app
  USING (
    user_id IS NOT NULL
    AND user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  )
  WITH CHECK (
    user_id IS NOT NULL
    AND user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  );

-- 3. public.session_revocations — drop legacy open SELECT + INSERT; enforce strict user_id scope
--    for setjoin_app self-SELECT and self-INSERT (UPDATE/DELETE remain default-deny).
DROP POLICY IF EXISTS session_revocations_admin_read ON public.session_revocations;
DROP POLICY IF EXISTS session_revocations_app_insert ON public.session_revocations;
DROP POLICY IF EXISTS session_revocations_self ON public.session_revocations;
DROP POLICY IF EXISTS session_revocations_app_self_insert ON public.session_revocations;
CREATE POLICY session_revocations_self ON public.session_revocations
  FOR SELECT TO setjoin_app
  USING (
    user_id IS NOT NULL
    AND user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  );
CREATE POLICY session_revocations_app_self_insert ON public.session_revocations
  FOR INSERT TO setjoin_app
  WITH CHECK (
    user_id IS NOT NULL
    AND user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  );

INSERT INTO public.schema_migrations (version, applied_at) VALUES (289, now())
  ON CONFLICT (version) DO NOTHING;

COMMIT;
