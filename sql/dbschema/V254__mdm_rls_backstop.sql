-- ════════════════════════════════════════════════════════════════════════
-- V254__mdm_rls_backstop.sql — R4 FORCE-RLS backstop for the MDM device
-- tables (L2 cluster C2, MDM-004 / rule R4-RLS-BACKSTOP-ABSENT).
--
-- Eight tables carried NO RLS while sibling device-trust tables received the
-- FORCE-RLS treatment (V053/V059/V060). This closes the gap with the project's
-- established postures, keyed on the SAME GUC the dbscope.RunUserScoped seam
-- sets transaction-locally (PgBouncer-safe):
--
--   Posture A (3) — per-user self + GUC-scoped admin arms:
--       mdm_device_state, device_registry, managed_devices.
--       Self = V059/V060 form (user_id = NULLIF(current_user GUC)); admin
--       arms = V224/V144 drive_has_admin_perm form — NEVER USING(true)
--       (V060's devices_admin_read shape is med-dbschema-rls-001's removal
--       target; no new USING(true) policy is minted here). Every admin-read
--       arm is the r2.4 view-or-manage OR-form: 'mam.read' OR 'mam.write' —
--       the wipe route requires only mam.write (main.go:4151) and the
--       invoker-rights mdm_device_wipe_arm reducer opens with SELECT ...
--       FOR UPDATE, so a write-only admin must be able to read.
--   Posture B (1) — device-join self + GUC-scoped admin arms:
--       device_events (keyed by device_id; owner via devices.user_id; the
--       V053 dee_self join form). The admin INSERT arm is perm-keyed WITH
--       CHECK so the wipe FSM's FK-honest NULL-device_id evidence row lands.
--   Posture C (3) — GUC-scoped admin-only org config:
--       mdm_policies, device_policy, device_policy_groups. Org-wide config
--       rows with no owner column (device_policy's NULL-device_id global
--       rows have no per-user path): SELECT arm admits 'mam.read' OR
--       'mam.write', the write arm is 'mam.write'-only — perm-keyed, never
--       owner-keyed, so the global rows stay reachable. The only non-admin
--       consumer (the device-HMAC checkin reader) is served EXCLUSIVELY
--       through mdm_effective_policy below (the ARCH-018 choke-point
--       recipe: policies APPLIED without being SELECTable).
--   Posture D (1) — deny-all FORCE (V217/V246/V249 form):
--       device_telemetry. Device-attested plumbing with no user GUC; the
--       ingest INSERT runs on the setjoin_worker (BYPASSRLS) pool and this
--       table has no reader anywhere. Zero policies = fail-closed for every
--       runtime role; proved non-vacuously by tests/V254__mdm_rls_backstop.pg.
--
--managed_devices is Posture A (not D): shared/threat's ResolveDeviceClaim /
-- isManagedDevice read it live on BOTH gateways' login paths (R1 keyed on
-- user_id), so deny-all would fail-closed every compliance read; zero writers
-- exist repo-wide, so the self FOR ALL arm is the whole surface.
--
-- TRUSTED SEAMS (r2.2). Two setjoin_worker-owned SECURITY DEFINER functions
-- (the established V114/V115 ALTER FUNCTION ... OWNER TO setjoin_worker +
-- EXECUTE-grant form) keep the no-GUC device paths alive under FORCE:
--   - mdm_effective_policy(p_device_id) — the device > group > global policy
--     merge for the authserver checkin reader; returns merged key/values +
--     wipe flag, never raw policy rows (a plain setjoin_app cannot SELECT
--     the underlying tables: choke-point invariant).
--   - mdm_checkin_event_append(p_device_id, p_event_type, p_event_data) —
--     the checkin evidence writer; resolves the device row in-DB before the
--     INSERT (R1 by resolution, not caller assertion).
--
-- OWNERSHIP: every table here moves to setjoin_owner (NOBYPASSRLS owner) so
-- ENABLE alone is not enough and FORCE binds the owner too — the V246/V249
-- pattern. App-layer auth (route middleware requireMamRead/requireMamWrite,
-- in-statement R1/R3 scope predicates, the BZ052 check-in reducer) remains
-- the PRIMARY guard; these policies are the defense-in-depth backstop per
-- root AGENTS.md R4. Live paths are GUC-paired by the coordinated Go wraps
-- (dbscope.RunUserScoped) shipped in the same window.
-- ════════════════════════════════════════════════════════════════════════

-- ── Posture A: mdm_device_state ───────────────────────────────────────────
ALTER TABLE public.mdm_device_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mdm_device_state FORCE ROW LEVEL SECURITY;

-- Self (R1/R3 backstop; V059/V060 self form; missing_ok GUC → NULL →
-- fail-closed empty-GUC, no cast error — V003 pattern).
DROP POLICY IF EXISTS mdm_device_state_self ON public.mdm_device_state;
CREATE POLICY mdm_device_state_self ON public.mdm_device_state
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- Admin read keyed on the MAM perms the route middleware enforces
-- (V224 view-or-manage OR-form; r2.4: a write-only admin must read — the
-- wipe reducer's first statement is SELECT ... FOR UPDATE).
DROP POLICY IF EXISTS mdm_device_state_admin_read ON public.mdm_device_state;
CREATE POLICY mdm_device_state_admin_read ON public.mdm_device_state
    FOR SELECT
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.read')
        OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

-- Admin write arm for the wipe FSM (invoker-rights reducer runs as the
-- caller; mam.write-only — the route gate for POST .../wipe).
DROP POLICY IF EXISTS mdm_device_state_admin_write ON public.mdm_device_state;
CREATE POLICY mdm_device_state_admin_write ON public.mdm_device_state
    FOR UPDATE
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    )
    WITH CHECK (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

-- ── Posture A: device_registry ────────────────────────────────────────────
-- The self FOR ALL arm is load-bearing: shared/threat's post-auth
-- upsertDevice INSERT..ON CONFLICT (user_id = GUC) passes USING/WITH CHECK
-- with the actor GUC paired by dbscope.RunUserScoped.
ALTER TABLE public.device_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_registry FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_registry_self ON public.device_registry;
CREATE POLICY device_registry_self ON public.device_registry
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- Admin read (MAM console list + per-device resolution resolve registry rows
-- through their owner; mam.write-only admins read — the r2.4 OR-form).
DROP POLICY IF EXISTS device_registry_admin_read ON public.device_registry;
CREATE POLICY device_registry_admin_read ON public.device_registry
    FOR SELECT
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.read')
        OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

-- ── Posture A: managed_devices ────────────────────────────────────────────
-- Login-time compliance surface (shared/threat ResolveDeviceClaim /
-- isManagedDevice). Self only: nothing reads it admin-side and no writer
-- exists repo-wide; a writer remains a separate decision.
ALTER TABLE public.managed_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.managed_devices FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS managed_devices_self ON public.managed_devices;
CREATE POLICY managed_devices_self ON public.managed_devices
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- ── Posture B: device_events ──────────────────────────────────────────────
-- Keyed by device_id (no user_id column); ownership resolves through
-- devices.user_id — the V053 dee_self join form, with WITH CHECK added for
-- the write direction.
ALTER TABLE public.device_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_events_self ON public.device_events;
CREATE POLICY device_events_self ON public.device_events
    FOR ALL
    TO public
    USING (
        device_id IN (
            SELECT id FROM public.devices
            WHERE user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
        )
    )
    WITH CHECK (
        device_id IN (
            SELECT id FROM public.devices
            WHERE user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
        )
    );

-- Admin read (mam.read OR mam.write — r2.4 OR-form).
DROP POLICY IF EXISTS device_events_admin_read ON public.device_events;
CREATE POLICY device_events_admin_read ON public.device_events
    FOR SELECT
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.read')
        OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

-- Admin evidence INSERT (LogDeviceEvent's lock/unlock/policy rows AND the
-- wipe FSM's FK-honest NULL-device_id lifecycle row): perm-keyed WITH CHECK,
-- never owner-keyed, so a NULL device_id admits under the mam.write arm
-- while the permissive-OR self arm stays the user path.
DROP POLICY IF EXISTS device_events_admin_insert ON public.device_events;
CREATE POLICY device_events_admin_insert ON public.device_events
    FOR INSERT
    TO public
    WITH CHECK (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

-- ── Posture C: mdm_policies / device_policy / device_policy_groups ───────
-- Org-wide config with no owner column: perm-keyed arms only. SELECT admits
-- 'mam.read' OR 'mam.write' (V224 view-or-manage; r2.4/r3.4 write-only-admin
-- visibility); the write arm is 'mam.write'-only WITH CHECK the same, which
-- admits device_policy's NULL-device_id global rows because the arm is
-- perm-keyed, not owner-keyed. The device-HMAC checkin reader gets its
-- policy exclusively through mdm_effective_policy below (choke point).
ALTER TABLE public.mdm_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mdm_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mdm_policies_admin_read ON public.mdm_policies;
CREATE POLICY mdm_policies_admin_read ON public.mdm_policies
    FOR SELECT
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.read')
        OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

DROP POLICY IF EXISTS mdm_policies_admin_write ON public.mdm_policies;
CREATE POLICY mdm_policies_admin_write ON public.mdm_policies
    FOR ALL
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    )
    WITH CHECK (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

ALTER TABLE public.device_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_policy FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_policy_admin_read ON public.device_policy;
CREATE POLICY device_policy_admin_read ON public.device_policy
    FOR SELECT
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.read')
        OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

DROP POLICY IF EXISTS device_policy_admin_write ON public.device_policy;
CREATE POLICY device_policy_admin_write ON public.device_policy
    FOR ALL
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    )
    WITH CHECK (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

ALTER TABLE public.device_policy_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_policy_groups FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_policy_groups_admin_read ON public.device_policy_groups;
CREATE POLICY device_policy_groups_admin_read ON public.device_policy_groups
    FOR SELECT
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.read')
        OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

DROP POLICY IF EXISTS device_policy_groups_admin_write ON public.device_policy_groups;
CREATE POLICY device_policy_groups_admin_write ON public.device_policy_groups
    FOR ALL
    TO public
    USING (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    )
    WITH CHECK (
        public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint, 'mam.write')
    );

-- ── Posture D: device_telemetry — deny-all FORCE (V217/V246/V249 form) ────
-- Device-attested plumbing with no user GUC (V239's documented rationale
-- pattern): the ingest INSERT moves to the setjoin_worker (BYPASSRLS) pool
-- in the same window; the table has no reader. Zero policies = fail-closed
-- for every runtime role, INCLUDING the owner (FORCE).
ALTER TABLE public.device_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_telemetry FORCE ROW LEVEL SECURITY;

-- ── Ownership: the NOBYPASSRLS owner owns every postured table ────────────
-- FORCE binds the owner too, so ENABLE alone can never silently no-op the
-- backstop (the V246/V249 rationale). setjoin_owner is provisioned by
-- scripts/provision-roles.sql (loader step 0/4 runs before migrations).
ALTER TABLE public.mdm_device_state     OWNER TO setjoin_owner;
ALTER TABLE public.device_registry      OWNER TO setjoin_owner;
ALTER TABLE public.managed_devices      OWNER TO setjoin_owner;
ALTER TABLE public.device_events        OWNER TO setjoin_owner;
ALTER TABLE public.mdm_policies         OWNER TO setjoin_owner;
ALTER TABLE public.device_policy        OWNER TO setjoin_owner;
ALTER TABLE public.device_policy_groups OWNER TO setjoin_owner;
ALTER TABLE public.device_telemetry     OWNER TO setjoin_owner;

-- ── Trusted seam 1: mdm_effective_policy (r2.2) ───────────────────────────
-- The trusted effective-policy reader for the device-HMAC checkin path
-- (authserver/internal/device checkin + /device/policy). SECURITY DEFINER
-- owned by setjoin_worker (BYPASSRLS definer — the established V114/V115
-- ALTER FUNCTION ... OWNER TO setjoin_worker + EXECUTE-grant form), invoked
-- by setjoin_app on the existing app pool: no new pool, no GUC on the device
-- path. It encapsulates the device > group > global merge EXACTLY (the
-- checkin contract: higher specificity wins; only group_type='department' is
-- resolved today — users has no role/domain mapping yet) and returns merged
-- key/values + the wipe flag — NEVER raw policy rows, so a non-admin holds
-- policies APPLIED without being able to SELECT them (ARCH-018 choke point;
-- direct device_policy/device_policy_groups SELECTs fail closed for any
-- non-mam GUC under the Posture C arms above).
CREATE OR REPLACE FUNCTION public.mdm_effective_policy(p_device_id bigint)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT jsonb_build_object(
        'policies',
        (SELECT COALESCE(jsonb_object_agg(g.policy_key, g.policy_value), '{}'::jsonb)
           FROM public.device_policy g
          WHERE g.device_id IS NULL)
        || COALESCE(
           (SELECT jsonb_object_agg(pg_.policy_key, pg_.policy_value)
              FROM public.device_policy_groups pg_
             WHERE pg_.group_type = 'department'
               AND pg_.group_id = (SELECT u.department_id
                                     FROM public.devices d
                                     JOIN public.users u ON u.id = d.user_id
                                    WHERE d.id = p_device_id)),
           '{}'::jsonb)
        || COALESCE(
           (SELECT jsonb_object_agg(pv.policy_key, pv.policy_value)
              FROM public.device_policy pv
             WHERE pv.device_id = p_device_id),
           '{}'::jsonb),
        'wipe_requested',
        COALESCE((SELECT d.wipe_requested FROM public.devices d WHERE d.id = p_device_id), false)
    )
$$;

-- ── Trusted seam 2: mdm_checkin_event_append (r2.2) ───────────────────────
-- The checkin evidence writer. SECURITY DEFINER owned by setjoin_worker so
-- the device-HMAC path (no user session, no GUC) can append device_events
-- rows under the Posture B FORCE flip. R1 BY RESOLUTION: the device row is
-- resolved in-DB and the INSERT only fires for an existing device — the
-- caller never asserts ownership, and a device_id that addresses no devices
-- row appends nothing (the caller's checked error path surfaces it).
CREATE OR REPLACE FUNCTION public.mdm_checkin_event_append(
    p_device_id   bigint,
    p_event_type  text,
    p_event_data  jsonb
)
RETURNS bigint
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    INSERT INTO public.device_events (device_id, event_type, event_data, created_at)
    SELECT p_device_id, p_event_type, p_event_data, now()
      FROM public.devices
     WHERE id = p_device_id
    RETURNING id
$$;

-- Ownership + EXECUTE grants for both seams (V115 form): the definer is the
-- worker credential; EXECUTE is revoked from PUBLIC and re-granted to the
-- runtime roles only. Guarded so a role-less cluster (fresh CI) still loads.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        ALTER FUNCTION public.mdm_effective_policy(bigint) OWNER TO setjoin_worker;
        ALTER FUNCTION public.mdm_checkin_event_append(bigint, text, jsonb) OWNER TO setjoin_worker;
    END IF;
    REVOKE EXECUTE ON FUNCTION public.mdm_effective_policy(bigint) FROM PUBLIC;
    REVOKE EXECUTE ON FUNCTION public.mdm_checkin_event_append(bigint, text, jsonb) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.mdm_effective_policy(bigint) TO setjoin_app;
        GRANT EXECUTE ON FUNCTION public.mdm_checkin_event_append(bigint, text, jsonb) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        GRANT EXECUTE ON FUNCTION public.mdm_effective_policy(bigint) TO setjoin_owner;
        GRANT EXECUTE ON FUNCTION public.mdm_checkin_event_append(bigint, text, jsonb) TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.mdm_effective_policy(bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.mdm_checkin_event_append(bigint, text, jsonb) TO setjoin_worker;
    END IF;
END $$;

-- ── Schema migration record (V060 bookkeeping form) ───────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (254, now())
    ON CONFLICT (version) DO NOTHING;
