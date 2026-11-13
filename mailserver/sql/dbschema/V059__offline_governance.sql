-- ════════════════════════════════════════════════════════════════════════
-- V059__offline_governance.sql — Offline-mail #2a: governance tables.
--
-- Creates:
--   offline_policies  — org/group/user-scoped policy records (RBAC-gated;
--                       R4 exception: org-level table, handler-auth enforced
--                       via mail.offline_policy perm added by V038).
--   user_devices cols — device_id, fingerprint_hash, offline_approval,
--                       offline_approval_at, offline_approval_by,
--                       offline_opt_in, offline_window_days.
--   UNIQUE INDEX       — user_devices(user_id, fingerprint_hash) WHERE NOT NULL.
--
-- feature.offline_mail already seeded OFF by V029; mail.offline_policy perm
-- already registered + assigned to Super Admin by V038. Not repeated here.
-- Forward migration on the V001 baseline (ARCH-007, no replay).
-- ════════════════════════════════════════════════════════════════════════

-- ── offline_policies (org table; R4 exception — handler-RBAC gated) ──────────
CREATE TABLE IF NOT EXISTS public.offline_policies (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL,
    scope_type       TEXT NOT NULL
                     CHECK (scope_type IN ('global','group','user')),
    scope_id         BIGINT,   -- group_id or user_id; NULL for global
    enabled          BOOLEAN NOT NULL DEFAULT false,
    max_offline_days INT NOT NULL DEFAULT 30
                     CHECK (max_offline_days >= 0),
    require_approval BOOLEAN NOT NULL DEFAULT true,
    wipe_on_logout   TEXT NOT NULL DEFAULT 'admin_default'
                     CHECK (wipe_on_logout IN ('always','admin_default','never')),
    priority         INT NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One global, disabled base-layer row so the resolver always finds a fallback.
-- ponytail: single seed row; policy resolver reads this when no narrower match.
INSERT INTO public.offline_policies (name, scope_type, scope_id, enabled, priority)
SELECT 'Default (global)', 'global', NULL, false, 0
WHERE NOT EXISTS (SELECT 1 FROM public.offline_policies WHERE scope_type = 'global');

-- ── user_devices: offline approval state + opt-in tracking ───────────────────
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS device_id           BIGINT
        REFERENCES public.devices(id),
    ADD COLUMN IF NOT EXISTS fingerprint_hash    BYTEA,
    ADD COLUMN IF NOT EXISTS offline_approval    TEXT NOT NULL DEFAULT 'pending'
        CHECK (offline_approval IN ('pending','approved','denied','revoked')),
    ADD COLUMN IF NOT EXISTS offline_approval_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS offline_approval_by BIGINT,
    ADD COLUMN IF NOT EXISTS offline_opt_in      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS offline_window_days INT;

-- Idempotent registration upsert key (native-device rows only).
-- ponytail: partial index avoids NULL-in-unique issues; NULL rows never collide.
CREATE UNIQUE INDEX IF NOT EXISTS user_devices_user_fp_uniq
    ON public.user_devices (user_id, fingerprint_hash)
    WHERE fingerprint_hash IS NOT NULL;

-- ── user_devices RLS (R4 fix — table predates RLS rollout; V039 is first touch) ─
-- Enable + force so even superuser-role app connections honour the policy unless
-- they explicitly BYPASSRLS (the worker/admin pool).
ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices FORCE ROW LEVEL SECURITY;

-- Self-read/write: user sees only their own device rows (R1/R3 backstop).
-- missing_ok GUC → NULL → fail-closed (no rows; no cast error — V003 pattern).
DROP POLICY IF EXISTS user_devices_self ON public.user_devices;
CREATE POLICY user_devices_self ON public.user_devices
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- Admin-read: lets the app pool (NOBYPASSRLS) SELECT all rows so the MDM
-- approval queue endpoint works in default deploy (DB_WORKER_DSN unset →
-- workerPool aliases pool, no BYPASSRLS). App-layer gate (mail.offline_policy
-- registered by V038) is the auth backstop — matches the session_revocations
-- admin_read pattern in V035.
DROP POLICY IF EXISTS user_devices_admin_read ON public.user_devices;
CREATE POLICY user_devices_admin_read ON public.user_devices
    FOR SELECT USING (true);

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (59, now())
    ON CONFLICT (version) DO NOTHING;
