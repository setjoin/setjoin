-- ════════════════════════════════════════════════════════════════════════
-- V055__cae_runtime_core.sql — CA-3a runtime / CAE CORE.
-- Adds the live session-revocation denylist, server-side idle/binding state,
-- and the per-policy session_control knob. Seeds feature.cae_runtime and
-- feature.token_binding (DEFAULT OFF — inert until deliberately flipped; the
-- code default toggle.IsEnabledDefault(key,false) is the real safety net).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.session_revocations (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  scope       TEXT   NOT NULL CHECK (scope IN ('all','family','jti')),
  jti         TEXT,
  family_id   TEXT,
  -- ponytail: fail-closed DB backstop — a NULL jti/family_id with the matching scope
  -- silently never matches any real token; the reducer layer alone can't catch this.
  CONSTRAINT session_revocations_jti_required    CHECK ((scope <> 'jti')    OR (jti IS NOT NULL)),
  CONSTRAINT session_revocations_family_required CHECK ((scope <> 'family') OR (family_id IS NOT NULL)),
  not_before  TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason      TEXT   NOT NULL,
  created_by  BIGINT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS session_revocations_user
  ON public.session_revocations(user_id, not_before DESC);
ALTER TABLE public.session_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.session_revocations FORCE ROW LEVEL SECURITY;
-- Self-read own rows; the setjoin_worker (BYPASSRLS) pool reconciles cross-user.
-- ponytail: NULLIF fail-closed — empty app.current_user_id → NULL → no rows returned.
DROP POLICY IF EXISTS session_revocations_self ON public.session_revocations;
CREATE POLICY session_revocations_self ON public.session_revocations
  FOR SELECT
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint));
-- Admin-read: allows the admin pool (setjoin_app, NOBYPASSRLS) to SELECT all rows for
-- SessionEnforcementLog. In the default deploy (DB_WORKER_DSN unset, workerPool aliases pool),
-- BYPASSRLS is not available; this policy lifts the RLS default-deny so the admin endpoint
-- returns rows. App-layer gate (access.policy_read) is the auth backstop, matching ca_signin_log.
DROP POLICY IF EXISTS session_revocations_admin_read ON public.session_revocations;
CREATE POLICY session_revocations_admin_read ON public.session_revocations
  FOR SELECT USING (true);

CREATE TABLE IF NOT EXISTS public.session_activity (
  jti           TEXT PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  last_activity TIMESTAMPTZ NOT NULL DEFAULT now(),
  bound_key_jkt TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS session_activity_user
  ON public.session_activity(user_id);
ALTER TABLE public.session_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.session_activity FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS session_activity_self ON public.session_activity;
CREATE POLICY session_activity_self ON public.session_activity
  FOR SELECT
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint));

ALTER TABLE public.conditional_access_policies
  ADD COLUMN IF NOT EXISTS session_control JSONB NOT NULL DEFAULT '{}'::jsonb;

INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('feature.cae_runtime', false,
   'Per-request conditional-access re-evaluation + live session revocation (CAE-equivalent) in the gateway. DEFAULT OFF — pure pass-through until flipped.'),
  ('feature.token_binding', false,
   'Sender-constrained access tokens (DPoP / mTLS cnf). DEFAULT OFF; ships report_only when first enabled.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (55, now())
  ON CONFLICT (version) DO NOTHING;
