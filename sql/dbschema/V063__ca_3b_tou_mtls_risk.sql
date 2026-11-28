-- ════════════════════════════════════════════════════════════════════════
-- V063__ca_3b_tou_mtls_risk.sql — CA-3b independent runtime features.
-- Terms-of-Use docs + per-user acceptance, and the local deterministic
-- user-risk score (Entra ID-Protection local-alt). Behaviour gated
-- default-OFF behind feature.conditional_access + feature.user_risk;
-- this migration is structural only.
-- (New seed data belongs in a forward migration, never a hand-edit of V001.)
-- ════════════════════════════════════════════════════════════════════════

-- ── Terms of Use documents ────────────────────────────────────────────────────
-- Admin-authored org-wide config (not per-user data): readable by any
-- authenticated user (to render the doc they must accept), mutated only by the
-- access.policy_write admin path. No per-user RLS (matches named_locations /
-- conditional_access_policies pattern — admin tables gated at the app layer).
CREATE TABLE IF NOT EXISTS public.terms_of_use (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name           text    NOT NULL,
    version        int     NOT NULL DEFAULT 1,
    body_md        text    NOT NULL,
    lang           text    NOT NULL DEFAULT 'en',
    require_scroll boolean NOT NULL DEFAULT TRUE,
    enabled        boolean NOT NULL DEFAULT TRUE,
    created_at     timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE (name, version, lang)
);

-- ── Per-user acceptance (self-scoped user data, R4) ───────────────────────────
CREATE TABLE IF NOT EXISTS public.terms_of_use_acceptance (
    user_id     bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    tou_id      bigint NOT NULL REFERENCES public.terms_of_use(id) ON DELETE CASCADE,
    version     int    NOT NULL,
    accepted_at timestamp with time zone NOT NULL DEFAULT now(),
    source_ip   inet,
    PRIMARY KEY (user_id, tou_id)
);
ALTER TABLE public.terms_of_use_acceptance ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.terms_of_use_acceptance FORCE  ROW LEVEL SECURITY;
-- ponytail: NULLIF fail-closed — empty app.current_user_id → NULL → no rows
-- returned (no cast error). Matches V040/V039 pattern.
DROP POLICY IF EXISTS toua_self ON public.terms_of_use_acceptance;
CREATE POLICY toua_self ON public.terms_of_use_acceptance
    USING      (user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint))
    WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint));

-- ── Local user-risk score (self-read; worker writes under DB_WORKER_DSN / BYPASSRLS) ──
-- Signals: failed-auth velocity (auth_attempts) + country-pair impossible-travel
-- (login_events.country + occurred_at). Computation by compute_user_risk reducer
-- (Task 3). This table is the sink; the CA engine reads it for require_risk_remediation.
CREATE TABLE IF NOT EXISTS public.user_risk (
    user_id       bigint   PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    score         smallint NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
    level         text     NOT NULL DEFAULT 'none' CHECK (level IN ('none','low','medium','high')),
    signals       jsonb    NOT NULL DEFAULT '[]'::jsonb,
    remediated_at timestamp with time zone,
    updated_at    timestamp with time zone NOT NULL DEFAULT now()
);
ALTER TABLE public.user_risk ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_risk FORCE  ROW LEVEL SECURITY;
-- Self-read only: user sees their own risk score. Worker writes via BYPASSRLS pool.
-- ponytail: NULLIF fail-closed (same as V040). No WITH CHECK — worker uses BYPASSRLS.
DROP POLICY IF EXISTS user_risk_self ON public.user_risk;
CREATE POLICY user_risk_self ON public.user_risk
    FOR SELECT
    USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint));

-- ── Feature toggle (default-OFF) ──────────────────────────────────────────────
-- ponytail: toggle.IsEnabledDefault(key, false) is the real safety net in Go —
-- inert on a fresh deployment regardless of this row. Row provides DB visibility.
INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('feature.user_risk', FALSE,
        'Compute a local deterministic per-user risk score (failed-auth velocity + country-pair impossible-travel over auth_attempts / login_events) and enforce require_risk_remediation CA action. DEFAULT OFF — inert until deliberately flipped; NOT Entra ML.')
ON CONFLICT (key) DO NOTHING;

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (63, now())
    ON CONFLICT (version) DO NOTHING;
