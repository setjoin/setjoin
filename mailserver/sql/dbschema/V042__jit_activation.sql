-- V042: JIT activation (Entra PIM). Per-assignment eligible-vs-active.
ALTER TABLE public.admin_role_assignments
  ADD COLUMN eligible        boolean NOT NULL DEFAULT false,
  ADD COLUMN activated_until  timestamptz;

CREATE TABLE public.admin_role_activation_policy (
  role_group_id        bigint PRIMARY KEY REFERENCES public.admin_role_groups(id) ON DELETE CASCADE,
  max_duration_minutes integer NOT NULL,
  require_justification boolean NOT NULL DEFAULT false
);

-- Global defaults (system_config jsonb; read via COALESCE((value->>0)::T, default)).
SELECT public.set_system_config('jit.default_max_minutes', '480'::jsonb);
SELECT public.set_system_config('jit.default_require_justification', 'false'::jsonb);

-- Feature toggle, default OFF (feature_toggles.enabled DEFAULTs true, so set it explicitly).
INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('rbac.jit', false, 'Just-in-time admin role activation (eligible assignments require time-boxed activation)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (42, now())
  ON CONFLICT (version) DO NOTHING;
