CREATE TABLE public.audit_policy (
    id                    smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    level                 text NOT NULL DEFAULT 'lean' CHECK (level IN ('lean','full')),
    reason_required_areas text[] NOT NULL DEFAULT '{}',
    updated_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            bigint
);
INSERT INTO public.audit_policy (id) VALUES (1) ON CONFLICT DO NOTHING;
INSERT INTO public.schema_migrations (version, applied_at) VALUES (38, now()) ON CONFLICT (version) DO NOTHING;
