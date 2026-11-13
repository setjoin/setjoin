-- TEST ONLY: temporary legacy table shape, absent from the active combined schema.
-- Never loaded by the runtime schema loader. The F09 oracle creates/drops these
-- objects only in its assigned disposable DB and records schema-missing cases too.
CREATE TABLE public.rule_templates (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT,
    category TEXT NOT NULL DEFAULT 'general'
        CHECK (category IN ('forwarding','organization','automation','security','general')),
    conditions JSONB NOT NULL DEFAULT '[]', actions JSONB NOT NULL DEFAULT '[]',
    parameters JSONB NOT NULL DEFAULT '[]', is_system BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE, sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE public.rule_template_visibility (
    template_id BIGINT NOT NULL REFERENCES public.rule_templates(id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES public.users(id) ON DELETE CASCADE,
    hidden BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX gofree_rules1_visibility_unique
    ON public.rule_template_visibility (template_id, (COALESCE(user_id, -1)));
COMMENT ON TABLE public.rule_templates IS 'gofree-rules1 temporary oracle fixture';
COMMENT ON TABLE public.rule_template_visibility IS 'gofree-rules1 temporary oracle fixture';
GRANT SELECT,INSERT,UPDATE,DELETE ON public.rule_templates,public.rule_template_visibility TO setjoin_app,setjoin_worker;
GRANT USAGE,SELECT ON SEQUENCE public.rule_templates_id_seq TO setjoin_app,setjoin_worker;
