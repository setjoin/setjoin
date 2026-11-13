-- V162: independent admission/read gates and per-source cutover mode.
ALTER TABLE public.identity_sources
    ADD COLUMN read_mode TEXT NOT NULL DEFAULT 'shadow'
    CHECK (read_mode IN ('legacy','shadow','canary','normalized'));

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
 ('feature.identity_normalized_reads',false,
  'Serve normalized identity links globally after shadow/canary proof'),
 ('feature.identity_transitions',false,
  'Admit new identity detach/migration transitions')
ON CONFLICT(key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (162, now());
