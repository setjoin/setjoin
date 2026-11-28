-- V154: durable, non-secret deployment identity for connector-secret AAD.
--
-- The value is created once and survives pg_dump/restore with system_config.
-- Connector secret envelopes bind to it so a ciphertext copied from a
-- different Setjoin deployment fails authentication.

INSERT INTO public.system_config (key, value, encrypted, description)
VALUES (
    'identity.deployment_id',
    to_jsonb(gen_random_uuid()::text),
    FALSE,
    'Stable deployment identity used as authenticated context for connector-secret envelopes'
)
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (154, now())
ON CONFLICT (version) DO NOTHING;
