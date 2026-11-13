-- Retire group reducers whose signatures predate authenticated source-generation
-- fencing. The reducer loader installs only the generation-aware overloads.
DROP FUNCTION IF EXISTS public.scim_upsert_group(BIGINT,TEXT,TEXT);
DROP FUNCTION IF EXISTS public.scim_delete_group(BIGINT,BIGINT);
DROP FUNCTION IF EXISTS public.scim_apply_group_members(BIGINT,TEXT,TEXT[],BOOLEAN);
DROP FUNCTION IF EXISTS public.scim_remove_group_members(BIGINT,TEXT,TEXT[]);

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (169, now()) ON CONFLICT (version) DO NOTHING;
