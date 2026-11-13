-- V040__bulk_role_jobs_scope.sql — one uniform OU scope per bulk role job.
-- Mirrors admin_role_assignments scope columns (V039): scope_type='ou'+scope_id,
-- or NULL/NULL (no OU = domain-wide on the OU axis, the pre-V040 behavior).
-- group/user reserved in the CHECK for forward-compat; rejected at the API (like V039).
ALTER TABLE public.bulk_role_jobs
  ADD COLUMN scope_type text,
  ADD COLUMN scope_id   bigint,
  ADD CONSTRAINT bulk_role_jobs_scope_type_chk
    CHECK (scope_type IS NULL OR scope_type IN ('ou','group','user')),
  ADD CONSTRAINT bulk_role_jobs_scope_pair_chk
    CHECK ((scope_type IS NULL) = (scope_id IS NULL));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (40, now()) ON CONFLICT (version) DO NOTHING;
