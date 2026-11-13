-- V043: thread eligible flag through bulk role assignment jobs.
-- Allows bulk-assign to mark assignments as eligible (JIT-only) rather than active.
ALTER TABLE public.bulk_role_jobs
  ADD COLUMN eligible boolean NOT NULL DEFAULT false;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (43, now())
  ON CONFLICT (version) DO NOTHING;
