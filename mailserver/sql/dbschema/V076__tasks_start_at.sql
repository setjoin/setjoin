-- V076: add tasks.start_at (a task's start date), mirroring due_at.
-- Outlook/Gmail Tasks both expose a start date distinct from the due date; the column
-- is nullable (optional, like due_at) and surfaced via the JMAP Task startAt property.

ALTER TABLE public.tasks ADD COLUMN IF NOT EXISTS start_at timestamp with time zone;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (76, now())
  ON CONFLICT (version) DO NOTHING;
