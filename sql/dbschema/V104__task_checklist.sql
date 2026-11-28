-- V104__task_checklist.sql — in-task lightweight checklist / steps (QoL #21).
--
-- A JSONB array of {id,text,done} on the task itself — check-off sub-steps
-- WITHOUT a full subtask object (the heavyweight one-level parent_id path stays
-- for real subtasks). Whole-array replace on save (the client sends the full
-- array back); item-level shape (text/done) is validated in the reducer, same as
-- categories/rrule. The DB only guards the top-level array shape.
ALTER TABLE public.tasks ADD COLUMN checklist JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE public.tasks ADD CONSTRAINT tasks_checklist_shape
  CHECK (jsonb_typeof(checklist) = 'array');

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (104, now())
    ON CONFLICT (version) DO NOTHING;
