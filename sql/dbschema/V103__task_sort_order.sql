-- V103__task_sort_order.sql — manual (drag/reorder) task ordering (QoL #20).
--
-- A GLOBAL (mailbox-wide) fractional sort key, NOT per-status: kanban columns
-- are just a filtered view over the same ordered list, so dragging a card
-- between columns doesn't renumber other columns, and the list view gets a
-- manual order for free. DOUBLE PRECISION so a reorder is a midpoint insert
-- (no bulk renumber) — the client computes the between-neighbours value.
ALTER TABLE public.tasks ADD COLUMN sort_order DOUBLE PRECISION NOT NULL DEFAULT 0;

-- Backfill so the upgrade preserves today's derived visual order (the same
-- ORDER BY jmap_task_get/query used before this column existed).
UPDATE public.tasks SET sort_order = sub.rn
FROM (
  SELECT id, ROW_NUMBER() OVER (
    PARTITION BY mailbox_id
    ORDER BY priority DESC, due_at NULLS LAST, created_at DESC
  ) AS rn
  FROM public.tasks
) sub
WHERE public.tasks.id = sub.id;

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (103, now())
    ON CONFLICT (version) DO NOTHING;
