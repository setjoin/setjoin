-- ════════════════════════════════════════════════════════════════════════
-- V109__recurrence_override_integrity.sql — recurring-event occurrence-edit
-- completion (docs/superpowers/plans/archive/2026-07-08-recurring-event-occurrence-edit.md).
--
-- ponytail: the plan called for a NEW unique index on
-- (calendar_id, uid, recurrence_override) + a dup backfill DELETE. Both already
-- exist/are unnecessary — V001 baseline ships
-- calendar_events_calendar_id_uid_recurrence_key UNIQUE (calendar_id, uid,
-- recurrence_override) NULLS NOT DISTINCT, which has prevented duplicate
-- override rows since day one (verified: a second same-occurrence 'this' edit
-- today raises a raw unique_violation, not a silent duplicate — the real bug,
-- fixed in the reducer via ON CONFLICT against this existing constraint, not a
-- new index). No backfill needed: no duplicates could ever have been written.
--
-- The one real gap: CalDAV's getEventByUID must resolve the master row
-- deterministically. events_uid_idx (plain btree on uid) doesn't discriminate
-- master vs. override rows; add the partial index CalDAV's WHERE
-- recurrence_override IS NULL clause (Task 6) will hit.
-- ════════════════════════════════════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_calendar_events_master_uid
  ON public.calendar_events (calendar_id, uid)
  WHERE recurrence_override IS NULL;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (109, now())
    ON CONFLICT (version) DO NOTHING;
