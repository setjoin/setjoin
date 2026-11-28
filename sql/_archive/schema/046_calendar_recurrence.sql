-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 046: Calendar recurrence exception handling (Phase 40).
-- RECURRENCE-ID links exception events to their master for correct expansion.
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS parent_event_uid TEXT;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS recurrence_override TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS calendar_events_parent_idx
  ON calendar_events(parent_event_uid, recurrence_override)
  WHERE parent_event_uid IS NOT NULL;

-- Recurrence-aware uniqueness for (calendar_id, uid). A master event has
-- recurrence_override IS NULL; its RECURRENCE-ID exception events share the same uid
-- (RFC 4791) and are distinguished by a non-NULL recurrence_override. NULLS NOT
-- DISTINCT (PG15+) keeps two masters with the same uid in one calendar rejected, while
-- letting each exception coexist alongside the master. Defined here (not in 010_*)
-- because it references recurrence_override, which is added just above.
CREATE UNIQUE INDEX IF NOT EXISTS calendar_events_calendar_id_uid_recurrence_key
  ON calendar_events (calendar_id, uid, recurrence_override)
  NULLS NOT DISTINCT;
