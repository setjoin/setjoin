-- ════════════════════════════════════════════════════════════════════════
-- V082__calendar_event_classification.sql — forward migration: event privacy.
--
-- Stores the iCal CLASS token (RFC 5545) per event, mirroring how `transp`
-- stores OPAQUE/TRANSPARENT. Surfaced to the OWNER as the RFC 8984 JSCalendar
-- `privacy` field (public|private|secret) via jmap_calendar_event_{get,
-- set_create,set_update}.
--
-- SECURITY: a non-PUBLIC event is REDACTED for every non-owner shared-calendar
-- viewer — the widened redaction gate in reducers/calendar_sharing.sql
-- (jmap_calendar_event_get_shared) treats classification<>'PUBLIC' the same as
-- a freebusy grant (title→'Busy', location/description/rrule NULL'd).
--
-- DEFAULT 'PUBLIC' backfills every existing row → zero behaviour change.
-- CONFIDENTIAL == PRIVATE for redaction in v1 (both <> 'PUBLIC').
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.calendar_events
  ADD COLUMN IF NOT EXISTS classification text NOT NULL DEFAULT 'PUBLIC';

ALTER TABLE public.calendar_events
  DROP CONSTRAINT IF EXISTS calendar_events_classification_check;

ALTER TABLE public.calendar_events
  ADD CONSTRAINT calendar_events_classification_check
  CHECK (classification IN ('PUBLIC','PRIVATE','CONFIDENTIAL'));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (82, now())
    ON CONFLICT (version) DO NOTHING;
