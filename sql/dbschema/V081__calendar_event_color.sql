-- ════════════════════════════════════════════════════════════════════════
-- V081__calendar_event_color.sql — forward migration: per-event color.
--
-- Gmail model: ONE color per event (a free-form hex string), NOT an Exchange
-- named-categories master list. A null/absent color means "inherit the
-- calendar's color" — the current behaviour, unchanged for existing rows.
--
-- Stored VERBATIM (no server-side hex validation): the webmail sanitizes on
-- render through safeColor() (#hex-only), matching how calendars.color already
-- flows. jmap_calendar_event_{get,set_create,set_update} carry the field.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.calendar_events ADD COLUMN IF NOT EXISTS color text;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (81, now())
    ON CONFLICT (version) DO NOTHING;
