-- ════════════════════════════════════════════════════════════════════════
-- V097__calendar_changes_journal.sql — A4 wave 2: real Calendar + CalendarEvent
-- /changes deltas. Mirrors V095 (Task) / V096 (ContactCard/AddressBook) for the
-- two calendar datatypes, keying each to its own per-(mailbox,datatype) monotonic
-- jmap_entity_state counter ('Calendar' vs 'CalendarEvent'). Before A4 both read
-- MAX(calendars.jmap_state) / MAX(calendar_events.jmap_state) — non-monotonic
-- tokens that a non-max-row update left unmoved (change silently dropped) and a
-- max-row destroy made regress. Separate journal counters give real
-- created/updated/destroyed lists per datatype.
--
-- MAILBOX-ID RESOLUTION (same shape as V096 contacts):
--   · calendars HAS a direct mailbox_id → trg_journal_calendar uses NEW/OLD.mailbox_id.
--   · calendar_events has ONLY calendar_id → trg_journal_calendar_event resolves
--     mailbox_id via calendars. Under a calendar DELETE the FK cascade
--     (calendar_events_calendar_id_fkey ON DELETE CASCADE) removes the parent
--     calendar row before the cascaded event-delete trigger runs, so that resolve
--     yields NULL and the trigger skips — covered precisely by the CalendarEvent
--     resync sentinel emitted in trg_journal_calendar's DELETE branch (below).
--
-- ── THE CROSS-MAILBOX RLS TRAP (gauntlet F5 — the load-bearing design point) ──
-- jmap_entity_state + jmap_changes_journal are ENABLE+FORCE RLS with a WITH CHECK
-- (mailbox_id = app.current_mailbox_id). A trigger's journal INSERT to mailbox X
-- passes WITH CHECK only if X == the acting tx's mailbox GUC (or the role is
-- BYPASSRLS). Unlike Task/Contacts, calendar has real cross-mailbox and no-GUC
-- write paths on the FORCE'd app pool:
--   · calendar_book_resource (CalendarEvent/set create → calendar_finalize_create_bookings,
--     CallScoped, GUC = the BOOKER's mailbox) INSERTs a calendar_events row into a
--     ROOM/equipment calendar whose mailbox_id is the ROOM's — X != GUC.
--   · Raw Go calendar create/delete (internal/user/calendar_subscriptions.go,
--     internal/caldav.go) run under dbscope.RunUserScoped, which sets
--     app.current_user_id but NOT app.current_mailbox_id — empty mailbox GUC.
--   · iMIP CANCEL/REPLY (calendar_process_itip_cancel/reply) update every local copy
--     of a UID across attendee mailboxes — today on the BYPASSRLS worker pool.
-- SECURITY DEFINER does NOT rescue the first two: it would run as setjoin_owner,
-- which is ALSO NOBYPASSRLS (verified: provision-roles.sql), so FORCE still rejects
-- the write (42501). Fix: the journal write is BEST-EFFORT — each trigger catches
-- insufficient_privilege and SKIPS the delta rather than break the calendar mutation.
-- Same-mailbox JMAP writes (the paths a client actually syncs) journal precisely; the
-- skipped cross-mailbox cases (room calendars nobody syncs; rare calendar-list DDL)
-- resync — SF-4 delegated/shared attribution is out of A4 scope. In dev/test the mail
-- superuser bypasses RLS so journaling always succeeds. Deltas are attributed to the
-- OWNER mailbox of the changed row (calendars.mailbox_id — correct per F5).
-- ════════════════════════════════════════════════════════════════════════

-- ── Calendar journaling trigger ──────────────────────────────────────────────
-- calendars has mailbox_id directly → journal at NEW/OLD.mailbox_id. On DELETE also
-- emit a CalendarEvent resync sentinel: the cascaded event deletes cannot resolve
-- their (now-gone) parent calendar's mailbox, so a client syncing CalendarEvent
-- across the deletion must resync (BZ011) rather than keep ghost events. This one
-- place covers every calendar-delete path (raw Go DELETE, mailbox-cascade, any
-- future reducer). Best-effort catch — see the F5 note above.
CREATE OR REPLACE FUNCTION public.journal_calendar_change() RETURNS TRIGGER AS $$
BEGIN
  -- Best-effort journal — see the RLS note on journal_calendar_event_change below.
  BEGIN
    IF TG_OP = 'DELETE' THEN
      PERFORM append_change(OLD.mailbox_id, 'Calendar',
                            bump_entity_state(OLD.mailbox_id, 'Calendar'), OLD.id, 'destroyed');
      -- ponytail: unconditional CalendarEvent resync sentinel on calendar delete. At
      -- AFTER-DELETE time the child events are already cascaded away so we cannot
      -- cheaply test "had events"; a spurious resync on an empty-calendar delete is
      -- harmless (one full CalendarEvent resync for that mailbox). Upgrade path: a
      -- BEFORE-DELETE row count if the spurious resync ever matters.
      PERFORM append_change(OLD.mailbox_id, 'CalendarEvent',
                            bump_entity_state(OLD.mailbox_id, 'CalendarEvent'), NULL, 'resync');
    ELSIF TG_OP = 'INSERT' THEN
      PERFORM append_change(NEW.mailbox_id, 'Calendar',
                            bump_entity_state(NEW.mailbox_id, 'Calendar'), NEW.id, 'created');
    ELSE
      PERFORM append_change(NEW.mailbox_id, 'Calendar',
                            bump_entity_state(NEW.mailbox_id, 'Calendar'), NEW.id, 'updated');
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_journal_calendar ON public.calendars;
CREATE TRIGGER trg_journal_calendar
  AFTER INSERT OR UPDATE OR DELETE ON public.calendars
  FOR EACH ROW EXECUTE FUNCTION public.journal_calendar_change();

-- ── CalendarEvent journaling trigger ─────────────────────────────────────────
-- calendar_events has NO direct mailbox_id → resolve via calendars. Under a calendar
-- DELETE the parent is already gone (FK cascade), so the resolve yields NULL and we
-- skip; the trg_journal_calendar CalendarEvent resync sentinel covers that path.
-- For every other op (insert/update, and a direct event delete while its calendar
-- still exists — the JMAP set_destroy path) the resolve succeeds → precise
-- created/updated/destroyed, attributed to the calendar's OWNER mailbox. This also
-- covers, without any manual append, the RSVP/iTIP-cancel UPDATEs (a cancel flips
-- status→cancelled = an UPDATE → 'updated').
--
-- RLS / cross-mailbox (gauntlet F5 — the load-bearing note referenced by the Task,
-- contacts and calendar triggers). The journal + counter are FORCE'd, mailbox-scoped
-- (WITH CHECK mailbox_id = app.current_mailbox_id). Two app-pool paths write a row
-- whose OWNER mailbox differs from the acting GUC: a resource booking INSERTs an event
-- into a ROOM calendar (mailbox = resource, GUC = booker), and raw-Go calendar DDL
-- runs under RunUserScoped (app.current_user_id set, NO mailbox GUC). On the flipped
-- app pool (setjoin_app, NOBYPASSRLS) those journal writes raise 42501 — and
-- SECURITY DEFINER does NOT help, because setjoin_owner is ALSO NOBYPASSRLS (verified:
-- provision-roles.sql). So the write is best-effort: catch insufficient_privilege and
-- SKIP the delta rather than break the calendar mutation. Same-mailbox JMAP writes
-- (the paths a client actually syncs) journal precisely; the skipped cross-mailbox
-- cases (room calendars nobody syncs; rare calendar-list DDL) resync — SF-4 delegated/
-- shared attribution is explicitly out of A4 scope. In dev/test the mail superuser
-- bypasses RLS so journaling always succeeds.
CREATE OR REPLACE FUNCTION public.journal_calendar_event_change() RETURNS TRIGGER AS $$
DECLARE
  v_mailbox_id BIGINT;
BEGIN
  BEGIN
    IF TG_OP = 'DELETE' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM calendars WHERE id = OLD.calendar_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'CalendarEvent',
                              bump_entity_state(v_mailbox_id, 'CalendarEvent'), OLD.id, 'destroyed');
      END IF;
    ELSIF TG_OP = 'INSERT' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM calendars WHERE id = NEW.calendar_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'CalendarEvent',
                              bump_entity_state(v_mailbox_id, 'CalendarEvent'), NEW.id, 'created');
      END IF;
    ELSE
      SELECT mailbox_id INTO v_mailbox_id FROM calendars WHERE id = NEW.calendar_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'CalendarEvent',
                              bump_entity_state(v_mailbox_id, 'CalendarEvent'), NEW.id, 'updated');
      END IF;
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_journal_calendar_event ON public.calendar_events;
CREATE TRIGGER trg_journal_calendar_event
  AFTER INSERT OR UPDATE OR DELETE ON public.calendar_events
  FOR EACH ROW EXECUTE FUNCTION public.journal_calendar_event_change();

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (97, now())
    ON CONFLICT (version) DO NOTHING;
