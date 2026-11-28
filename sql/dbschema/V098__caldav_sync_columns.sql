-- ════════════════════════════════════════════════════════════════════════
-- V098__caldav_sync_columns.sql — A4 wave 3: per-collection delta for the
-- CalDAV/CardDAV RFC 6578 sync-collection consumer.
--
-- The mailbox-wide jmap_changes_journal (V095) records created/updated/destroyed
-- per datatype at a per-(mailbox,datatype) counter. RFC 6578 sync tokens are
-- per-COLLECTION (one calendar / one addressbook), so the reader must filter the
-- journal to a single collection AND recover a destroyed resource's href token
-- (the live row is gone). Two nullable columns carry that:
--   · collection_id — CalendarEvent → calendar_id, ContactCard → addressbook_id.
--   · resource_uid  — CalendarEvent → the event uid, ContactCard → the vcard_uid
--     (contacts has no `uid` column; the CardDAV href is /{ab}/{vcard_uid}.vcf,
--     so vcard_uid IS the href token — that is what the sync consumer must emit
--     for a removed member). Both NULL for every other datatype (Task/AddressBook/
--     Calendar) and for the coarse resync sentinel.
--
-- Populated by the CalendarEvent + ContactCard journal triggers, redefined below
-- (CREATE OR REPLACE — overrides V097 / V096). The best-effort EXCEPTION wrapper
-- (F5 RLS note) + the calendars/addressbooks mailbox resolution + NULL-guard are
-- PRESERVED unchanged; only the append_change call gains the two trailing args.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.jmap_changes_journal
  ADD COLUMN IF NOT EXISTS collection_id BIGINT,
  ADD COLUMN IF NOT EXISTS resource_uid  TEXT;

-- ── CalendarEvent trigger (overrides V097) ────────────────────────────────────
-- collection_id = calendar_id, resource_uid = event uid. DELETE uses OLD.* (both
-- present on the deleted row). See the F5 RLS note in V097 — unchanged here.
CREATE OR REPLACE FUNCTION public.journal_calendar_event_change() RETURNS TRIGGER AS $$
DECLARE
  v_mailbox_id BIGINT;
BEGIN
  BEGIN
    IF TG_OP = 'DELETE' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM calendars WHERE id = OLD.calendar_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'CalendarEvent',
                              bump_entity_state(v_mailbox_id, 'CalendarEvent'), OLD.id, 'destroyed',
                              OLD.calendar_id, OLD.uid);
      END IF;
    ELSIF TG_OP = 'INSERT' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM calendars WHERE id = NEW.calendar_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'CalendarEvent',
                              bump_entity_state(v_mailbox_id, 'CalendarEvent'), NEW.id, 'created',
                              NEW.calendar_id, NEW.uid);
      END IF;
    ELSE
      SELECT mailbox_id INTO v_mailbox_id FROM calendars WHERE id = NEW.calendar_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'CalendarEvent',
                              bump_entity_state(v_mailbox_id, 'CalendarEvent'), NEW.id, 'updated',
                              NEW.calendar_id, NEW.uid);
      END IF;
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ── ContactCard trigger (overrides V096) ──────────────────────────────────────
-- collection_id = addressbook_id, resource_uid = vcard_uid (the CardDAV href
-- token). DELETE uses OLD.*; the addressbook-cascade hole (parent gone → mailbox
-- unresolvable) stays covered by the ContactCard resync sentinel in
-- jmap_addressbook_set_destroy (V096). Best-effort wrapper preserved.
CREATE OR REPLACE FUNCTION public.journal_contact_change() RETURNS TRIGGER AS $$
DECLARE
  v_mailbox_id BIGINT;
BEGIN
  BEGIN
    IF TG_OP = 'DELETE' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM addressbooks WHERE id = OLD.addressbook_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'ContactCard',
                              bump_entity_state(v_mailbox_id, 'ContactCard'), OLD.id, 'destroyed',
                              OLD.addressbook_id, OLD.vcard_uid);
      END IF;
    ELSIF TG_OP = 'INSERT' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM addressbooks WHERE id = NEW.addressbook_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'ContactCard',
                              bump_entity_state(v_mailbox_id, 'ContactCard'), NEW.id, 'created',
                              NEW.addressbook_id, NEW.vcard_uid);
      END IF;
    ELSE
      SELECT mailbox_id INTO v_mailbox_id FROM addressbooks WHERE id = NEW.addressbook_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'ContactCard',
                              bump_entity_state(v_mailbox_id, 'ContactCard'), NEW.id, 'updated',
                              NEW.addressbook_id, NEW.vcard_uid);
      END IF;
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (98, now())
    ON CONFLICT (version) DO NOTHING;
