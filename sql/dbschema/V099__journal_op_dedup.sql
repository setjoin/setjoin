-- ════════════════════════════════════════════════════════════════════════
-- V099__journal_op_dedup.sql — architecture deepening (improve-codebase-architecture
-- review of the A4 change-journal). The 5 per-datatype journal trigger functions
-- (V095-V098) each re-implemented the same inner block: TG_OP→op mapping,
-- bump_entity_state+append_change, the parent-join NULL-guard, and the best-effort
-- `EXCEPTION WHEN insufficient_privilege` catch (the F5 RLS-flip fix). That logic now
-- lives ONCE in journal_op / journal_resync (reducers/journal_op.sql); this migration
-- CREATE OR REPLACEs the 5 trigger FUNCTIONS to delegate to it (the triggers stay bound).
-- Each body now carries only its genuinely-unique part: NEW/OLD selection + mailbox
-- resolution (direct column vs parent-table join) + the collection_id/resource_uid it
-- passes. No behaviour change — verified by the full pgTAP suite + the journal_op.pg
-- in-suite setjoin_app RLS proof + byte-identical schema determinism.
-- ════════════════════════════════════════════════════════════════════════

-- Task — direct mailbox_id, no CalDAV collection.
CREATE OR REPLACE FUNCTION public.journal_task_change() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM journal_op(OLD.mailbox_id, 'Task', OLD.id, 'DELETE');
  ELSE
    PERFORM journal_op(NEW.mailbox_id, 'Task', NEW.id, TG_OP);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- AddressBook — direct mailbox_id.
CREATE OR REPLACE FUNCTION public.journal_addressbook_change() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM journal_op(OLD.mailbox_id, 'AddressBook', OLD.id, 'DELETE');
  ELSE
    PERFORM journal_op(NEW.mailbox_id, 'AddressBook', NEW.id, TG_OP);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ContactCard — mailbox via addressbooks (NULL-guarded in journal_op under cascade);
-- collection = addressbook_id, resource_uid = vcard_uid (the CardDAV href token).
CREATE OR REPLACE FUNCTION public.journal_contact_change() RETURNS TRIGGER AS $$
DECLARE v_mb BIGINT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT mailbox_id INTO v_mb FROM addressbooks WHERE id = OLD.addressbook_id;
    PERFORM journal_op(v_mb, 'ContactCard', OLD.id, 'DELETE', OLD.addressbook_id, OLD.vcard_uid);
  ELSE
    SELECT mailbox_id INTO v_mb FROM addressbooks WHERE id = NEW.addressbook_id;
    PERFORM journal_op(v_mb, 'ContactCard', NEW.id, TG_OP, NEW.addressbook_id, NEW.vcard_uid);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Calendar — direct mailbox_id. On DELETE also emit a CalendarEvent resync sentinel:
-- cascaded event deletes can't be named, so a client syncing CalendarEvent across the
-- deletion must resync (BZ011) rather than keep ghost events.
CREATE OR REPLACE FUNCTION public.journal_calendar_change() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM journal_op(OLD.mailbox_id, 'Calendar', OLD.id, 'DELETE');
    PERFORM journal_resync(OLD.mailbox_id, 'CalendarEvent');
  ELSE
    PERFORM journal_op(NEW.mailbox_id, 'Calendar', NEW.id, TG_OP);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- CalendarEvent — mailbox via calendars (NULL-guarded under cascade);
-- collection = calendar_id, resource_uid = uid (the CalDAV href token).
CREATE OR REPLACE FUNCTION public.journal_calendar_event_change() RETURNS TRIGGER AS $$
DECLARE v_mb BIGINT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT mailbox_id INTO v_mb FROM calendars WHERE id = OLD.calendar_id;
    PERFORM journal_op(v_mb, 'CalendarEvent', OLD.id, 'DELETE', OLD.calendar_id, OLD.uid);
  ELSE
    SELECT mailbox_id INTO v_mb FROM calendars WHERE id = NEW.calendar_id;
    PERFORM journal_op(v_mb, 'CalendarEvent', NEW.id, TG_OP, NEW.calendar_id, NEW.uid);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (99, now())
    ON CONFLICT (version) DO NOTHING;
