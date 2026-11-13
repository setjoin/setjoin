-- ════════════════════════════════════════════════════════════════════════
-- V096__contact_changes_journal.sql — A4 wave 1: real ContactCard + AddressBook
-- /changes deltas. Mirrors V095's Task proof-slice (trg_journal_task) for the two
-- contacts datatypes, keying each to its own per-(mailbox,datatype) monotonic
-- jmap_entity_state counter ('ContactCard' vs 'AddressBook'). Before A4 both read
-- MAX(addressbooks.jmap_state) — a shared, non-monotonic token that notify_contact_state
-- bumped on EVERY contact change, so the two datatypes polluted each other and a
-- non-max-row update was silently dropped from /changes. Separate journal counters
-- decouple them and give real created/updated/destroyed lists.
--
-- MAILBOX-ID RESOLUTION (the structural difference from Task):
--   · addressbooks HAS a direct mailbox_id → trg_journal_addressbook uses NEW/OLD.mailbox_id.
--   · contacts has ONLY addressbook_id (no direct mailbox_id) → trg_journal_contact
--     resolves mailbox_id via addressbooks. During an addressbook DELETE the FK
--     cascade removes the parent row FIRST, so a cascaded contact-delete can no
--     longer resolve its mailbox — the resolve returns NULL and the trigger skips
--     (nothing to journal, no crash). That hole is covered precisely by a ContactCard
--     resync sentinel emitted in jmap_addressbook_set_destroy (gauntlet F1): a client
--     syncing across an address-book deletion gets BZ011 (full resync) instead of
--     ghost contacts, rather than depending on a per-row trigger that can't fire with
--     a resolvable mailbox under cascade.
-- ════════════════════════════════════════════════════════════════════════

-- ── AddressBook journaling trigger ───────────────────────────────────────────
-- addressbooks has mailbox_id directly (like tasks) → journal at NEW/OLD.mailbox_id.
CREATE OR REPLACE FUNCTION public.journal_addressbook_change() RETURNS TRIGGER AS $$
BEGIN
  -- Best-effort journal (skip on RLS reject, don't break the mutation) — see the
  -- note in journal_calendar_event_change (V097). Address books are same-mailbox
  -- today; the guard covers a future/import writer with no matching mailbox GUC.
  BEGIN
    IF TG_OP = 'DELETE' THEN
      PERFORM append_change(OLD.mailbox_id, 'AddressBook',
                            bump_entity_state(OLD.mailbox_id, 'AddressBook'), OLD.id, 'destroyed');
    ELSIF TG_OP = 'INSERT' THEN
      PERFORM append_change(NEW.mailbox_id, 'AddressBook',
                            bump_entity_state(NEW.mailbox_id, 'AddressBook'), NEW.id, 'created');
    ELSE
      PERFORM append_change(NEW.mailbox_id, 'AddressBook',
                            bump_entity_state(NEW.mailbox_id, 'AddressBook'), NEW.id, 'updated');
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_journal_addressbook ON public.addressbooks;
CREATE TRIGGER trg_journal_addressbook
  AFTER INSERT OR UPDATE OR DELETE ON public.addressbooks
  FOR EACH ROW EXECUTE FUNCTION public.journal_addressbook_change();

-- ── ContactCard journaling trigger ───────────────────────────────────────────
-- contacts has NO direct mailbox_id → resolve via addressbooks. Under an addressbook
-- DELETE the parent is already gone (FK cascade), so the resolve yields NULL and we
-- skip: the jmap_addressbook_set_destroy ContactCard resync sentinel covers that path.
-- For every non-cascade op (insert/update, and a direct contact delete while its
-- addressbook still exists) the resolve succeeds → precise created/updated/destroyed.
CREATE OR REPLACE FUNCTION public.journal_contact_change() RETURNS TRIGGER AS $$
DECLARE
  v_mailbox_id BIGINT;
BEGIN
  -- Best-effort journal (skip on RLS reject, don't break the mutation) — see the
  -- note in journal_calendar_event_change (V097).
  BEGIN
    IF TG_OP = 'DELETE' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM addressbooks WHERE id = OLD.addressbook_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'ContactCard',
                              bump_entity_state(v_mailbox_id, 'ContactCard'), OLD.id, 'destroyed');
      END IF;
    ELSIF TG_OP = 'INSERT' THEN
      SELECT mailbox_id INTO v_mailbox_id FROM addressbooks WHERE id = NEW.addressbook_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'ContactCard',
                              bump_entity_state(v_mailbox_id, 'ContactCard'), NEW.id, 'created');
      END IF;
    ELSE
      SELECT mailbox_id INTO v_mailbox_id FROM addressbooks WHERE id = NEW.addressbook_id;
      IF v_mailbox_id IS NOT NULL THEN
        PERFORM append_change(v_mailbox_id, 'ContactCard',
                              bump_entity_state(v_mailbox_id, 'ContactCard'), NEW.id, 'updated');
      END IF;
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_journal_contact ON public.contacts;
CREATE TRIGGER trg_journal_contact
  AFTER INSERT OR UPDATE OR DELETE ON public.contacts
  FOR EACH ROW EXECUTE FUNCTION public.journal_contact_change();

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (96, now())
    ON CONFLICT (version) DO NOTHING;
