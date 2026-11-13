-- notify_contact_state.sql: the single owner of "a contact / contact-group / address
-- book changed → bump the owning mailbox's addressbooks.jmap_state → push on
-- contact:{mailbox_id}". The contact secondary seam (mirrors bump_reminder_state /
-- notify_state_change): static SQL, one bump + one channel + one payload. Folds in
-- the former bump_contact_group_state (groups share the contacts jmap_state domain
-- so clients resync contacts + groups off one token).
--
-- Contract:
--   * Bumps addressbooks.jmap_state for EVERY address book of p_mailbox_id (the
--     contacts/groups domain token). The Contact/AddressBook/ContactGroup readers
--     all take MAX(jmap_state) over the mailbox, so advancing every book advances
--     that MAX by exactly one — the same observable token, mailbox-scoped (R1).
--     A mailbox always has at least one address book; the guard tolerates the
--     (test) case where it has none (no row updated → NULL state).
--   * Pushes on the canonical 'contact:{mailbox_id}' channel with {event,contact_id}.
--     p_contact_id is NULL for group-domain events (contact_group_changed) — the
--     key is then JSON null, preserving the former bump_contact_group_state payload.
--   * Returns the new MAX(addressbooks.jmap_state) for the mailbox (or NULL if the
--     mailbox has no address book).
--
-- NOTE: the per-GROUP token (contact_groups.jmap_state, read by ContactGroup/get)
-- is a DIFFERENT, group-scoped token and is bumped by the group reducer itself —
-- this seam owns only the addressbook-DOMAIN bump+push, never the group token.
--
-- p_mailbox_id — the owning mailbox id (required; BZ034 if NULL).
-- p_event      — the event name ('contact_created' | 'contact_updated' |
--   'contact_destroyed' | 'contact_group_changed' | …), preserved verbatim.
-- p_contact_id — the changed contact id, or NULL for a group/domain-wide change.
CREATE OR REPLACE FUNCTION notify_contact_state(
  p_mailbox_id BIGINT,
  p_event      TEXT,
  p_contact_id BIGINT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_contact_state requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  UPDATE addressbooks SET jmap_state = jmap_state + 1
  WHERE mailbox_id = p_mailbox_id;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_state
  FROM addressbooks WHERE mailbox_id = p_mailbox_id;

  PERFORM app_notify(
    'contact:' || p_mailbox_id,
    jsonb_build_object(
      'event',      p_event,
      'contact_id', p_contact_id
    )::TEXT
  );

  RETURN v_state;
END;
$$ LANGUAGE plpgsql;
