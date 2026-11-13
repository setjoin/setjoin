-- append_change.sql: append one change-journal row in the SAME txn as the state
-- bump, for ANY datatype. The id-bearing seam passes a precise (datatype, entity_id,
-- op); the coarse/bulk seam passes a NULL entity_id which is stored as the
-- entity_id=0 'resync' SENTINEL — a sentinel between a client's sinceState and
-- newState forces jmap_entity_changes / jmap_email_changes to return
-- cannotCalculateChanges (BZ011) so the coarse path degrades to a full resync
-- rather than silently dropping a change.
--
-- p_collection_id / p_resource_uid (V098, A4 wave 3) carry the per-collection
-- delta the CalDAV/CardDAV RFC 6578 sync-collection consumer needs:
-- collection_id filters the journal to one calendar/addressbook, and resource_uid
-- recovers a DESTROYED resource's href token (uid / vcard_uid) after the live row
-- is gone. Both DEFAULT NULL — every existing 5-arg caller (email, Task,
-- AddressBook, Calendar, the coarse resync sentinels) resolves here via the
-- defaults, so only the two collection triggers (CalendarEvent/ContactCard) pass
-- them. DROP the old 5-arg signature first: a 5-arg call would otherwise be
-- ambiguous with this 7-param-all-defaulted function.
DROP FUNCTION IF EXISTS append_change(bigint, text, bigint, bigint, text);
CREATE OR REPLACE FUNCTION append_change(
  p_mailbox_id    BIGINT,
  p_datatype      TEXT,
  p_state_seq     BIGINT,
  p_entity_id     BIGINT,
  p_op            TEXT,
  p_collection_id BIGINT DEFAULT NULL,
  p_resource_uid  TEXT   DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_entity BIGINT;
  v_op     TEXT;
BEGIN
  IF p_entity_id IS NULL OR p_op = 'resync' THEN
    v_entity := 0;
    v_op     := 'resync';
  ELSE
    v_entity := p_entity_id;
    v_op     := p_op;
  END IF;

  -- R2: mailbox_id is the reducer's auth-derived p_mailbox_id, never req.*.
  -- ponytail: upsert op on same (mailbox_id, datatype, state_seq, entity_id) — a
  -- same-seq same-id dup (rare, same batch) keeps latest op; collapse is at READ time.
  INSERT INTO jmap_changes_journal (mailbox_id, datatype, state_seq, entity_id, op, collection_id, resource_uid)
  VALUES (p_mailbox_id, p_datatype, p_state_seq, v_entity, v_op, p_collection_id, p_resource_uid)
  ON CONFLICT (mailbox_id, datatype, state_seq, entity_id)
    DO UPDATE SET op = EXCLUDED.op,
                  collection_id = EXCLUDED.collection_id,
                  resource_uid  = EXCLUDED.resource_uid;
END;
$$ LANGUAGE plpgsql;

-- Compat shim: the existing email callers (notify_state_change, recall, retention)
-- keep working unchanged. email = datatype 'email', entity_id = message_id.
CREATE OR REPLACE FUNCTION append_email_change(
  p_mailbox_id  BIGINT,
  p_state_seq   BIGINT,
  p_message_id  BIGINT,
  p_op          TEXT
) RETURNS VOID AS $$
BEGIN
  PERFORM append_change(p_mailbox_id, 'email', p_state_seq, p_message_id, p_op);
END;
$$ LANGUAGE plpgsql;
