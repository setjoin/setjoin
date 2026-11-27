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
-- is gone.
--
-- p_imap_uid (V296, Wave 2.7 #554) retains the email's IMAP UID even after a
-- message row is soft- or hard-deleted so RFC 7162 QRESYNC VANISHED can report
-- exact vanished UIDs directly from jmap_changes_journal without a parallel
-- MODSEQ currency. All trailing params DEFAULT NULL so existing 5- and 7-arg
-- callers resolve unambiguously after dropping the narrower signatures.
DROP FUNCTION IF EXISTS append_change(bigint, text, bigint, bigint, text);
DROP FUNCTION IF EXISTS append_change(bigint, text, bigint, bigint, text, bigint, text);
CREATE OR REPLACE FUNCTION append_change(
  p_mailbox_id    BIGINT,
  p_datatype      TEXT,
  p_state_seq     BIGINT,
  p_entity_id     BIGINT,
  p_op            TEXT,
  p_collection_id BIGINT DEFAULT NULL,
  p_resource_uid  TEXT   DEFAULT NULL,
  p_imap_uid      BIGINT DEFAULT NULL
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
  INSERT INTO jmap_changes_journal (
    mailbox_id, datatype, state_seq, entity_id, op, collection_id, resource_uid, imap_uid
  )
  VALUES (
    p_mailbox_id, p_datatype, p_state_seq, v_entity, v_op, p_collection_id, p_resource_uid, p_imap_uid
  )
  ON CONFLICT (mailbox_id, datatype, state_seq, entity_id)
    DO UPDATE SET op            = EXCLUDED.op,
                  collection_id = COALESCE(EXCLUDED.collection_id, jmap_changes_journal.collection_id),
                  resource_uid  = COALESCE(EXCLUDED.resource_uid,  jmap_changes_journal.resource_uid),
                  imap_uid      = COALESCE(EXCLUDED.imap_uid,      jmap_changes_journal.imap_uid);
END;
$$ LANGUAGE plpgsql;

-- Email journal helper (V296, #554): stamps messages.imap_modseq from the same
-- monotonic mailboxes.jmap_email_state currency (R3: ownership in WHERE) and
-- captures (collection_id, imap_uid) for RFC 7162 CONDSTORE / QRESYNC VANISHED.
-- Existing 4-arg callers resolve via the trailing DEFAULT NULL parameters.
DROP FUNCTION IF EXISTS append_email_change(bigint, bigint, bigint, text);
CREATE OR REPLACE FUNCTION append_email_change(
  p_mailbox_id  BIGINT,
  p_state_seq   BIGINT,
  p_message_id  BIGINT,
  p_op          TEXT,
  p_tag_id      BIGINT DEFAULT NULL,
  p_imap_uid    BIGINT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_uid             BIGINT := p_imap_uid;
  v_tag_id          BIGINT := p_tag_id;
  v_msg_uid         BIGINT;
  v_msg_tag_id      BIGINT;
  v_msg_received_at TIMESTAMPTZ;
  v_modseq          BIGINT := GREATEST(COALESCE(p_state_seq, 0), 0) + 1;
BEGIN
  IF p_message_id IS NOT NULL AND p_op IS DISTINCT FROM 'resync' THEN
    IF p_op IN ('created', 'updated', 'destroyed') THEN
      UPDATE messages
         SET imap_modseq = v_modseq
       WHERE id = p_message_id
         AND mailbox_id = p_mailbox_id
      RETURNING imap_uid, folder_id, received_at
        INTO v_msg_uid, v_msg_tag_id, v_msg_received_at;

      IF v_msg_received_at IS NOT NULL THEN
        UPDATE message_tags
           SET imap_modseq = v_modseq
         WHERE message_id = p_message_id
           AND received_at = v_msg_received_at;
      END IF;
    END IF;
    v_uid    := COALESCE(v_uid, v_msg_uid);
    v_tag_id := COALESCE(v_tag_id, v_msg_tag_id);

    UPDATE tags
       SET imap_modseq = GREATEST(COALESCE(imap_modseq, 0), v_modseq)
     WHERE mailbox_id = p_mailbox_id
       AND (
         id = v_tag_id
         OR (
           v_msg_received_at IS NOT NULL
           AND id IN (
             SELECT tag_id
               FROM message_tags
              WHERE message_id = p_message_id
                AND received_at = v_msg_received_at
           )
         )
       );
  END IF;

  PERFORM append_change(
    p_mailbox_id, 'email', p_state_seq, p_message_id, p_op,
    v_tag_id, NULL, v_uid
  );
END;
$$ LANGUAGE plpgsql;
