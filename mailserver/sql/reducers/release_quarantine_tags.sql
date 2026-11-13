-- release_quarantine_tags: the atomic inverse of quarantine_message's tag swap —
-- remove the Quarantined (quarantine-group) tag and restore the message's original
-- location tag, then push the change. The caller (user self-service or admin) has
-- already marked quarantined_messages.released_at under its own ownership gate and
-- passes the message's mailbox + the recorded original_tag.
--
-- Replaces the former open-coded Go tag rewrite (arch A8), fixing three defects:
--   1. The ADMIN path INSERTed message_tags with received_at = now(), which always
--      violates the composite FK (message_id, received_at) → messages, so the
--      original tag was NEVER restored (the error was swallowed by h.pool.Exec) —
--      the released message was left with NO location tag (invisible in every
--      folder). Here received_at is sourced from messages, so the FK holds.
--   2. The two statements ran as separate autocommits (admin), so a partial failure
--      left a half-released message; here they are one txn.
--   3. NEITHER path emitted pg_notify, so a connected webmail/IMAP client did not
--      see the message return to its folder until a manual refresh; p_notify pushes
--      it through the single owner (the same omission quarantine_message fixed in
--      the forward direction).
--
-- R3 (ownership-scoped): every statement filters by p_mailbox_id; a foreign
-- mailbox resolves neither the message nor its Quarantined tag → BZ074, nothing
-- mutated.
CREATE OR REPLACE FUNCTION release_quarantine_tags(
    p_message_id   BIGINT,
    p_mailbox_id   BIGINT,
    p_original_tag TEXT,
    p_notify       BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_received_at TIMESTAMPTZ;
    v_quar_tag_id BIGINT;
BEGIN
    v_quar_tag_id := get_tag_id('Quarantined', p_mailbox_id);

    -- Source the message's real received_at (the composite-FK partition key), scoped
    -- to the owning mailbox (R3). A foreign/absent message yields no row → BZ074.
    SELECT received_at INTO v_received_at
      FROM messages
     WHERE id = p_message_id AND mailbox_id = p_mailbox_id;
    IF v_received_at IS NULL THEN
        RAISE EXCEPTION 'message % not found in mailbox %', p_message_id, p_mailbox_id
          USING ERRCODE = 'BZ074',
                HINT = jsonb_build_object('type', 'quarantine_message_not_found',
                                          'message_id', p_message_id,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Remove the Quarantined (quarantine-group) tag for this mailbox. Counter
    -- triggers maintain tags.total_count / unread_count on the DELETE.
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id  = p_message_id
      AND mt.received_at = v_received_at
      AND mt.tag_id      = t.id
      AND t.mailbox_id   = p_mailbox_id
      AND t.name         = 'Quarantined';

    -- Restore the recorded original location tag with the FK-correct received_at.
    -- tag_message resolves the tag IN p_mailbox_id again (R3) and the exclusive
    -- trigger keeps the location group singular.
    PERFORM tag_message(p_message_id, v_received_at, p_original_tag, p_mailbox_id, 'system', TRUE);

    -- Tag membership changed → push through the single owner so the client sees the
    -- message return to its folder immediately. Suppressible via p_notify = FALSE.
    IF p_notify AND v_quar_tag_id IS NOT NULL THEN
        PERFORM notify_state_change(p_mailbox_id, v_quar_tag_id);
    END IF;
END;
$$ LANGUAGE plpgsql;
