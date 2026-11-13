-- transition_message_location: the single, atomic owner of the `location`
-- exclusive-group swap + the owner notify. It is the deliberate front door for
-- "move this message to location X (and notify the owner)". The actual tag swap
-- (remove the old location tag(s), add the new one as primary) is delegated to
-- set_message_location — the INTERNAL primitive — so there is one place the swap
-- mechanics live; this reducer adds the invariant guard and the single
-- notify_state_change. Counters are maintained by the AFTER INSERT/DELETE
-- triggers on message_tags (trg_message_tags_counters) — neither this reducer nor
-- set_message_location touches tags.total_count / unread_count directly.
--
-- The BEFORE INSERT exclusive trigger (trg_message_tags_exclusive) is the
-- defensive backstop; this reducer is the deliberate, state-bumping front door.
-- Every location-group change goes through this seam: Track A2 (Archive),
-- jmap_email destroy/recover, rule_engine move/delete, send() DLP quarantine,
-- and recall — so the swap + notify decision can't drift across call sites.
--
-- p_added_by (DEFAULT 'user'): the message_tags.added_by provenance recorded for
-- the new location tag ('user','rule','dlp','recall',…). Threaded so callers keep
-- their exact provenance value while still routing through the one seam.
--
-- p_notify (DEFAULT TRUE): when TRUE the seam pushes the location change through
-- the single owner notify_state_change(p_mailbox_id, <new tag id>) — bumps email +
-- tag state, pushes on 'tag:{mailbox_id}'. Callers that ALREADY emit their own
-- single push for the whole operation (a batch loop with one end-of-call notify,
-- or send()'s single Sent-tag notify, or recall's bespoke 'recalled' event) pass
-- FALSE so the state bump count is unchanged — exactly the no-double-bump pattern
-- delete_draft_message uses.
CREATE OR REPLACE FUNCTION transition_message_location(
    p_message_id            BIGINT,
    p_received_at           TIMESTAMPTZ,
    p_new_location_tag_name TEXT,
    p_mailbox_id            BIGINT,
    p_added_by              TEXT    DEFAULT 'user',
    p_notify                BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
    v_loc_count INT;
    v_new_tag_id BIGINT;
BEGIN
    -- Guard against corrupt multi-location state: a message must carry 0 or 1
    -- location tags. >1 means the invariant was already broken upstream.
    SELECT count(*) INTO v_loc_count
    FROM message_tags mt
    JOIN tags t ON t.id = mt.tag_id
    WHERE mt.message_id = p_message_id
      AND mt.received_at = p_received_at
      AND t.mailbox_id = p_mailbox_id
      AND t.exclusive_group = 'location';

    IF v_loc_count > 1 THEN
        RAISE EXCEPTION 'message % carries % location tags (expected <=1)', p_message_id, v_loc_count
          USING ERRCODE = 'BZ035',
                HINT = jsonb_build_object('type', 'location_invariant_violation',
                                          'message_id', p_message_id,
                                          'count', v_loc_count)::TEXT;
    END IF;

    -- The atomic swap itself (remove old location tag(s), add the new one as
    -- primary) is the internal primitive. set_message_location resolves the tag
    -- in the mailbox and RAISEs BZ019 if it does not exist (also covers a foreign
    -- p_mailbox_id, which cannot resolve the tag — no cross-tenant write).
    PERFORM set_message_location(p_message_id, p_received_at, p_new_location_tag_name, p_mailbox_id, p_added_by);

    -- The location tag membership changed → bump email + tag state and push
    -- through the single owner exactly once for the whole swap, UNLESS the caller
    -- already emits the single push for this operation (p_notify = FALSE).
    IF p_notify THEN
        v_new_tag_id := get_tag_id(p_new_location_tag_name, p_mailbox_id);
        PERFORM notify_state_change(p_mailbox_id, v_new_tag_id, p_message_id, 'updated');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- delete_draft_message: the single owner of the "remove this draft's location
-- tags, then delete the message row" pattern (formerly inlined in
-- jmap_email_submission's legacy send path and rule_engine's `discard` action).
-- Ownership-scoped (R3): every statement filters by p_mailbox_id, so a foreign
-- mailbox_id deletes nothing.
--
-- p_notify (DEFAULT TRUE): when TRUE this is the sole visibility change for the
-- operation, so it pushes one mailbox-wide state change through the single owner
-- (notify_state_change(p_mailbox_id, NULL)) — this matches the rule_engine
-- `discard` action's existing single bump. The jmap_email_submission legacy send
-- path passes FALSE because send() already pushed the state change for that same
-- logical send (preserving the no-double-bump invariant).
CREATE OR REPLACE FUNCTION delete_draft_message(
    p_message_id  BIGINT,
    p_received_at TIMESTAMPTZ,
    p_mailbox_id  BIGINT,
    p_notify      BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
BEGIN
    -- Remove location-group tags first (counter triggers fire on DELETE),
    -- scoped to the owning mailbox.
    DELETE FROM message_tags mt
    USING tags t
    WHERE mt.message_id = p_message_id
      AND mt.received_at = p_received_at
      AND mt.tag_id = t.id
      AND t.mailbox_id = p_mailbox_id
      AND t.exclusive_group = 'location';

    -- Delete the message row; ownership in the same WHERE (R3, no TOCTOU).
    -- The message_tags FK (ON DELETE CASCADE) clears any remaining tags.
    DELETE FROM messages
    WHERE id = p_message_id
      AND received_at = p_received_at
      AND mailbox_id = p_mailbox_id;

    -- Mailbox-wide change (message removed) → push through the single owner.
    -- Suppressed (p_notify = FALSE) when the caller already pushed the change.
    IF p_notify THEN
        PERFORM notify_state_change(p_mailbox_id, NULL);
    END IF;
END;
$$ LANGUAGE plpgsql;
