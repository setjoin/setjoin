-- scheduled_action_snooze.sql: the `snooze` handler. At wake (fire_at passed) it
-- clears the Snoozed tag and restores the message to Inbox via
-- transition_message_location (the state-bumping location front door). Pure DB
-- write, trivially idempotent: if the message is already un-snoozed it is a no-op.
-- Returns the handler status JSON the dispatcher reads: {"status":"ok"|...}.
--
-- payload = {message_id, received_at}; mailbox_id is the action's owner column.
CREATE OR REPLACE FUNCTION scheduled_action_snooze(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_message_id  BIGINT;
    v_received_at TIMESTAMPTZ;
    v_mailbox_id  BIGINT := p_action.mailbox_id;
    v_snooze_tag  BIGINT;
    v_deleted     INT := 0;
    v_has_loc     BOOLEAN;
BEGIN
    v_message_id  := (p_action.payload->>'message_id')::BIGINT;
    v_received_at := (p_action.payload->>'received_at')::TIMESTAMPTZ;

    -- Defensive: a payload without a message reference is a no-op success (e.g. a
    -- bare action used only to exercise the dispatcher).
    IF v_message_id IS NULL OR v_received_at IS NULL OR v_mailbox_id IS NULL THEN
        RETURN jsonb_build_object('status', 'ok', 'note', 'no message to wake');
    END IF;

    -- Resolve the mailbox's Snoozed tag (snooze exclusive group), scoped to owner.
    SELECT id INTO v_snooze_tag
    FROM tags
    WHERE mailbox_id = v_mailbox_id AND name = 'Snoozed' AND exclusive_group = 'snooze';

    -- Clear the Snoozed tag for this message (mailbox-scoped, R3).
    IF v_snooze_tag IS NOT NULL THEN
        WITH del AS (
            DELETE FROM message_tags mt
            USING tags t
            WHERE mt.message_id = v_message_id
              AND mt.received_at = v_received_at
              AND mt.tag_id = t.id
              AND t.mailbox_id = v_mailbox_id
              AND t.exclusive_group = 'snooze'
            RETURNING 1
        )
        SELECT count(*) INTO v_deleted FROM del;
    END IF;

    -- Restore Inbox only if the message no longer carries a location tag (idempotent:
    -- if it is already in some location, leave it). transition_message_location does
    -- the state-bumping swap + push through notify_state_change.
    SELECT EXISTS (
        SELECT 1 FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        WHERE mt.message_id = v_message_id
          AND mt.received_at = v_received_at
          AND t.mailbox_id = v_mailbox_id
          AND t.exclusive_group = 'location'
    ) INTO v_has_loc;

    IF NOT v_has_loc THEN
        PERFORM transition_message_location(v_message_id, v_received_at, 'Inbox', v_mailbox_id);
    ELSIF v_deleted > 0 THEN
        -- Snoozed tag removed but a location already present → still a visibility
        -- change; push once (no new location tag, so mailbox-wide bump).
        PERFORM notify_state_change(v_mailbox_id, NULL);
    END IF;

    RETURN jsonb_build_object('status', 'ok', 'note', 'woken');
END;
$$ LANGUAGE plpgsql;
