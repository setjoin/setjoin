-- message_snooze.sql: B1 snooze set-path.
-- Snoozes a message until p_until. Two facts (§6 decoupling): it applies the
-- mailbox's Snoozed tag (exclusive 'snooze' group) AND enqueues a `snooze`
-- scheduled_action whose fire_at is p_until. The deferred-action dispatcher
-- (dispatch_scheduled_actions) + the snooze handler wake the message — no
-- tags.timer_type / process_message_timers machinery here.
--
-- Ownership is enforced through p_mailbox_id in every user-data statement
-- (R1/R3 of docs/standards/DATABASE_SECURITY.md). p_mailbox_id is the
-- sending/owning mailbox id (mailboxes.id), matching jmap_email_set_update.
CREATE OR REPLACE FUNCTION message_snooze(
    p_mailbox_id BIGINT,
    p_message_id BIGINT,
    p_until      TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
    v_received_at TIMESTAMPTZ;
    v_snooze_tag  BIGINT;
BEGIN
    -- Reject a snooze time that is not in the future.
    IF p_until IS NULL OR p_until <= now() THEN
        RAISE EXCEPTION 'Snooze time must be in the future'
            USING ERRCODE = 'BZ031',
                  HINT = jsonb_build_object('type', 'snooze_past', 'until', p_until)::TEXT;
    END IF;

    -- R1: resolve the message AND verify ownership in the same statement.
    SELECT received_at INTO v_received_at
    FROM messages
    WHERE id = p_message_id AND mailbox_id = p_mailbox_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Message not found'
            USING ERRCODE = 'BZ030',
                  HINT = jsonb_build_object('type', 'message_not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    -- Resolve the Snoozed system tag for this mailbox (scoped by p_mailbox_id).
    SELECT id INTO v_snooze_tag
    FROM tags
    WHERE mailbox_id = p_mailbox_id AND name = 'Snoozed' AND exclusive_group = 'snooze';

    IF v_snooze_tag IS NULL THEN
        RAISE EXCEPTION 'Snoozed tag missing for mailbox'
            USING ERRCODE = 'BZ030',
                  HINT = jsonb_build_object('type', 'snooze_tag_missing', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- First fact: apply the Snoozed tag. The message_tags BEFORE INSERT trigger
    -- removes any other 'snooze'-group tag (exclusivity); the counter trigger
    -- maintains tags.total_count/unread_count/jmap_state. We set is_primary FALSE so
    -- the existing location tag (Inbox) remains the IMAP primary. snooze_until is
    -- kept as an informational mirror; the authoritative wake-time is the
    -- scheduled_action's fire_at enqueued below.
    INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary, snooze_until)
    VALUES (p_message_id, v_received_at, v_snooze_tag, 'snooze', FALSE, p_until)
    ON CONFLICT (message_id, received_at, tag_id) DO UPDATE
        SET snooze_until = EXCLUDED.snooze_until,
            added_by     = EXCLUDED.added_by;

    -- Second fact: cancel any prior pending snooze action for this message, then
    -- enqueue the new deferred `snooze` action (re-snooze replaces the wake-time).
    PERFORM cancel_scheduled_action(p_mailbox_id, 'snooze',
        jsonb_build_object('message_id', p_message_id));
    PERFORM enqueue_scheduled_action('snooze', p_until,
        jsonb_build_object('message_id', p_message_id, 'received_at', v_received_at),
        p_mailbox_id);

    -- One call: bump email + tag state (the Snoozed tag membership changed) and
    -- push on the canonical tag:{mailbox_id} channel. The counter trigger has
    -- already bumped the per-tag jmap_state; notify_state_change leaves it alone.
    PERFORM notify_state_change(p_mailbox_id, v_snooze_tag);

    RETURN jsonb_build_object(
        'snoozed', TRUE,
        'messageId', p_message_id::TEXT,
        'snoozeUntil', p_until
    );
END;
$$ LANGUAGE plpgsql;
