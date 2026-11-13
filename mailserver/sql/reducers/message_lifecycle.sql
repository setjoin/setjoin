-- message_lifecycle.sql: scheduled-send / undo-send lifecycle.
--
-- A6 (Scheduled Actions): the unified process_message_timers() cron handler is
-- GONE — firing is now the deferred-action dispatcher (dispatch_scheduled_actions)
-- + the `send` handler. message_schedule enqueues a `send` scheduled_action (the
-- "second fact") and still applies the Scheduled tag (the "first fact", §6
-- two-facts decoupling), WITHOUT touching the dropped tags.timer_type side-channel.
-- message_cancel cancels the pending action and restores Drafts.

-- message_schedule: schedule a message for later delivery or an undo-send window.
-- p_mailbox_id: the mailbox ID (ownership validated)
-- p_message_id: the message to schedule
-- p_send_at: when to send (future scheduled send)
-- p_undo_window_s: seconds to wait before sending (undo-send window)
-- p_extra_payload: optional JSONB merged into the scheduled_action payload
CREATE OR REPLACE FUNCTION message_schedule(
    p_mailbox_id    BIGINT,
    p_message_id    BIGINT,
    p_send_at       TIMESTAMPTZ DEFAULT NULL,
    p_undo_window_s INT DEFAULT NULL,
    p_extra_payload JSONB DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    v_msg            RECORD;
    v_scheduled_tag  BIGINT;
    v_drafts_tag     BIGINT;
    v_received_at    TIMESTAMPTZ;
    v_effective_send TIMESTAMPTZ;
    v_is_undo        BOOLEAN;
    v_action_id      UUID;
BEGIN
    -- Validate message exists and belongs to p_mailbox_id (R1).
    SELECT * INTO v_msg
    FROM messages
    WHERE id = p_message_id AND mailbox_id = p_mailbox_id;

    IF v_msg.id IS NULL THEN
        RAISE EXCEPTION 'Message not found'
            USING ERRCODE = 'BZ020', HINT = jsonb_build_object('type', 'message_not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    v_received_at := v_msg.received_at;

    SELECT id INTO v_scheduled_tag FROM tags WHERE mailbox_id = p_mailbox_id AND name = 'Scheduled';
    SELECT id INTO v_drafts_tag    FROM tags WHERE mailbox_id = p_mailbox_id AND name = 'Drafts';

    -- Determine effective send time and whether this is an undo-send window.
    IF p_undo_window_s IS NOT NULL AND p_undo_window_s > 0 THEN
        v_effective_send := now() + make_interval(secs => p_undo_window_s);
        v_is_undo := TRUE;
    ELSIF p_send_at IS NOT NULL AND p_send_at > now() THEN
        v_effective_send := p_send_at;
        v_is_undo := FALSE;
    ELSE
        -- Immediate send: no deferred action needed.
        v_effective_send := NULL;
        v_is_undo := FALSE;
    END IF;

    IF v_effective_send IS NOT NULL THEN
        -- First fact: move the draft to the Scheduled tag (snooze exclusive group).
        IF v_drafts_tag IS NOT NULL THEN
            DELETE FROM message_tags
            WHERE message_id = p_message_id
              AND received_at = v_received_at
              AND tag_id = v_drafts_tag;
        END IF;

        INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
        VALUES (p_message_id, v_received_at, v_scheduled_tag, 'schedule', TRUE)
        ON CONFLICT (message_id, received_at, tag_id) DO UPDATE
            SET added_by = EXCLUDED.added_by, is_primary = EXCLUDED.is_primary;

        -- Second fact: enqueue the deferred `send` action. dedup_key defaults to the
        -- action id (egress idempotency). payload carries the message reference + the
        -- undo flag so the submission view can derive undoSendBefore.
        -- p_extra_payload (if provided) is merged in so callers can thread additional
        -- flags through to the deferred handler without widening this function's
        -- positional signature further.
        v_action_id := enqueue_scheduled_action(
            'send', v_effective_send,
            jsonb_build_object('message_id', p_message_id, 'received_at', v_received_at, 'undo', v_is_undo)
              || COALESCE(p_extra_payload, '{}'::JSONB),
            p_mailbox_id);
    END IF;

    RETURN jsonb_build_object(
        'messageId', p_message_id::TEXT,
        'scheduled', v_effective_send IS NOT NULL,
        'sendAt', v_effective_send,
        'undo', v_is_undo,
        'actionId', v_action_id
    );
END;
$$ LANGUAGE plpgsql;

-- message_cancel: cancel a pending scheduled send / undo-send.
-- Cancels the deferred `send` action and restores the Drafts tag.
CREATE OR REPLACE FUNCTION message_cancel(
    p_mailbox_id BIGINT,
    p_message_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_msg           RECORD;
    v_scheduled_tag BIGINT;
    v_drafts_tag    BIGINT;
    v_received_at   TIMESTAMPTZ;
    v_cancelled     INT;
BEGIN
    SELECT * INTO v_msg
    FROM messages
    WHERE id = p_message_id AND mailbox_id = p_mailbox_id;

    IF v_msg.id IS NULL THEN
        RAISE EXCEPTION 'Message not found'
            USING ERRCODE = 'BZ020', HINT = jsonb_build_object('type', 'message_not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    v_received_at := v_msg.received_at;

    SELECT id INTO v_scheduled_tag FROM tags WHERE mailbox_id = p_mailbox_id AND name = 'Scheduled';
    SELECT id INTO v_drafts_tag    FROM tags WHERE mailbox_id = p_mailbox_id AND name = 'Drafts';

    -- Cancel the pending deferred send action (owner-scoped, R3).
    v_cancelled := cancel_scheduled_action(
        p_mailbox_id, 'send',
        jsonb_build_object('message_id', p_message_id));

    -- Remove the Scheduled tag.
    DELETE FROM message_tags
    WHERE message_id = p_message_id
      AND received_at = v_received_at
      AND tag_id = v_scheduled_tag;

    -- Restore the Drafts tag.
    IF v_drafts_tag IS NOT NULL THEN
        INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
        VALUES (p_message_id, v_received_at, v_drafts_tag, 'user', TRUE)
        ON CONFLICT (message_id, received_at, tag_id) DO NOTHING;
    END IF;

    -- The Scheduled→Drafts tag swap is a visibility change. The counter trigger
    -- only bumps the per-tag tags.jmap_state; it does NOT advance
    -- mailboxes.jmap_email_state or push. Route through the single owner so WS/IMAP
    -- consumers on 'tag:{mailbox_id}' see the move without a manual refresh (mirrors
    -- the message_schedule caller in jmap_email_submission.sql).
    PERFORM notify_state_change(p_mailbox_id, NULL, p_message_id, 'updated');

    RETURN jsonb_build_object(
        'cancelled', v_cancelled > 0,
        'messageId', p_message_id::TEXT
    );
END;
$$ LANGUAGE plpgsql;

-- undo_send: retract a sent message within the undo window.
-- Moves the message from Sent back to Drafts, cancels any pending `send` action,
-- and deletes any outbound queue entries not yet dispatched.
CREATE OR REPLACE FUNCTION undo_send(
    p_mailbox_id BIGINT,
    p_message_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_msg           RECORD;
    v_sent_tag      BIGINT;
    v_drafts_tag    BIGINT;
    v_received_at   TIMESTAMPTZ;
    v_deleted_queue INT;
    v_deleted_tag   INT;
BEGIN
    SELECT * INTO v_msg
    FROM messages
    WHERE id = p_message_id AND mailbox_id = p_mailbox_id;

    IF v_msg.id IS NULL THEN
        RAISE EXCEPTION 'Message not found'
            USING ERRCODE = 'BZ021', HINT = jsonb_build_object('type', 'message_not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    v_received_at := v_msg.received_at;

    SELECT id INTO v_sent_tag   FROM tags WHERE mailbox_id = p_mailbox_id AND name = 'Sent';
    SELECT id INTO v_drafts_tag FROM tags WHERE mailbox_id = p_mailbox_id AND name = 'Drafts';

    IF v_sent_tag IS NULL OR NOT EXISTS (
        SELECT 1 FROM message_tags
        WHERE message_id = p_message_id
          AND received_at = v_received_at
          AND tag_id = v_sent_tag
    ) THEN
        RAISE EXCEPTION 'Message has not been sent'
            USING ERRCODE = 'BZ022', HINT = jsonb_build_object('type', 'not_sent', 'message_id', p_message_id)::TEXT;
    END IF;

    -- Cancel any still-pending deferred send action for this message.
    PERFORM cancel_scheduled_action(p_mailbox_id, 'send',
        jsonb_build_object('message_id', p_message_id));

    -- Remove Sent tag.
    WITH deleted AS (
        DELETE FROM message_tags
        WHERE message_id = p_message_id
          AND received_at = v_received_at
          AND tag_id = v_sent_tag
        RETURNING 1
    )
    SELECT count(*) INTO v_deleted_tag FROM deleted;

    -- Restore Drafts tag.
    IF v_drafts_tag IS NOT NULL THEN
        INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
        VALUES (p_message_id, v_received_at, v_drafts_tag, 'user', TRUE)
        ON CONFLICT (message_id, received_at, tag_id) DO NOTHING;
    END IF;

    -- Delete any pending outbound queue entries that have not yet been dispatched.
    WITH deleted AS (
        DELETE FROM outbound_queue
        WHERE message_id = v_msg.message_id
          AND mailbox_id = p_mailbox_id  -- #476: never another tenant's row with the same Message-ID
          AND status = 'deferred'
          AND next_attempt_at > now()
        RETURNING 1
    )
    SELECT count(*) INTO v_deleted_queue FROM deleted;

    WITH deleted AS (
        DELETE FROM outbound_queue_hot
        WHERE message_id = v_msg.message_id
          AND mailbox_id = p_mailbox_id  -- #476
          AND status = 'pending'
        RETURNING 1
    )
    SELECT count(*) + v_deleted_queue INTO v_deleted_queue FROM deleted;

    -- The Sent→Drafts tag swap is a visibility change. The counter trigger only
    -- bumps the per-tag tags.jmap_state; it does NOT advance
    -- mailboxes.jmap_email_state or push. Route through the single owner so WS/IMAP
    -- consumers on 'tag:{mailbox_id}' see the retraction without a manual refresh.
    PERFORM notify_state_change(p_mailbox_id, NULL, p_message_id, 'updated');

    RETURN jsonb_build_object(
        'undone', v_deleted_tag > 0,
        'messageId', p_message_id::TEXT,
        'queueItemsCleared', v_deleted_queue
    );
END;
$$ LANGUAGE plpgsql;
