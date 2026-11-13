-- scheduled_action_send.sql: the `send` handler — exactly-once SMTP egress for a
-- scheduled-send / undo-send action. Moves the draft to Sent and enqueues it on
-- outbound_queue_hot keyed by the action's dedup_key (= the action id). A
-- post-crash reclaim re-runs this handler; the dedup_key UNIQUE on
-- outbound_queue_hot is the hard backstop against a double-transmit, and the
-- explicit "already enqueued?" guard avoids even attempting it.
--
-- payload = {message_id, received_at, undo?}; mailbox_id is the owner column.
-- Returns the dispatcher status JSON: ok | retry | permanent_fail (+ note).
CREATE OR REPLACE FUNCTION scheduled_action_send(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_message_id  BIGINT;
    v_received_at TIMESTAMPTZ;
    v_mailbox_id  BIGINT  := p_action.mailbox_id;
    v_dedup       TEXT    := p_action.dedup_key;
    v_msg         RECORD;
    v_recipient   JSONB;
    v_ordinal     BIGINT;
    v_webhook_rcpts JSONB;
    v_webhook_from TEXT;
BEGIN
    v_message_id  := (p_action.payload->>'message_id')::BIGINT;
    v_received_at := (p_action.payload->>'received_at')::TIMESTAMPTZ;

    IF v_message_id IS NULL OR v_received_at IS NULL OR v_mailbox_id IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail', 'note', 'send action missing message reference');
    END IF;

    -- Idempotency guard: if this action's egress is already enqueued (same
    -- dedup_key), this is a reclaim after a crash — do nothing, report ok.
    IF v_dedup IS NOT NULL AND EXISTS (
        SELECT 1 FROM outbound_queue_hot WHERE dedup_key = v_dedup
    ) THEN
        RETURN jsonb_build_object('status', 'ok', 'note', 'already enqueued (dedup)');
    END IF;

    -- Load the draft AND verify ownership in the same statement (R1).
    SELECT * INTO v_msg
    FROM messages
    WHERE id = v_message_id AND received_at = v_received_at AND mailbox_id = v_mailbox_id;

    IF v_msg.id IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail', 'note', 'scheduled message not found');
    END IF;

    -- Move Scheduled → Sent (the exclusive 'snooze'/'location' triggers maintain
    -- exclusivity + counters). state bump + push routed through the single owner.
    PERFORM tag_message(v_message_id, v_received_at, 'Sent', v_mailbox_id, 'schedule', TRUE);

    -- Enqueue for outbound delivery, keyed by dedup_key. The recipients come from
    -- the message's to_addrs envelope. The draft's raw_ref already carries any
    -- signed wire artifact (S/MIME signing happens at submission, Phase D).
    INSERT INTO outbound_queue_hot (message_id, from_addr, rcpt_addrs, raw_ref, status, next_attempt_at, mailbox_id, dedup_key)
    SELECT v_msg.message_id, v_msg.from_addr,
           COALESCE(array_agg(r->>'email'), ARRAY[]::TEXT[]),
           v_msg.raw_ref, 'pending', now(), v_mailbox_id, v_dedup
    FROM jsonb_array_elements(v_msg.to_addrs) AS r;

    PERFORM notify_state_change(v_mailbox_id, get_tag_id('Sent', v_mailbox_id), v_message_id, 'created');
    PERFORM mail_work_record_first_response(v_mailbox_id,
      NULLIF(p_action.payload->>'actor_user_id','')::bigint,v_msg.thread_id,v_message_id);

    v_webhook_rcpts := COALESCE(p_action.payload->'webhook_envelope_rcpts',v_msg.to_addrs);
    v_webhook_from := COALESCE(p_action.payload->>'webhook_envelope_from',v_msg.from_addr);
    FOR v_recipient,v_ordinal IN
      SELECT value,ordinality FROM jsonb_array_elements(v_webhook_rcpts) WITH ORDINALITY
    LOOP
      PERFORM webhook_mail_committed_publish(
        v_message_id,'mail.sent','scheduled_send',v_webhook_from,
        CASE WHEN jsonb_typeof(v_recipient)='string' THEN v_recipient #>> '{}'
             ELSE v_recipient->>'email' END,
        v_ordinal::integer);
    END LOOP;

    RETURN jsonb_build_object('status', 'ok', 'note', 'sent');
EXCEPTION
    WHEN unique_violation THEN
        -- The dedup_key UNIQUE fired (a concurrent reclaim won the race): the
        -- egress is already present, so this run is a successful no-op.
        RETURN jsonb_build_object('status', 'ok', 'note', 'dedup race; already enqueued');
END;
$$ LANGUAGE plpgsql;
