-- scheduled_action_enqueue.sql: the single writer callers use to schedule or
-- cancel a deferred action. Every statement is owner-scoped by p_mailbox_id
-- (R1/R2/R3 — this repo enforces R4 by parameter propagation, not native RLS).
--
-- enqueue_scheduled_action returns the new action id. For the `send` kind (and
-- Chat A3 QoL's `chat_send`) the caller passes no dedup_key and the function
-- defaults it to id::TEXT (one UPDATE in the same txn), so a post-crash reclaim
-- of the same action conflicts on the partial-UNIQUE dedup index and cannot
-- double-transmit. Pure-DB kinds (snooze / remind) leave dedup_key NULL.
CREATE OR REPLACE FUNCTION enqueue_scheduled_action(
    p_kind       TEXT,
    p_fire_at    TIMESTAMPTZ,
    p_payload    JSONB,
    p_mailbox_id BIGINT,
    p_dedup_key  TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_id UUID;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('send','snooze','remind','dsn','chat_send') THEN
        RAISE EXCEPTION 'Unknown action_kind %', p_kind
            USING ERRCODE = 'BZ036',
                  HINT = jsonb_build_object('type','bad_action_kind','kind',p_kind)::TEXT;
    END IF;

    IF p_fire_at IS NULL THEN
        RAISE EXCEPTION 'fire_at is required'
            USING ERRCODE = 'BZ037',
                  HINT = jsonb_build_object('type','fire_at_required')::TEXT;
    END IF;

    INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id, dedup_key)
    VALUES (p_kind, p_fire_at, COALESCE(p_payload, '{}'::JSONB), p_mailbox_id, p_dedup_key)
    RETURNING id INTO v_id;

    -- Default the send-style kinds' dedup_key to the action id (egress
    -- idempotency / reclaim correlation). chat_send joins send here — see
    -- the header note above.
    IF p_kind IN ('send', 'chat_send') AND p_dedup_key IS NULL THEN
        UPDATE scheduled_actions SET dedup_key = v_id::TEXT WHERE id = v_id;
    END IF;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- cancel_scheduled_action: delete the matching pending action for this owner.
-- Matches on action_kind + a payload subset (e.g. {message_id}); ownership via
-- p_mailbox_id in the same DELETE (R3). Only pending rows are cancellable (a
-- processing/done/failed action has already fired or is mid-flight). Returns the
-- number of cancelled rows.
CREATE OR REPLACE FUNCTION cancel_scheduled_action(
    p_mailbox_id    BIGINT,
    p_kind          TEXT,
    p_payload_match JSONB DEFAULT '{}'::JSONB
) RETURNS INT AS $$
DECLARE
    v_count INT;
BEGIN
    WITH del AS (
        DELETE FROM scheduled_actions
        WHERE mailbox_id = p_mailbox_id
          AND action_kind = p_kind
          AND status = 'pending'
          AND payload @> COALESCE(p_payload_match, '{}'::JSONB)
        RETURNING 1
    )
    SELECT count(*) INTO v_count FROM del;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
