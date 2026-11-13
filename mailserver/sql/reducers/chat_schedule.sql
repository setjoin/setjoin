-- chat_schedule.sql: scheduled-send trio, chat-owned (Pillar A3 QoL Task 2).
--
-- Producers: chat_schedule_message, chat_scheduled_list, chat_scheduled_cancel.
--
-- scheduled_actions has NO RLS (R4-by-parameter) and its mailbox_id column is
-- NULLable — chat rows carry mailbox_id=NULL (a channel has no mailbox owner)
-- so the generic cancel_scheduled_action (owner-scoped by p_mailbox_id) can
-- NEVER match a chat row. This trio is the chat-owned replacement: ownership
-- lives in payload->>'userId', set server-side from p_user_id (R2, never
-- trusted from the caller at list/cancel time) and re-checked in the SAME
-- statement as every list/cancel query (R1/R3).
--
-- BZ179 (scheduled-send invalid): a missing/past p_fire_at at enqueue time,
-- or a cancel attempt against a row that is not pending/failed/not-yours/
-- nonexistent (one code, all shapes, no oracle on which — same posture as
-- chat_message.sql's BZ167/BZ170 anti-oracle raisers).
CREATE OR REPLACE FUNCTION chat_schedule_message(
    p_user_id bigint, p_channel_id bigint, p_body text,
    p_parent_id bigint DEFAULT NULL, p_mentions bigint[] DEFAULT '{}',
    p_broadcast text DEFAULT NULL, p_fire_at timestamptz DEFAULT NULL
) RETURNS uuid AS $$
DECLARE
    v_payload jsonb;
    v_id      uuid;
BEGIN
    -- membership checked at ENQUEUE time (BZ163); the handler re-checks at
    -- FIRE time via chat_message_send itself (TOCTOU — a member kicked
    -- between now and fire_at must not silently post).
    PERFORM chat_require_role(p_channel_id, p_user_id);
    IF coalesce(btrim(p_body), '') = '' OR octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_fire_at IS NULL OR p_fire_at <= now() THEN
        RAISE EXCEPTION 'fireAt must be a future timestamp'
            USING ERRCODE='BZ179', HINT='{"type":"invalidArguments","detail":"fireAt must be in the future"}';
    END IF;
    -- payload built server-side from p_user_id/p_channel_id/etc — never from
    -- a raw request-body pass-through (R2). mentions defaults to '{}' so a
    -- NULL array never round-trips as JSON null.
    v_payload := jsonb_build_object(
      'userId', p_user_id, 'channelId', p_channel_id, 'body', p_body,
      'parentId', p_parent_id, 'mentions', to_jsonb(COALESCE(p_mentions, '{}'::bigint[])),
      'broadcast', p_broadcast
    );
    v_id := enqueue_scheduled_action('chat_send', p_fire_at, v_payload, NULL);
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- chat_scheduled_list: the caller's own pending + FAILED chat_send rows.
-- Failed rows stay visible (grill-decided, plan Task 2): silent content loss
-- is the wrong brand for a compliance product — the failure reason (the
-- handler's caught BZ, in payload->>'failureCode') and the still-readable
-- body let the user copy it out and re-send; Dismiss is chat_scheduled_cancel
-- on a failed row.
CREATE OR REPLACE FUNCTION chat_scheduled_list(p_user_id bigint) RETURNS jsonb AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'actionId', id, 'channelId', (payload->>'channelId')::bigint,
             'body', payload->>'body', 'fireAt', fire_at, 'status', status,
             'failureCode', payload->>'failureCode', 'lastError', last_error
           ) ORDER BY fire_at ASC), '[]'::jsonb)
      FROM scheduled_actions
     WHERE action_kind = 'chat_send'
       AND status IN ('pending', 'failed')
       AND payload->>'userId' = p_user_id::text;
$$ LANGUAGE sql STABLE;

-- chat_scheduled_cancel: works on pending AND failed (dismiss); ownership +
-- id + status all folded into ONE DELETE (R1/R3, no check-then-act window).
-- Anti-oracle (BZ179): doesn't exist, belongs to another user, or already
-- fired/processing all fail identically — a client can't probe which.
CREATE OR REPLACE FUNCTION chat_scheduled_cancel(
    p_user_id bigint, p_action_id uuid
) RETURNS void AS $$
DECLARE
    v_count int;
BEGIN
    WITH del AS (
        DELETE FROM scheduled_actions
         WHERE id = p_action_id
           AND action_kind = 'chat_send'
           AND status IN ('pending', 'failed')
           AND payload->>'userId' = p_user_id::text
        RETURNING 1
    )
    SELECT count(*) INTO v_count FROM del;
    IF v_count = 0 THEN
        RAISE EXCEPTION 'scheduled action not found or not cancellable'
            USING ERRCODE='BZ179', HINT='{"type":"invalidArguments","detail":"not pending/failed, not yours, or does not exist"}';
    END IF;
END;
$$ LANGUAGE plpgsql;
