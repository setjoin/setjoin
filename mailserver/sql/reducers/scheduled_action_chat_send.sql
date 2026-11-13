-- scheduled_action_chat_send.sql: the `chat_send` dispatcher handler
-- (Pillar A3 QoL Task 2). Fires chat_schedule_message's enqueued payload
-- through chat_message_send at FIRE time — this IS the TOCTOU re-check
-- (membership/archive/permission may have changed since enqueue).
--
-- BZ->outcome map: a membership/archive/permission failure (BZ163 kicked
-- from the channel, BZ164 announcement-channel post by a non-admin, BZ166
-- broadcast restricted, BZ168 body now over cap, BZ171 channel archived) is
-- caught HERE and turned into a terminal permanent_fail — NOT a retry loop,
-- since none of these self-heal by waiting. The caught BZ is recorded onto
-- the action's OWN payload (payload->>'failureCode') so chat_scheduled_list
-- can render a specific reason (mapped to i18n client-side) instead of a
-- raw SQLERRM. Any OTHER error (a transient DB issue, an unexpected raise)
-- propagates uncaught — the dispatcher's own outer handler treats that as
-- 'retry' (scheduled_actions_dispatch.sql), unchanged.
CREATE OR REPLACE FUNCTION scheduled_action_chat_send(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_user_id    bigint := (p_action.payload->>'userId')::bigint;
    v_channel_id bigint := (p_action.payload->>'channelId')::bigint;
    v_body       text   := p_action.payload->>'body';
    v_parent_id  bigint := NULLIF(p_action.payload->>'parentId', '')::bigint;
    v_broadcast  text   := p_action.payload->>'broadcast';
    v_mentions   bigint[];
    v_result     jsonb;
BEGIN
    SELECT COALESCE(array_agg(x::bigint), '{}'::bigint[]) INTO v_mentions
      FROM jsonb_array_elements_text(COALESCE(p_action.payload->'mentions', '[]'::jsonb)) x;

    v_result := chat_message_send(v_user_id, v_channel_id, v_body, v_parent_id, v_mentions, v_broadcast);
    RETURN jsonb_build_object('status', 'ok', 'note', v_result->>'messageId');
EXCEPTION
    WHEN SQLSTATE 'BZ163' OR SQLSTATE 'BZ164' OR SQLSTATE 'BZ166'
      OR SQLSTATE 'BZ168' OR SQLSTATE 'BZ171' THEN
        UPDATE scheduled_actions
           SET payload = payload || jsonb_build_object('failureCode', SQLSTATE)
         WHERE id = p_action.id;
        RETURN jsonb_build_object('status', 'permanent_fail', 'note', SQLSTATE);
END;
$$ LANGUAGE plpgsql;
