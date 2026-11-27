-- notify_chat_state.sql: the O(1) chat push seam (Wave 2.5 #552).
--
-- Eliminates the legacy O(members) chat:{user_id} fan-out loop from write
-- transactions:
--   * Ephemeral 'typing' events (p_seq IS NULL) emit ONE O(1) notification on
--     'chat_ephemeral' (never 'sync') for in-memory hub fan-out to currently
--     attached channel subscribers.
--   * Strictly monotonic message-advancing events ('message_created',
--     'message_sent', 'message_edited', 'message_deleted', 'message_delivered')
--     emit ONE content-free bell via emit_wakeup_bell('sync',
--     'channel:' || p_channel_id || ':' || COALESCE(p_seq, 0)).
--   * Non-seq-advancing events (reactions reusing an existing message's seq,
--     poll votes/closes, pins, roster/metadata updates, unfurls) emit seq = 0
--     ('channel:' || p_channel_id || ':0') so Wave 2.8 (#555) clients never
--     drop them via the `wakeup.seq > 0 && wakeup.seq <= lastAppliedSeq` check.
--
-- p_channel_id — the chat_channels.id (required; BZ160 on NULL).
-- p_event       — the event name ('typing', 'message_created', etc.).
-- p_message_id  — the affected chat_messages.id, or NULL for channel-level events.
-- p_seq         — the channel's change_seq AFTER the mutation, or NULL.
CREATE OR REPLACE FUNCTION notify_chat_state(
    p_channel_id bigint, p_event text,
    p_message_id bigint DEFAULT NULL, p_seq bigint DEFAULT NULL
) RETURNS void AS $$
DECLARE
    v_emit_seq bigint;
BEGIN
    IF p_channel_id IS NULL THEN
        RAISE EXCEPTION 'notify_chat_state requires a channel'
            USING ERRCODE='BZ160', HINT='{"type":"missing_channel"}';
    END IF;
    IF p_event = 'typing' AND p_seq IS NULL THEN
        PERFORM public.app_notify(
            'chat_ephemeral',
            jsonb_build_object(
                'event', p_event,
                'channelId', p_channel_id,
                'messageId', p_message_id,
                'seq', p_seq
            )::text
        );
        RETURN;
    END IF;
    v_emit_seq := CASE
        WHEN p_event IN (
            'message_created', 'message_sent', 'message_edited',
            'message_deleted', 'message_delivered'
        ) THEN COALESCE(p_seq, 0)
        ELSE 0
    END;
    PERFORM public.emit_wakeup_bell(
        'sync',
        'channel:' || p_channel_id || ':' || v_emit_seq
    );
END; $$ LANGUAGE plpgsql;
