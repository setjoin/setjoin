-- notify_chat_state.sql: the chat push seam (Pillar A1 Task 3). Per-member
-- fan-out to each channel member's self-scoped chat:{user_id} channel — the
-- drive-watch pattern (drive_watch_set/drive_watch_remove use the same
-- self-channel shape). Every chat-mutating reducer (send/edit/delete,
-- membership changes, reactions, read-state) routes its push through here
-- instead of open-coding pg_notify — app_notify is the single choke point
-- (account-scope guard + feature.notify_decouple both apply transparently;
-- decouple ON is RECOMMENDED for chat-heavy orgs, since it turns this loop
-- into notify_intents inserts drained out-of-txn instead of N queue locks
-- held for the duration of the send txn).
--
-- p_channel_id — the chat_channels.id whose membership defines the fan-out
--   set. Required (BZ160 on NULL) — there is no channel-less push.
-- p_event       — the event name ('message_sent' | 'message_edited' |
--   'message_deleted' | 'member_added' | 'member_removed' | 'owner_changed' |
--   'reaction_added' | 'reaction_removed' | 'read_state' | …), preserved
--   verbatim in the payload.
-- p_message_id  — the affected chat_messages.id, or NULL for channel-level
--   events (membership/roster changes carry no message).
-- p_seq         — the channel's change_seq AFTER the mutation (NULL for
--   events that don't bump it). Lets clients detect gaps and drive
--   since(seq) cheaply instead of re-fetching on every push.
--
-- ponytail: O(members) in the write txn; ceiling ~1k-member channels at low
-- message rates. If a deployment exceeds that, move to channel-scoped
-- subscriptions in the WS dispatcher (documented alternative, not built).
CREATE OR REPLACE FUNCTION notify_chat_state(
    p_channel_id bigint, p_event text,
    p_message_id bigint DEFAULT NULL, p_seq bigint DEFAULT NULL
) RETURNS void AS $$
DECLARE
    v_member_id bigint;
    v_payload   text;
BEGIN
    IF p_channel_id IS NULL THEN
        RAISE EXCEPTION 'notify_chat_state requires a channel'
            USING ERRCODE='BZ160', HINT='{"type":"missing_channel"}';
    END IF;
    v_payload := jsonb_build_object('event', p_event, 'channelId', p_channel_id,
                                    'messageId', p_message_id, 'seq', p_seq)::text;
    FOR v_member_id IN
        SELECT user_id FROM public.chat_channel_members WHERE channel_id = p_channel_id
    LOOP
        PERFORM app_notify('chat:' || v_member_id, v_payload);
    END LOOP;
END; $$ LANGUAGE plpgsql;
