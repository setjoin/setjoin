-- chat_reaction.sql: message-reaction reducer (Pillar A1 Task 6).
--
-- Producers: chat_reaction_toggle.
--
-- BZ block (chat = BZ160-BZ175, this file's slice): BZ169 message not found
-- or soft-deleted (distinct from BZ163 membership — F9: a client toggling a
-- reaction on a message it can no longer see gets a different code than one
-- toggling from outside the channel entirely).
--
-- App-level-primary (ARCH-006): membership scoped via a direct SELECT against
-- chat_channel_members, not the chat_member_role() DEFINER helper (that
-- helper exists solely for the latent FORCE-RLS policy).
--
-- Reactions do NOT bump the channel's change_seq (they aren't messages on
-- the seq rail) — the push instead carries the reacted-to message's CURRENT
-- seq, so a client can correlate the event with the row it already has.
CREATE OR REPLACE FUNCTION chat_reaction_toggle(
    p_user_id bigint, p_message_id bigint, p_emoji text
) RETURNS boolean AS $$
DECLARE
    v_channel_id bigint;
    v_seq        bigint;
    v_deleted    timestamptz;
    v_visible    boolean;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    SELECT channel_id, seq, deleted_at INTO v_channel_id, v_seq, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    -- one code for "doesn't exist" and "soft-deleted" (BZ169) — reacting to a
    -- message you can no longer really see behaves like it isn't there.
    IF v_channel_id IS NULL OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    PERFORM chat_require_role(v_channel_id, p_user_id);
    SELECT m.seq > COALESCE(cm.history_floor_seq, 0)
           AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
      INTO v_visible
      FROM chat_messages m JOIN chat_channel_members cm
        ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
     WHERE m.id = p_message_id;
    -- GUEST_HISTORY_FLOOR: chat_reaction_toggle
    IF NOT COALESCE(v_visible, false) THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    -- toggle: an existing (message_id,user_id,emoji) row is removed; absence
    -- is added. The PK is the natural mutex — no separate EXISTS check.
    DELETE FROM chat_message_reactions
     WHERE message_id = p_message_id AND user_id = p_user_id AND emoji = p_emoji;
    IF FOUND THEN
        PERFORM notify_chat_state(v_channel_id, 'reaction_removed', p_message_id, v_seq);
        RETURN false;
    END IF;
    INSERT INTO chat_message_reactions (message_id, user_id, emoji)
      VALUES (p_message_id, p_user_id, p_emoji);
    PERFORM notify_chat_state(v_channel_id, 'reaction_added', p_message_id, v_seq);
    RETURN true;
END;
$$ LANGUAGE plpgsql;
