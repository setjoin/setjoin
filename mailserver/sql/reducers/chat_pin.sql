-- chat_pin.sql: channel pin (curation act) reducer (Pillar A3 QoL Task 3).
--
-- Producers: chat_pin_toggle, chat_pins_list.
--
-- BZ block (chat = BZ160-BZ179): BZ176 pin permission — channels require
-- owner/admin; DMs/group-DMs (kind <> 'channel') are all-member, since every
-- DM/group-DM row is 'member' (V119) — admin-gating would make pin
-- dead-on-arrival where users pin most. BZ163 not a channel member (both
-- toggle and list). BZ169 message not found/soft-deleted (reused from
-- chat_reaction.sql's posture — pinning a message you can no longer see
-- behaves like it isn't there).
--
-- Domain semantics (plan Task 3, grill-decided): a Pin is a channel-scoped
-- CURATION act (an org record — A4 exports it with the channel), distinct
-- from chat_save.sql's personal bookmark. chat_message_pins is
-- current-state-only; the pin/unpin ACTS belong to A4's per-conversation
-- audit chain, not an A3 history table. Unpin is COLLECTIVE — any authorized
-- member (owner/admin in a channel, any member in a DM) may remove ANY pin,
-- not just their own — Slack channel-curation semantics, so there is
-- deliberately no "only the pinner may unpin" guard.
--
-- Pin/unpin bump the channel's change_seq (rare relative to sends, but on
-- the SAME rail as send/edit/delete) and chat_message_to_json projects
-- 'pinned' — so a client that missed the live message_pinned push still
-- heals on its next since(seq) replay, exactly the edit/delete precedent in
-- chat_message.sql.
CREATE OR REPLACE FUNCTION chat_pin_toggle(
    p_user_id bigint, p_message_id bigint
) RETURNS boolean AS $$
DECLARE
    v_channel_id bigint;
    v_deleted    timestamptz;
    v_kind       text;
    v_role       text;
    v_seq        bigint;
    v_pinned     boolean;
    v_floor      bigint;
    v_joined_at  timestamptz;
BEGIN
    SELECT channel_id, deleted_at INTO v_channel_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    IF v_channel_id IS NULL OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    SELECT c.kind, m.role, m.history_floor_seq, m.joined_at
      INTO v_kind, v_role, v_floor, v_joined_at
      FROM chat_channels c JOIN chat_channel_members m
        ON m.channel_id = c.id AND m.user_id = p_user_id
     WHERE c.id = v_channel_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'not a member of channel %', v_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    -- GUEST_HISTORY_FLOOR: chat_pin_toggle
    IF NOT EXISTS (
        SELECT 1 FROM chat_messages m
         WHERE m.id = p_message_id
           AND m.seq > COALESCE(v_floor, 0)
           AND (v_floor IS NULL OR m.created_at >= v_joined_at)
    ) THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    -- BZ176: channels require owner/admin; DMs/group-DMs are all-member.
    IF v_kind = 'channel' AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'owner/admin required to pin in a channel'
            USING ERRCODE='BZ176', HINT='{"type":"forbidden"}';
    END IF;

    -- re-stamp seq (same rail as send/edit/delete) so a since(seq) replay
    -- re-surfaces the message with its new pinned state.
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id RETURNING change_seq INTO v_seq;
    UPDATE chat_messages SET seq = v_seq WHERE id = p_message_id;

    -- toggle: the PK is the natural mutex. Collective unpin — no
    -- pinned_by-only guard; the role check above already authorizes ANY
    -- eligible member to flip either direction.
    DELETE FROM chat_message_pins
     WHERE channel_id = v_channel_id AND message_id = p_message_id;
    IF FOUND THEN
        v_pinned := false;
    ELSE
        INSERT INTO chat_message_pins (channel_id, message_id, pinned_by)
          VALUES (v_channel_id, p_message_id, p_user_id);
        v_pinned := true;
    END IF;
    -- A4a Task 3: chained ACT (pin.add / pin.remove), inert while
    -- feature.chat_compliance is OFF.
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_channel_id,
          CASE WHEN v_pinned THEN 'pin.add' ELSE 'pin.remove' END,
          'message', p_message_id, NULL, jsonb_build_object('seq', v_seq), NULL, NULL);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'message_pinned', p_message_id, v_seq);
    RETURN v_pinned;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chat_pins_list(
    p_user_id bigint, p_channel_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_floor bigint;
    v_joined_at timestamptz;
BEGIN
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    RETURN COALESCE((
      SELECT jsonb_agg(chat_message_to_json(m, p_user_id) ORDER BY p.created_at DESC)
        FROM chat_message_pins p JOIN chat_messages m ON m.id = p.message_id
       WHERE p.channel_id = p_channel_id
         -- GUEST_HISTORY_FLOOR: chat_pins_list
         AND m.seq > COALESCE(v_floor, 0)
         AND (v_floor IS NULL OR m.created_at >= v_joined_at)
         AND (m.parent_message_id IS NULL OR EXISTS (
               SELECT 1 FROM chat_messages parent
                WHERE parent.id = m.parent_message_id
                  AND parent.seq > COALESCE(v_floor, 0)
                  AND (v_floor IS NULL OR parent.created_at >= v_joined_at)))
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;
