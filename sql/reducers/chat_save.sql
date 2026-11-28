-- chat_save.sql: personal saved-message bookmark reducer (Pillar A3 QoL
-- Task 3).
--
-- Producers: chat_save_toggle, chat_saves_list.
--
-- BZ block (chat = BZ160-BZ179): BZ163 not a channel member — checked at
-- SAVE time only (a save is a personal record; chat_saves_list re-derives
-- current membership on every read instead of trusting a stored flag). BZ169
-- message not found/soft-deleted — gates the INSERT (save) branch ONLY. The
-- DELETE (unsave) branch runs first and is UNGATED: review blocker fix
-- (chat_pin.pg's stuck-pin sibling) — a save-then-soft-delete must stay
-- dismissable. chat_message_delete deliberately does NOT purge
-- chat_saved_messages (a save is a personal record; another user's
-- moderation action must not destroy it — contrast chat_pin.sql, which DOES
-- purge on delete because a pin is a channel-curation record). Before this
-- fix, the BZ169 guard fired before the toggle could even see the DELETE
-- branch, so an already-saved-then-deleted message could never be unsaved
-- via any path.
--
-- Domain semantics (plan Task 3, grill-decided): a Saved message is a
-- PERSONAL bookmark (user-scoped discovery only, NEVER a channel export —
-- distinct from chat_message_pins' org-curation semantics). No fan-out: this
-- is self-only state — the FORCE-RLS self-scoped policy on
-- chat_saved_messages already limits visibility to the saver, so no other
-- member is notified.
--
-- R1 (left-channel saves are HIDDEN, not deleted): chat_saves_list joins
-- current membership IN-SQL rather than storing a membership snapshot — a
-- save in a channel the user has since left silently disappears from their
-- list (the row is retained), and rejoining the channel silently restores it
-- with no separate "restore" step.
CREATE OR REPLACE FUNCTION chat_save_toggle(
    p_user_id bigint, p_message_id bigint
) RETURNS boolean AS $$
DECLARE
    v_channel_id bigint;
    v_deleted    timestamptz;
    v_floor      bigint;
    v_joined_at  timestamptz;
BEGIN
    -- Unsave FIRST and UNGATED: the PK (user_id, message_id) is a
    -- self-scoped mutex needing no message lookup at all, so a save can
    -- always be dismissed regardless of whether the message still exists,
    -- is soft-deleted, or the user has since left the channel. This is the
    -- review-blocker fix — the BZ169/BZ163 guards below now gate ONLY the
    -- save (INSERT) branch, never the unsave (DELETE) branch.
    DELETE FROM chat_saved_messages WHERE user_id = p_user_id AND message_id = p_message_id;
    IF FOUND THEN
        RETURN false;
    END IF;
    -- Reaching here means this is a fresh save attempt: gate on
    -- message-exists/not-deleted and current membership.
    SELECT channel_id, deleted_at INTO v_channel_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    IF v_channel_id IS NULL OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    PERFORM chat_require_role(v_channel_id, p_user_id);
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = v_channel_id AND user_id = p_user_id;
    -- GUEST_HISTORY_FLOOR: chat_save_toggle
    IF NOT EXISTS (
        SELECT 1 FROM chat_messages m
         WHERE m.id = p_message_id
           AND m.seq > COALESCE(v_floor, 0)
           AND (v_floor IS NULL OR m.created_at >= v_joined_at)
    ) THEN
        RAISE EXCEPTION 'message not found'
            USING ERRCODE='BZ169', HINT='{"type":"notFound"}';
    END IF;
    INSERT INTO chat_saved_messages (user_id, message_id) VALUES (p_user_id, p_message_id);
    RETURN true;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chat_saves_list(p_user_id bigint) RETURNS jsonb AS $$
    -- R1: membership join IN-SQL, not a stored flag — a save in a channel
    -- the user has since left is hidden here (row retained in
    -- chat_saved_messages), and rejoining the channel silently restores it.
    SELECT COALESCE(jsonb_agg(chat_message_to_json(m, p_user_id) ORDER BY s.created_at DESC), '[]'::jsonb)
      FROM chat_saved_messages s
     JOIN chat_messages m ON m.id = s.message_id
      JOIN chat_channel_members cm ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
     WHERE s.user_id = p_user_id
       -- GUEST_HISTORY_FLOOR: chat_saves_list
       AND m.seq > COALESCE(cm.history_floor_seq, 0)
       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
       AND (m.parent_message_id IS NULL OR EXISTS (
             SELECT 1 FROM chat_messages parent
              WHERE parent.id = m.parent_message_id
                AND parent.seq > COALESCE(cm.history_floor_seq, 0)
                AND (cm.history_floor_seq IS NULL OR parent.created_at >= cm.joined_at)));
$$ LANGUAGE sql STABLE;
