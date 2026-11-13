-- set_message_focus.sql: move a message between Focused and Other, and remember
-- the per-sender preference so future mail from that sender lands the same way.
--
--   p_focused = TRUE  → Focused: remove the Other tag; record focused=TRUE
--   p_focused = FALSE → Other:   add the Other tag;    record focused=FALSE
--
-- Focused/Other is modelled as the single system tag `Other` (absence = Focused).
-- The sender is read from the message server-side (R1-scoped to p_mailbox_id) —
-- never trust a client-supplied address for the override key.
CREATE OR REPLACE FUNCTION set_message_focus(
    p_message_id  BIGINT,
    p_received_at TIMESTAMPTZ,
    p_focused     BOOL,
    p_mailbox_id  BIGINT
) RETURNS VOID AS $$
DECLARE
    v_other_id BIGINT;
    v_sender   TEXT;
    v_user_id  BIGINT;
BEGIN
    v_other_id := get_tag_id('Other', p_mailbox_id);
    IF v_other_id IS NULL THEN
        RAISE EXCEPTION 'mailbox % has no Other tag', p_mailbox_id
          USING ERRCODE = 'BZ019',
                HINT = jsonb_build_object('type', 'tag_not_found', 'tag_name', 'Other', 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Resolve the message's real sender, scoped to this mailbox (R1/R3 — ownership
    -- in the same statement, no TOCTOU). Missing → not the caller's message.
    SELECT lower(from_addr) INTO v_sender
    FROM messages
    WHERE id = p_message_id AND received_at = p_received_at AND mailbox_id = p_mailbox_id;
    IF v_sender IS NULL THEN
        RAISE EXCEPTION 'message % not found in mailbox %', p_message_id, p_mailbox_id
          USING ERRCODE = 'BZ006',
                HINT = jsonb_build_object('type', 'not_found', 'message_id', p_message_id)::TEXT;
    END IF;

    IF p_focused THEN
        -- Focused: strip the Other tag (scoped delete, mirrors set_message_location).
        DELETE FROM message_tags mt
        USING tags t
        WHERE mt.message_id = p_message_id
          AND mt.received_at = p_received_at
          AND mt.tag_id = t.id
          AND t.mailbox_id = p_mailbox_id
          AND t.name = 'Other';
    ELSE
        -- Other: add the Other tag (idempotent — skip if already present, since
        -- tag_message inserts unconditionally and message_tags pk would reject a dup).
        IF NOT EXISTS (
            SELECT 1 FROM message_tags
            WHERE message_id = p_message_id AND received_at = p_received_at AND tag_id = v_other_id
        ) THEN
            PERFORM tag_message(p_message_id, p_received_at, 'Other', p_mailbox_id, 'user', FALSE);
        END IF;
    END IF;

    -- Remember the per-sender preference (keyed on the user behind the mailbox).
    SELECT user_id INTO v_user_id FROM account_scope(p_mailbox_id);
    IF v_user_id IS NOT NULL THEN
        INSERT INTO focus_sender_overrides (user_id, sender, focused)
        VALUES (v_user_id, v_sender, p_focused)
        ON CONFLICT (user_id, sender) DO UPDATE SET focused = EXCLUDED.focused, updated_at = now();
    END IF;

    PERFORM notify_state_change(p_mailbox_id, v_other_id, p_message_id, 'updated');
END;
$$ LANGUAGE plpgsql;
