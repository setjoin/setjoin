-- chat_presence.sql: typing signal (Pillar A1 Task 7).
--
-- Producer: chat_typing_signal — no table backs this (M3/F3 decision:
-- "Typing/presence: no table — ephemeral notify, capped + throttled"). The
-- notify_chat_state fan-out IS the whole feature; there is nothing to read
-- back, so no _to_json / _list sibling exists here.
--
-- BZ block (chat = BZ160-BZ175, this file's slice): BZ163 not a channel
-- member — same code/shape as chat_message.sql's membership guard.
--
-- ponytail: the >32-member cap is a literal constant, not a config row or
-- toggle — typing storms are the worst fan-out amplifier and the signal is
-- meaningless at that size anyway. Raise the constant (or promote it to a
-- toggle) if a customer's usage pattern needs a bigger ceiling.

CREATE OR REPLACE FUNCTION chat_typing_signal(
    p_user_id bigint, p_channel_id bigint
) RETURNS void AS $$
DECLARE
    v_member_count int;
BEGIN
    PERFORM chat_require_role(p_channel_id, p_user_id);
    SELECT count(*) INTO v_member_count
      FROM chat_channel_members WHERE channel_id = p_channel_id;
    -- no-op, no notify: a channel over the cap gets silence, not an error —
    -- the caller (composer keystroke handler) shouldn't have to special-case
    -- large channels.
    IF v_member_count > 32 THEN
        RETURN;
    END IF;
    PERFORM notify_chat_state(p_channel_id, 'typing');
END;
$$ LANGUAGE plpgsql;
