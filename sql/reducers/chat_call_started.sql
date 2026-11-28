-- chat_call_started.sql: the Meet↔Chat bridge (spec §3.3, Meet B1 Task 3).
--
-- Posts a msg_type='call' system message into an existing chat channel
-- THROUGH chat_message_send — never a direct INSERT into chat_messages. This
-- means a call announcement rides the exact same membership/archive/
-- post-permission gate, seq bump, and notify_chat_state fan-out as any other
-- message; a meeting bridge is not a backdoor around chat's own rules.
--
-- p_slug is carried in the payload (not just p_meeting_id) so the chat
-- card's "Join" deep-link is the ONE unified shape the public/authed
-- surfaces both resolve (design #14) — the client never has to
-- round-trip meetingId → slug through a separate lookup to build the link.
--
-- The body is the meeting title itself: msg_type='call' is a progressive
-- enhancement (a client that renders it specially uses the payload; one
-- that doesn't falls back to plain text), and chat_message_send's BZ168
-- rejects an empty body when there are no attachments — an empty "call"
-- message would need a special-case carve-out this avoids entirely.
CREATE OR REPLACE FUNCTION chat_call_started(
    p_user_id bigint, p_channel_id bigint, p_meeting_id bigint,
    p_slug text, p_title text
) RETURNS bigint AS $$
DECLARE
    v_result jsonb;
BEGIN
    v_result := chat_message_send(
        p_user_id, p_channel_id, p_title,
        NULL, '{}', NULL, '[]', 'call',
        jsonb_build_object('meetingId', p_meeting_id, 'slug', p_slug, 'title', p_title)
    );
    RETURN (v_result ->> 'messageId')::bigint;
END;
$$ LANGUAGE plpgsql;
