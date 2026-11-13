-- chat_member_set_notif.sql — a member's own per-channel DND/mute preference
-- (extracted verbatim from the legacy chat_channel.sql bundle per WP3
-- one-reducer-per-file; body unchanged except the routine-tier audit_write).
--
-- Purely a client-decision surface ("No push filtering. Mobile push = A3.5") —
-- the WS relay is never filtered by notif_level; self-scoped state nobody else
-- needs to learn about. R1/R2/R3 in one statement.

CREATE OR REPLACE FUNCTION chat_member_set_notif(
    p_user_id bigint, p_channel_id bigint, p_level text
) RETURNS void AS $$
BEGIN
    IF p_level NOT IN ('all', 'mentions', 'none') THEN
        RAISE EXCEPTION 'invalid notif_level %', p_level
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"level must be all|mentions|none"}';
    END IF;
    UPDATE chat_channel_members SET notif_level = p_level
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;

    -- WP3 audit coverage: the member's own per-channel DND/mute preference —
    -- routine tier, so the row lands only at audit_policy level 'full'.
    PERFORM audit_write(
        p_user_id, 'chat_member_set_notif', 'chat_channel', p_channel_id,
        NULL,
        jsonb_build_object('notif_level', p_level),
        NULL, NULL, 'routine');
END;
$$ LANGUAGE plpgsql;
