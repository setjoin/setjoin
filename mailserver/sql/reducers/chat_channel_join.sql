-- chat_channel_join.sql — public-channel self-join (extracted verbatim from
-- the legacy chat_channel.sql bundle per WP3 one-reducer-per-file; body
-- unchanged except the WP3 audit_write call inside the actual-insert arm).
--
-- BZ215 (guest door), BZ170 anti-oracle: private/archived/nonexistent ids all
-- raise the SAME error — joining never reveals a private channel exists.

CREATE OR REPLACE FUNCTION chat_channel_join(
    p_user_id bigint, p_channel_id bigint
) RETURNS void AS $$
DECLARE
    v_visibility text;
    v_archived   boolean;
BEGIN
    -- Guest door (spec P2): org-open reach is denied for guest accounts.
    IF is_guest_account(p_user_id) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
    SELECT visibility, is_archived INTO v_visibility, v_archived
      FROM chat_channels WHERE id = p_channel_id AND kind = 'channel';
    -- anti-oracle (BZ170): a private/archived/nonexistent/non-channel-kind id
    -- all raise the SAME error — joining must never reveal that a private
    -- channel exists.
    IF NOT FOUND OR v_visibility <> 'public' OR v_archived THEN
        RAISE EXCEPTION 'channel not found'
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    INSERT INTO chat_channel_members (channel_id, user_id, role)
      VALUES (p_channel_id, p_user_id, 'member')
      ON CONFLICT (channel_id, user_id) DO NOTHING;
    IF FOUND THEN
        -- A4a Task 3: a self-join is member.join, not member.add — the
        -- joiner is both actor and target.
        IF COALESCE((SELECT enabled FROM feature_toggles
                     WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, p_channel_id, 'member.join',
              'member', p_user_id, NULL, jsonb_build_object('userId', p_user_id, 'role', 'member'), NULL, NULL);
        END IF;

        -- WP3 audit coverage: an ACTUAL join is a membership transition (the
        -- ON CONFLICT re-join arm is a no-op and writes no row).
        PERFORM audit_write(
            p_user_id, 'chat_channel_join', 'chat_channel', p_channel_id,
            NULL,
            jsonb_build_object('userId', p_user_id, 'role', 'member'),
            NULL, NULL, 'core');

        PERFORM notify_chat_state(p_channel_id, 'member_added', NULL, NULL);
    END IF;
END;
$$ LANGUAGE plpgsql;
