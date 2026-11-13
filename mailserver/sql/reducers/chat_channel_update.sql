-- chat_channel_update.sql — owner/admin channel settings mutation (extracted
-- verbatim from the legacy chat_channel.sql bundle per WP3 one-reducer-per-file;
-- body unchanged except the before-state capture and the WP3 audit_write call).
--
-- BZ161 owner/admin; BZ162 (bad name / post_permission / broadcast_permission
-- vocabulary); BZ209 (federated-room archive fences). Pillar A3 QoL Task 8:
-- p_post_permission/p_broadcast_permission flip the announcement-channel gate
-- (BZ164, V119) and the @channel/@all broadcast gate (BZ166, V122) without a
-- raw UPDATE.

DROP FUNCTION IF EXISTS chat_channel_update(bigint, bigint, text, text, boolean);
CREATE OR REPLACE FUNCTION chat_channel_update(
    p_user_id bigint, p_channel_id bigint,
    p_name text DEFAULT NULL, p_topic text DEFAULT NULL, p_archived boolean DEFAULT NULL,
    p_post_permission text DEFAULT NULL, p_broadcast_permission text DEFAULT NULL
) RETURNS void AS $$
DECLARE
    v_role        text;
    v_room_id     text;
    v_room_peer   text;
    v_room_removed timestamptz;
    v_before      jsonb;
BEGIN
    SELECT role INTO v_role FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF v_role IS NULL OR v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'owner/admin required'
            USING ERRCODE='BZ161', HINT='{"type":"forbidden"}';
    END IF;
    -- Pillar C2 Task 2 (Q13): archiving a room-bound channel is refused,
    -- both shapes — hub (federated_peer_domain NULL) while ANY non-left
    -- roster member remains ("remove all member orgs first, then archive"
    -- is the documented close flow); spoke mirror (federated_peer_domain
    -- set) always while live, EXCEPT once federated_room_removed_at is set
    -- (a kicked/closed mirror is a purely local artifact — archiving it is
    -- a local act). The hub roster-empty probe MUST be DEFINER
    -- (federation_room_has_active_members) — federation_room_members is
    -- FORCE-RLS deny-all, so an invoker-rights read here would silently see
    -- zero rows and allow EVERY hub archive.
    IF p_archived IS TRUE THEN
        SELECT federated_room_id, federated_peer_domain, federated_room_removed_at
          INTO v_room_id, v_room_peer, v_room_removed
          FROM chat_channels WHERE id = p_channel_id;
        IF v_room_id IS NOT NULL THEN
            IF v_room_peer IS NULL THEN
                IF federation_room_has_active_members(v_room_id) THEN
                    RAISE EXCEPTION 'remove all member orgs before archiving a federated hub room'
                        USING ERRCODE='BZ209',
                              HINT='{"type":"conflict","detail":"hub room has active member orgs"}';
                END IF;
            ELSIF v_room_removed IS NULL THEN
                RAISE EXCEPTION 'a live federated room mirror cannot be archived'
                    USING ERRCODE='BZ209',
                          HINT='{"type":"conflict","detail":"the hub org controls this room''s lifecycle"}';
            END IF;
        END IF;
    END IF;
    -- BZ162 (not a raw 23514): whitespace-only rejected same as create, so
    -- the A2 rename-sync line below never sees an empty name reach
    -- drive_spaces_name_check.
    IF p_name IS NOT NULL AND NULLIF(btrim(p_name), '') IS NULL THEN
        RAISE EXCEPTION 'channel name required'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"name required"}';
    END IF;
    IF p_post_permission IS NOT NULL AND p_post_permission NOT IN ('all', 'admins') THEN
        RAISE EXCEPTION 'invalid post_permission %', p_post_permission
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"post_permission must be all|admins"}';
    END IF;
    IF p_broadcast_permission IS NOT NULL AND p_broadcast_permission NOT IN ('admins', 'all') THEN
        RAISE EXCEPTION 'invalid broadcast_permission %', p_broadcast_permission
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"broadcast_permission must be admins|all"}';
    END IF;

    -- WP3 audit coverage: capture the pre-image for the access-policy audit
    -- below (name/topic/archive + the two permission gates).
    SELECT jsonb_build_object('name', name, 'topic', topic,
                              'is_archived', is_archived,
                              'post_permission', post_permission,
                              'broadcast_permission', broadcast_permission)
      INTO v_before
      FROM chat_channels WHERE id = p_channel_id;

    -- no hard delete in A1 (grill Q6b); archive = read-only + hidden from
    -- browse/conversation list, purge is A4's.
    UPDATE chat_channels SET
        name = COALESCE(p_name, name),
        topic = COALESCE(p_topic, topic),
        is_archived = COALESCE(p_archived, is_archived),
        post_permission = COALESCE(p_post_permission, post_permission),
        broadcast_permission = COALESCE(p_broadcast_permission, broadcast_permission)
      WHERE id = p_channel_id;

    -- WP3 audit coverage: channel settings/role-gate changes are chat
    -- authority (core tier).
    PERFORM audit_write(
        p_user_id, 'chat_channel_update', 'chat_channel', p_channel_id,
        v_before,
        jsonb_build_object('name', COALESCE(p_name, v_before->>'name'),
                           'topic', COALESCE(p_topic, v_before->>'topic'),
                           'is_archived', COALESCE(p_archived, (v_before->>'is_archived')::boolean),
                           'post_permission', COALESCE(p_post_permission, v_before->>'post_permission'),
                           'broadcast_permission', COALESCE(p_broadcast_permission, v_before->>'broadcast_permission')),
        NULL, NULL, 'core');

    -- A2 rename sync: a bound Drive space's name mirrors the channel name
    -- (chat_space_ensure sets it at provision time); archive does NOT touch
    -- the space (lifecycle: archive != unbind, DES-009). No-op if unbound.
    IF p_name IS NOT NULL THEN
        UPDATE drive_spaces SET name = left(btrim(p_name), 200)
          WHERE chat_channel_id = p_channel_id;
    END IF;
    PERFORM notify_chat_state(p_channel_id, 'channel_updated', NULL, NULL);
END;
$$ LANGUAGE plpgsql;
