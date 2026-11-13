-- chat_channel_create.sql — channel creation (extracted verbatim from the
-- legacy chat_channel.sql bundle per WP3 one-reducer-per-file; body unchanged
-- except the WP3 audit_write call).
--
-- BZ161 (org-admin chat.channel_creation gate), BZ162 (bad name/visibility),
-- BZ215 (guest door). Meet B1 Task 3: p_system bypasses ONLY the org gate.

CREATE OR REPLACE FUNCTION chat_channel_create(
    p_user_id bigint, p_name text, p_topic text DEFAULT NULL,
    p_visibility text DEFAULT 'public', p_system boolean DEFAULT false
) RETURNS bigint AS $$
DECLARE
    v_id                      bigint;
    v_is_guest                boolean := is_guest_account(p_user_id);
    v_guest_can_post          boolean;
    v_guest_history_from_join boolean;
BEGIN
    -- Guest door (spec P2) remains closed to every user-facing call. Guest G3
    -- permits only the existing internal p_system=true call from
    -- meeting_create, after that reducer has enforced allow_meet_create. No
    -- HTTP route exposes p_system and this carve-out grants no member-add verb.
    IF v_is_guest AND NOT p_system THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
    IF v_is_guest THEN
        PERFORM guest_require_grantable(p_user_id);
        SELECT s.can_post, s.history_from_join
          INTO v_guest_can_post, v_guest_history_from_join
          FROM guest_chat_policy_snapshot(p_user_id) s;
    END IF;
    IF NULLIF(btrim(COALESCE(p_name, '')), '') IS NULL THEN
        RAISE EXCEPTION 'channel name required'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"name required"}';
    END IF;
    IF p_visibility NOT IN ('public', 'private') THEN
        RAISE EXCEPTION 'invalid visibility'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"visibility must be public|private"}';
    END IF;
    -- any authenticated user may create a channel (grill Q6a) UNLESS the
    -- org has flipped chat.channel_creation OFF (A3 QoL Task 12,
    -- drive.space_creation's shape) — then only an org admin may (BZ161;
    -- ORG-admin semantics here, not channel-admin — see docs/reducer-error-
    -- codes.md's BZ161 raiser note). p_system=true skips this gate entirely
    -- (Meet B1 Task 3): a governance org that restricts channel creation
    -- must never see meeting_create fail with a cryptic chat error.
    IF NOT p_system
       AND NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'chat.channel_creation'), TRUE)
       AND NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND is_local_admin = TRUE) THEN
        RAISE EXCEPTION 'channel creation is restricted to admins'
            USING ERRCODE='BZ161', HINT='{"type":"forbidden","detail":"chat.channel_creation is disabled; org admin required"}';
    END IF;
    -- Pre-allocated id, NO RETURNING: under live FORCE-RLS (native-RLS flip)
    -- INSERT..RETURNING must also pass the SELECT policy, and chat_channels'
    -- read policy is membership-scoped — the creator's member row does not
    -- exist yet at RETURNING time, so a non-public channel create failed with
    -- an RLS violation for every non-BYPASSRLS caller (found live by the B1
    -- webmail-UI gate: meeting_create 500'd through this path). Do NOT add a
    -- created_by arm to the read policy instead — membership is the ONLY
    -- access truth (DES-008/A2), a creator who leaves must lose read.
    v_id := nextval(pg_get_serial_sequence('chat_channels', 'id'));
    INSERT INTO chat_channels (id, kind, name, topic, visibility, created_by)
      OVERRIDING SYSTEM VALUE
      VALUES (v_id, 'channel', p_name, p_topic, p_visibility, p_user_id);
    INSERT INTO chat_channel_members
        (channel_id, user_id, role, can_post, history_floor_seq)
      VALUES (
        v_id, p_user_id, 'owner',
        CASE WHEN v_is_guest THEN v_guest_can_post ELSE NULL END,
        -- A newly-created channel starts at change_seq=0; stamping the same
        -- profile snapshot as chat_member_add preserves the immutable floor.
        CASE WHEN v_is_guest AND v_guest_history_from_join THEN 0 ELSE NULL END
      );
    -- A4a Task 3: founding membership is a member.add act too — "who could
    -- see this channel at time T" is unanswerable without a baseline.
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_id, 'member.add',
          'member', p_user_id, NULL, jsonb_build_object('userId', p_user_id, 'role', 'owner'), NULL, NULL);
    END IF;

    -- WP3 audit coverage: channel creation is chat authority — a core-tier
    -- admin_audit_log row in the same transaction as the channel + founding
    -- membership.
    PERFORM audit_write(
        p_user_id, 'chat_channel_create', 'chat_channel', v_id,
        NULL,
        jsonb_build_object('name', p_name, 'visibility', p_visibility,
                           'topic', p_topic),
        NULL, NULL, 'core');

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
