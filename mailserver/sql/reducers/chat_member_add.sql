-- chat_member_add.sql — owner/admin member add (extracted verbatim from the
-- legacy chat_channel.sql bundle per WP3 one-reducer-per-file; body unchanged
-- except the WP3 audit_write call inside the actual-insert arm).

CREATE OR REPLACE FUNCTION chat_member_add(
    p_user_id bigint, p_channel_id bigint, p_add_id bigint
) RETURNS void AS $$
DECLARE
    v_role text;
    v_kind text;
    v_federated boolean;
    v_channel_change_seq bigint;
    v_guest_can_post boolean;
    v_guest_history_from_join boolean;
    v_is_guest boolean;
BEGIN
    -- (1) Guest door (spec P2): the CALLER being a guest is denied full stop
    -- — even though a guest may itself be an addABLE target (P15 asymmetry,
    -- below), it can never act as the adder. Placed before any other
    -- validation so the deny is not an oracle for anything else (e.g. the
    -- dm/group_dm BZ162 check, or the owner/admin BZ161 check).
    IF is_guest_account(p_user_id) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
    -- (2) P12 arm 1 (BZ199 genre): lock the channel row so a concurrent
    -- federation bind cannot race this add — the two arms are checked under
    -- the SAME row lock federation_room_create takes.
    SELECT kind, (federated_peer_domain IS NOT NULL OR federated_room_id IS NOT NULL), change_seq
      INTO v_kind, v_federated, v_channel_change_seq
      FROM chat_channels WHERE id = p_channel_id FOR UPDATE;
    -- (3) member sets are immutable for dm/group_dm — they define the
    -- channel's identity (member_key). "Add people to a DM" is a client
    -- gesture that calls chat_dm_open with the larger member set instead
    -- (grill Q5).
    IF v_kind IN ('dm', 'group_dm') THEN
        RAISE EXCEPTION 'cannot add members to a dm/group_dm'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;
    -- (4) P12 arm 1 (the C2 standing obligation, BZ216): a guest account can
    -- never be added to a channel with a federation binding (dm-shaped or
    -- room-shaped) — a guest's content must never leave the tenant via a
    -- federation peer (spec §4A residency promise). Checked under the SAME
    -- FOR UPDATE row lock taken at (2).
    IF v_federated AND is_guest_account(p_add_id) THEN
        RAISE EXCEPTION 'a guest account cannot join a federated channel'
            USING ERRCODE='BZ216', HINT='{"type":"forbidden","detail":"channel is federation-bound; guests are excluded (residency)"}';
    END IF;
    -- (5) owner/admin authority check. NOTE (Task 8, E-M3-mandated order):
    -- arm (4) above now fires BEFORE this check, so an authed non-guest caller
    -- who knows a channel id CAN distinguish "bound AND target-is-guest" (BZ216)
    -- from other outcomes without owner/admin rights — a narrow residual oracle
    -- (channel-binding + target-guest-status only, no membership/content leak),
    -- accepted as the cost of enforcing the residency refusal under the lock.
    -- The dm/group_dm (BZ162) and this owner/admin (BZ161) checks still gate
    -- everything else.
    SELECT role INTO v_role FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF v_role IS NULL OR v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'owner/admin required'
            USING ERRCODE='BZ161', HINT='{"type":"forbidden"}';
    END IF;
    -- (6) C-5: guest-target grants serialize against guest_set_status (FOR
    -- SHARE vs its FOR UPDATE) and refuse a non-active guest (BZ219) — a
    -- grant either lands before a disable (and its clean-slate sweep deletes
    -- it) or waits and is refused. No-op/no-lock for member targets.
    -- Deliberately AFTER (2)'s channel read and (5)'s role check so lock
    -- order stays channel->satellite, and immediately before the INSERT.
    PERFORM guest_require_grantable(p_add_id);
    SELECT s.can_post, s.history_from_join
      INTO v_guest_can_post, v_guest_history_from_join
      FROM guest_chat_policy_snapshot(p_add_id) s;
    v_is_guest := FOUND;
    INSERT INTO chat_channel_members
        (channel_id, user_id, role, can_post, history_floor_seq)
      VALUES (
        p_channel_id, p_add_id, 'member',
        CASE WHEN v_is_guest THEN v_guest_can_post ELSE NULL END,
        CASE WHEN v_is_guest AND v_guest_history_from_join
             THEN v_channel_change_seq ELSE NULL END
      )
      ON CONFLICT (channel_id, user_id) DO NOTHING;
    -- F9: notify only on an actual insert — re-adding an existing member is a
    -- silent no-op, never a duplicate push.
    IF FOUND THEN
        -- A4a Task 3: member.add act, actor = p_user_id, target = p_add_id.
        IF COALESCE((SELECT enabled FROM feature_toggles
                     WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, p_channel_id, 'member.add',
              'member', p_add_id, NULL, jsonb_build_object('userId', p_add_id, 'role', 'member'), NULL, NULL);
        END IF;

        -- WP3 audit coverage: an ACTUAL member add is a membership
        -- transition (the ON CONFLICT re-add arm is a no-op and writes no
        -- row).
        PERFORM audit_write(
            p_user_id, 'chat_member_add', 'chat_channel', p_channel_id,
            NULL,
            jsonb_build_object('userId', p_add_id, 'role', 'member'),
            NULL, NULL, 'core');
        PERFORM notify_chat_state(p_channel_id, 'member_added', NULL, NULL);
    END IF;
END;
$$ LANGUAGE plpgsql;
