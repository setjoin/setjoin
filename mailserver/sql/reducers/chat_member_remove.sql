-- chat_member_remove.sql — member remove / self-leave + owner succession
-- (extracted verbatim from the legacy chat_channel.sql bundle per WP3
-- one-reducer-per-file; body unchanged except the WP3 audit_write calls).
--
-- SECURITY DEFINER + worker-owned (V134 / native-RLS W4 wave): the Q7 owner-
-- succession arm UPDATEs the NEW owner's row AFTER the departing last owner's
-- own membership row is already deleted. Pinned search_path per ARCH-018.

CREATE OR REPLACE FUNCTION chat_member_remove(
    p_user_id bigint, p_channel_id bigint, p_remove_id bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_role        text;
    v_kind        text;
    v_target_role text;
    v_new_owner   bigint;
BEGIN
    SELECT kind INTO v_kind FROM chat_channels WHERE id = p_channel_id;
    IF v_kind IN ('dm', 'group_dm') THEN
        RAISE EXCEPTION 'cannot remove members from a dm/group_dm'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;
    -- Org-default membership is non-revocable BY THE MEMBER (A3 QoL Task 12,
    -- grill-decided): a self-leave on an org-default channel is rejected —
    -- the UI offers Mute instead. Without this, the idempotent
    -- chat_autojoin_defaults re-provision hook would silently undo a leave
    -- at the user's next AD/LDAP sync, a confusing boomerang. Exits: an
    -- admin unmarks the channel (chat_org_default_set), or admin-initiated
    -- removal (p_user_id <> p_remove_id) still works, e.g. offboarding.
    IF p_user_id = p_remove_id
       AND EXISTS (SELECT 1 FROM org_default_channels WHERE channel_id = p_channel_id) THEN
        RAISE EXCEPTION 'cannot leave an org-default channel'
            USING ERRCODE='BZ163', HINT='{"type":"forbidden","detail":"org-default channel membership is system-maintained; mute instead of leave"}';
    END IF;
    IF p_user_id <> p_remove_id THEN
        SELECT role INTO v_role FROM chat_channel_members
         WHERE channel_id = p_channel_id AND user_id = p_user_id;
        IF v_role IS NULL OR v_role NOT IN ('owner', 'admin') THEN
            RAISE EXCEPTION 'owner/admin required'
                USING ERRCODE='BZ161', HINT='{"type":"forbidden"}';
        END IF;
    END IF;

    SELECT role INTO v_target_role FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_remove_id;
    IF v_target_role IS NULL THEN
        RETURN;  -- idempotent: already not a member
    END IF;

    DELETE FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_remove_id;
    -- A4a Task 3: member.remove (someone else removed them) vs member.leave
    -- (a self-leave) — same predicate the BZ genre above already used.
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, p_channel_id,
          CASE WHEN p_user_id = p_remove_id THEN 'member.leave' ELSE 'member.remove' END,
          'member', p_remove_id, NULL, jsonb_build_object('userId', p_remove_id, 'role', v_target_role), NULL, NULL);
    END IF;

        -- WP3 audit coverage: member.leave vs member.remove, plus the
        -- owner-succession promotion below — chat authority transitions
        -- (core), in the same transaction as the membership delete.
        PERFORM audit_write(
            p_user_id, CASE WHEN p_user_id = p_remove_id
                            THEN 'chat_member_leave' ELSE 'chat_member_remove' END,
            'chat_channel', p_channel_id,
            jsonb_build_object('userId', p_remove_id, 'role', v_target_role),
            NULL,
            NULL, NULL, 'core');
    PERFORM notify_chat_state(p_channel_id, 'member_removed', NULL, NULL);

    -- Owner succession (grill Q7): a channel can never be orphaned. If the
    -- departing member was the LAST owner, auto-promote the longest-tenured
    -- admin, else the longest-tenured member, in the SAME txn — covers
    -- AD/LDAP deprovisioning removals where nobody can be prompted. Explicit
    -- transfer UI is A3. Notified LAST so it is the terminal event on the
    -- affected members' channels (member_removed, then owner_changed).
    IF v_target_role = 'owner' AND NOT EXISTS (
         SELECT 1 FROM chat_channel_members
          WHERE channel_id = p_channel_id AND role = 'owner') THEN
        SELECT user_id INTO v_new_owner FROM chat_channel_members
         WHERE channel_id = p_channel_id AND role = 'admin'
         ORDER BY joined_at ASC LIMIT 1;
        IF v_new_owner IS NULL THEN
            SELECT user_id INTO v_new_owner FROM chat_channel_members
             WHERE channel_id = p_channel_id
             ORDER BY joined_at ASC LIMIT 1;
        END IF;
        IF v_new_owner IS NOT NULL THEN
            UPDATE chat_channel_members SET role = 'owner'
             WHERE channel_id = p_channel_id AND user_id = v_new_owner;
            PERFORM notify_chat_state(p_channel_id, 'owner_changed', NULL, NULL);
            -- WP3 audit coverage: last-owner succession is chat authority —
            -- the promotion that keeps a channel un-orphaned is its own row.
            PERFORM audit_write(
                p_user_id, 'chat_owner_succession', 'chat_channel', p_channel_id,
                jsonb_build_object('userId', p_remove_id, 'role', 'owner'),
                jsonb_build_object('userId', v_new_owner, 'role', 'owner'),
                NULL, NULL, 'core');
        END IF;
    END IF;
END;
$$;
SELECT apply_worker_ownership('chat_member_remove(bigint,bigint,bigint)'::regprocedure);
