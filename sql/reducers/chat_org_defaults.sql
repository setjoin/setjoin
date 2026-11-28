-- chat_org_defaults.sql: org-default channel management (Pillar A3 QoL
-- Task 12 — an A1 deferral pull-in: a 10k-seat org flipping feature.chat
-- must not land every user in an empty app; #general seeding is the
-- rollout-day experience).
--
-- org_default_channels (V122 §G) is an org catalog with NO RLS (admin
-- config, not per-user data — same posture as feature_toggles/
-- retention_policies) — the admin write-gate lives here, not on the table.
--
-- BZ161 here has ORG-admin, not channel-admin, semantics (docs/reducer-
-- error-codes.md's BZ161 raiser list is updated to say so): gated on
-- users.is_local_admin, the same flag ensure_admin.sql/provision_account.sql
-- already treat as "the org admin", not channel ownership/role.
--
-- Membership by policy, not by choice (grill-decided): org-default
-- membership is system-maintained and non-revocable BY THE MEMBER — see
-- chat_channel.sql's chat_member_remove for the leave-rejection guard this
-- table drives. Exits are unmark (this file) or deactivating the user
-- (out of scope here — deactivation does not currently remove chat
-- memberships at all, org-default or not).

CREATE OR REPLACE FUNCTION chat_org_default_set(
    p_admin_user_id bigint, p_channel_id bigint, p_on boolean
) RETURNS void AS $$
DECLARE
    v_new_user_id bigint;
    v_any_added   boolean := false;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_admin_user_id AND is_local_admin = TRUE) THEN
        RAISE EXCEPTION 'org admin required'
            USING ERRCODE='BZ161', HINT='{"type":"forbidden","detail":"org admin required"}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM chat_channels WHERE id = p_channel_id AND kind = 'channel') THEN
        RAISE EXCEPTION 'channel not found'
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    -- Pillar C2 Task 2 (Q14 arm 2): a channel already bound to a federated
    -- room may never become org-default — arm 1 (federation_room_create
    -- refusing an ALREADY org-default channel) lives in
    -- federation_room_create.sql; this is the reverse direction, same
    -- reasoning (an org-default channel federates every employee's
    -- messages with no individual opt-out), same code.
    IF p_on AND EXISTS (
         SELECT 1 FROM chat_channels WHERE id = p_channel_id AND federated_room_id IS NOT NULL) THEN
        RAISE EXCEPTION 'a channel bound to a federated room cannot be marked org-default'
            USING ERRCODE='BZ209', HINT='{"type":"conflict","detail":"channel is bound to a federated room"}';
    END IF;

    IF p_on THEN
        INSERT INTO org_default_channels (channel_id) VALUES (p_channel_id)
          ON CONFLICT (channel_id) DO NOTHING;
        -- Mark → backfill-join ALL existing enabled users in one shot
        -- (idempotent: ON CONFLICT DO NOTHING per membership row). One
        -- aggregate notify for the whole backfill, not one per backfilled
        -- user (the fan-out-ceiling posture chat_channel/AGENTS.md already
        -- documents — a per-user notify here would multiply that ceiling by
        -- however many users a bulk mark backfills). Audit-chain coverage
        -- (pipeline review fix) is per-user — one member.join act per
        -- newly-backfilled member, since "who could see this channel at
        -- time T" is unanswerable without one — but the notify stays
        -- aggregate.
        FOR v_new_user_id IN
            INSERT INTO chat_channel_members (channel_id, user_id, role)
              SELECT p_channel_id, u.id, 'member' FROM users u
               WHERE u.enabled
                 -- Guest exclusion (spec §4.1): org-default membership is an
                 -- org-people concept; guests join only by explicit add.
                 AND NOT is_guest_account(u.id)
              ON CONFLICT (channel_id, user_id) DO NOTHING
              RETURNING user_id
        LOOP
            v_any_added := true;
            IF COALESCE((SELECT enabled FROM feature_toggles
                         WHERE key = 'feature.chat_compliance'), FALSE) THEN
                PERFORM chat_access_audit(p_admin_user_id, p_channel_id, 'member.join',
                  'member', v_new_user_id, NULL,
                  jsonb_build_object('userId', v_new_user_id, 'role', 'member'), NULL, NULL);
            END IF;
        END LOOP;
        IF v_any_added THEN
            PERFORM notify_chat_state(p_channel_id, 'member_added', NULL, NULL);
        END IF;
    ELSE
        -- Unmark → memberships persist; the channel becomes ordinary and
        -- leavable again (chat_member_remove's guard reads this table live).
        DELETE FROM org_default_channels WHERE channel_id = p_channel_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- chat_autojoin_defaults(p_user_id): the provisioning hook. Called from
-- provision_account.sql — the ONE seam covering admin-create/CSV/AD/LDAP/
-- SCIM/JIT provisioning in one line, rather than five re-implementations.
-- Idempotent (ON CONFLICT DO NOTHING per channel), so re-provisioning the
-- same user (AD/LDAP re-sync) never duplicates a membership row. Notifies
-- only channels ACTUALLY newly joined (mirrors chat_member_add's
-- notify-only-on-FOUND posture) — a re-provision that joins nothing new
-- stays silent.
CREATE OR REPLACE FUNCTION chat_autojoin_defaults(p_user_id bigint) RETURNS void AS $$
DECLARE
    v_channel_id bigint;
BEGIN
    -- Guests never autojoin org defaults (spec §4.1) — silent no-op, not a
    -- raise: this runs inside provisioning seams that must not fail.
    IF is_guest_account(p_user_id) THEN
        RETURN;
    END IF;
    FOR v_channel_id IN
        INSERT INTO chat_channel_members (channel_id, user_id, role)
          SELECT odc.channel_id, p_user_id, 'member' FROM org_default_channels odc
          ON CONFLICT (channel_id, user_id) DO NOTHING
          RETURNING channel_id
    LOOP
        -- Audit-chain coverage (pipeline review fix): a self-join by policy
        -- is still a member.join act — the same shape chat_channel_join's
        -- founding self-join writes, just triggered by provisioning instead
        -- of a user click.
        IF COALESCE((SELECT enabled FROM feature_toggles
                     WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, v_channel_id, 'member.join',
              'member', p_user_id, NULL, jsonb_build_object('userId', p_user_id, 'role', 'member'), NULL, NULL);
        END IF;
        PERFORM notify_chat_state(v_channel_id, 'member_added', NULL, NULL);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
