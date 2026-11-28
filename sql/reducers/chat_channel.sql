-- chat_channel.sql: read-only channel surfaces retained from the legacy
-- Pillar A1 Task 4 bundle. Every MUTATING member of that bundle moved to its
-- one-reducer-per-file home with WP3 audit coverage (chat_channel_create.sql,
-- chat_channel_join.sql, chat_channel_update.sql, chat_dm_open.sql,
-- chat_member_add.sql, chat_member_remove.sql, chat_member_set_notif.sql);
-- this file keeps only the two read paths.
--
-- BZ block (chat = BZ160-BZ179): BZ215 is the guest door both read paths
-- enforce; chat_guest_preview shares one shape for missing/inactive/member/
-- foreign-host targets.
--
-- App-level-primary (ARCH-006): every reducer here scopes membership/role via
-- a direct SELECT against chat_channel_members, not the chat_member_role()
-- DEFINER helper (that helper exists solely for the latent FORCE-RLS policy).

CREATE OR REPLACE FUNCTION chat_browse_channels(p_user_id bigint) RETURNS jsonb AS $$
BEGIN
    -- Guest door (spec P2): org-open reach is denied for guest accounts.
    IF is_guest_account(p_user_id) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
    RETURN (
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
                 'channelId', c.id, 'name', c.name, 'topic', c.topic,
                 'memberCount', (SELECT count(*) FROM chat_channel_members m WHERE m.channel_id = c.id),
                 'joined', EXISTS (SELECT 1 FROM chat_channel_members m2
                                    WHERE m2.channel_id = c.id AND m2.user_id = p_user_id)
               ) ORDER BY c.name), '[]'::jsonb)
        FROM chat_channels c
        -- visibility controls DISCOVERY only, never content access (grill Q1);
        -- archived channels are hidden here even though they still exist.
        WHERE c.kind = 'channel' AND c.visibility = 'public' AND NOT c.is_archived
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Guest G2 exact-email preview. SECURITY DEFINER is required because the
-- target guest satellite is FORCE-RLS self-scoped. The delegated helper owns
-- the actor/channel authority check and host-domain derivation before any
-- target lookup. Missing, inactive, member, and foreign-host targets share one
-- shape.
CREATE OR REPLACE FUNCTION chat_guest_preview(
    p_user_id bigint, p_channel_id bigint, p_email text
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_result jsonb;
BEGIN
    SELECT jsonb_build_object(
             'kind', 'activeGuest',
             'userId', preview.user_id,
             'displayName', preview.display_name,
             'historyFromJoin', preview.history_from_join)
      INTO v_result
      FROM guest_active_preview(p_user_id, p_channel_id, p_email) preview;
    RETURN COALESCE(v_result, '{"kind":"inviteRequired"}'::jsonb);
END;
$$;
SELECT apply_worker_ownership('chat_guest_preview(bigint,bigint,text)'::regprocedure);
