-- chat_roster.sql: channel roster + mention-search reducers (Pillar A1 Task 11).
-- No -- deps: header: this file queries chat_channels/chat_channel_members/
-- public.users TABLES directly (all created by the V119 migration, not by
-- another reducer function), so it has no genuine cross-reducer load-order
-- dependency for sort_reducers() to track. (A prior draft of this comment
-- named "chat_channel.sql" in a "-- deps:" line — reload-reducers.sh's dep
-- parser only understands FUNCTION names there; see chat_read.sql's header
-- for the self-referential-cycle bug that same footgun caused elsewhere.)
--
-- Producers: chat_channel_roster, chat_mention_search.
--
-- BZ block (chat = BZ160-BZ175, this file's slice): BZ163 not a channel
-- member.
--
-- App-level-primary (ARCH-006): membership scoped via a direct SELECT
-- against chat_channel_members, not the chat_member_role() DEFINER helper
-- (that helper exists solely for the latent FORCE-RLS policy).

-- Full member list for a channel the caller belongs to — feeds DM title
-- resolution (client resolves memberIds -> names) and MessageRow author
-- name/avatar lookups (Task 11 plan). Never exposed to a non-member (BZ163):
-- a channel's roster is membership-private, same posture as its messages.
CREATE OR REPLACE FUNCTION chat_channel_roster(
    p_user_id bigint, p_channel_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_result jsonb;
BEGIN
    PERFORM chat_require_role(p_channel_id, p_user_id);

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'userId', m.user_id,
             'displayName', u.display_name,
             'avatarSha256', u.avatar_sha256,
             'role', m.role,
             'external', is_guest_account(m.user_id),
             'removed', EXISTS (SELECT 1 FROM guest_account_status(m.user_id) gs
                                 WHERE gs.status IN ('disabled','expired')
                                    OR (gs.expires_at IS NOT NULL AND gs.expires_at <= now()))
           ) ORDER BY u.display_name), '[]'::jsonb)
      INTO v_result
      FROM chat_channel_members m
      JOIN public.users u ON u.id = m.user_id
     WHERE m.channel_id = p_channel_id;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;

-- @mention autocomplete: prefix/substring match on display_name, scoped to
-- THIS channel's members only (F4 — mentions target members, never an
-- org-wide directory search; an org user who is not in the channel must
-- never surface here, mention-search is not a people-picker). A blank/NULL
-- query returns the whole roster (capped at 10) so an empty composer popup
-- still has something to show; membership is checked first, same BZ163 as
-- the roster above.
CREATE OR REPLACE FUNCTION chat_mention_search(
    p_user_id bigint, p_channel_id bigint, p_query text DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_query  text;
    v_result jsonb;
BEGIN
    PERFORM chat_require_role(p_channel_id, p_user_id);

    v_query := NULLIF(btrim(COALESCE(p_query, '')), '');

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'userId', matched.user_id,
             'displayName', matched.display_name,
             'avatarSha256', matched.avatar_sha256,
             'external', is_guest_account(matched.user_id),
             'removed', EXISTS (SELECT 1 FROM guest_account_status(matched.user_id) gs
                                 WHERE gs.status IN ('disabled','expired')
                                    OR (gs.expires_at IS NOT NULL AND gs.expires_at <= now()))
           ) ORDER BY matched.display_name), '[]'::jsonb)
      INTO v_result
      FROM (
        SELECT m.user_id, u.display_name, u.avatar_sha256
          FROM chat_channel_members m
          JOIN public.users u ON u.id = m.user_id
         WHERE m.channel_id = p_channel_id
           AND (v_query IS NULL OR u.display_name ILIKE v_query || '%')
         ORDER BY u.display_name
         LIMIT 10
      ) matched;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;
