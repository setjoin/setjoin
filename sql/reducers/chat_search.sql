-- chat_search.sql: CJK-capable full-text search (Pillar A3 QoL Task 10).
--
-- Producer: chat_search(p_user_id, p_query, p_channel_id, p_from_user,
-- p_before_id, p_has, p_use_trgm, p_limit) -> jsonb array, newest-first on
-- the GLOBAL chat_messages.id (NOT seq — seq is per-channel, UNIQUE(channel_id,
-- seq), and cannot keyset across channels the way a cross-channel search
-- result set must).
--
-- Membership is scoped IN-SQL (R1, a plain JOIN against chat_channel_members
-- for the caller — no reducer-level RAISE, same "filters rather than errors"
-- posture as chat_conversation_list): a query never surfaces a hit from a
-- channel the caller isn't in, and there is no separate BZ163 raise to
-- distinguish "no results" from "not a member" (an oracle chat_search must
-- not create). deleted_at IS NULL excludes soft-deleted messages (their body
-- is blanked in the projection anyway, but excluding them from the match set
-- avoids a query hitting the tombstone's now-empty body).
--
-- Query routing (the CN-critical differentiator): the caller (Go, HasHanRune
-- in internal/chat/search.go) detects a Han run and sets p_use_trgm — the
-- 'simple' tsquery config cannot tokenize Han text into words (chat_messages
-- .search_tsv, V119, is latin-only in practice), so a Han-containing query
-- routes to the pg_trgm-backed body ILIKE substring leg
-- (chat_messages_body_trgm_idx, V122) instead of
-- search_tsv @@ plainto_tsquery('simple', p_query). Proper zh
-- segmentation (zhparser/pg_jieba) stays deferred — substring match is the
-- v1 floor (plan NOT-in-scope).
--
-- p_has is a v1 floor too: only 'attachment' is recognized (EXISTS against
-- chat_message_attachments); any other value matches nothing rather than
-- erroring, so an unrecognized filter degrades to "no results" not a 500.
CREATE OR REPLACE FUNCTION chat_search(
    p_user_id bigint, p_query text,
    p_channel_id bigint DEFAULT NULL,
    p_from_user bigint DEFAULT NULL,
    p_before_id bigint DEFAULT NULL,
    p_has text DEFAULT NULL,
    p_use_trgm boolean DEFAULT false,
    p_limit int DEFAULT 50
) RETURNS jsonb AS $$
DECLARE
    v_lim int;
BEGIN
    v_lim := LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);
    RETURN COALESCE((
      SELECT jsonb_agg(chat_message_to_json(m, p_user_id) ORDER BY m.id DESC)
        FROM (
          SELECT m.* FROM chat_messages m
          JOIN chat_channel_members cm
            ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
          WHERE m.deleted_at IS NULL
            -- GUEST_HISTORY_FLOOR: chat_search
            AND m.seq > COALESCE(cm.history_floor_seq, 0)
            AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
            AND (m.parent_message_id IS NULL OR EXISTS (
                  SELECT 1 FROM chat_messages parent
                   WHERE parent.id = m.parent_message_id
                     AND parent.seq > COALESCE(cm.history_floor_seq, 0)
                     AND (cm.history_floor_seq IS NULL OR parent.created_at >= cm.joined_at)))
            AND (p_channel_id IS NULL OR m.channel_id = p_channel_id)
            AND (p_from_user IS NULL OR m.author_id = p_from_user)
            AND (p_before_id IS NULL OR m.id < p_before_id)
            AND (p_has IS NULL OR (p_has = 'attachment'
                 AND EXISTS (SELECT 1 FROM chat_message_attachments a WHERE a.message_id = m.id)))
            AND (CASE WHEN p_use_trgm
                      THEN m.body ILIKE '%' || p_query || '%'
                      ELSE m.search_tsv @@ plainto_tsquery('simple', p_query)
                 END)
          ORDER BY m.id DESC
          LIMIT v_lim
        ) m
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;
