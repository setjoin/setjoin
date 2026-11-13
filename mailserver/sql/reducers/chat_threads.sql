-- chat_threads.sql: My-Threads inbox (Pillar A3 QoL Task 11). Pure query,
-- no new BZ code — same "filters rather than errors" IN-SQL membership
-- posture as chat_search (chat_search.sql) and chat_conversation_list
-- (chat_read.sql): a caller never sees a thread from a channel they aren't
-- CURRENTLY a member of, and there is no oracle distinguishing "no threads"
-- from "not a member".
-- No -- deps: header: this file queries chat_messages/chat_channel_members/
-- chat_mentions TABLES directly (no cross-reducer call), so it has no
-- genuine load-order dependency for sort_reducers() to track (chat_roster.sql's
-- precedent for the same reasoning).
--
-- Producer: chat_my_threads(p_user_id, p_limit) -> jsonb array, newest
-- lastReplyAt first.
--
-- A "thread" is a top-level message (parent_message_id IS NULL) that has AT
-- LEAST ONE live reply — a lone root nobody has replied to is not yet a
-- thread (it would otherwise surface every message the caller has ever
-- sent). The caller is "in" a thread if they authored the root, authored
-- ANY reply, or were @mentioned in the root or a reply (chat_mentions rows
-- only ever exist for verified members at send time — chat_message_send's
-- R2 membership filter — so a mention here can never itself be the sole
-- signal from a non-member).
--
-- unreadCount is a per-thread PROJECTION over the A1 channel-level
-- last_read_seq watermark (DES-010's read-receipt posture, reused, not a
-- new write path): count of the root + its live replies whose seq exceeds
-- the caller's own chat_channel_members.last_read_seq for that channel.
-- This is an approximation (a channel-wide watermark, not a per-thread one)
-- — the same tradeoff DES-010 accepts for read receipts generally.
CREATE OR REPLACE FUNCTION chat_my_threads(
    p_user_id bigint, p_limit int DEFAULT 50
) RETURNS jsonb AS $$
DECLARE
    v_lim int;
BEGIN
    v_lim := LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);
    RETURN COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
               'messageId', t.id,
               'channelId', t.channel_id,
               'seq', t.seq,
               'authorId', t.author_id,
               'body', CASE WHEN t.deleted_at IS NOT NULL THEN '' ELSE t.body END,
               'createdAt', t.created_at,
               'replyCount', t.reply_count,
               'lastReplyAt', t.last_reply_at,
               'unreadCount', t.unread_count
             ) ORDER BY t.last_reply_at DESC)
        FROM (
          SELECT root.id, root.channel_id, root.seq, root.author_id,
                 root.body, root.deleted_at, root.created_at,
                 counts.reply_count, counts.last_reply_at,
                 (SELECT count(*) FROM chat_messages u
                    WHERE (u.id = root.id OR u.parent_message_id = root.id)
                      AND u.deleted_at IS NULL
                      AND u.seq > cm.last_read_seq
                      AND u.seq > COALESCE(cm.history_floor_seq, 0)
                      AND (cm.history_floor_seq IS NULL OR u.created_at >= cm.joined_at)) AS unread_count
            FROM chat_messages root
            JOIN chat_channel_members cm
              ON cm.channel_id = root.channel_id AND cm.user_id = p_user_id
            JOIN LATERAL (
              SELECT count(*) AS reply_count, max(created_at) AS last_reply_at
                FROM chat_messages r
               WHERE r.parent_message_id = root.id AND r.deleted_at IS NULL
                 AND r.seq > COALESCE(cm.history_floor_seq, 0)
                 AND (cm.history_floor_seq IS NULL OR r.created_at >= cm.joined_at)
            ) counts ON counts.reply_count > 0
           WHERE root.parent_message_id IS NULL
             -- GUEST_HISTORY_FLOOR: chat_my_threads
             AND root.seq > COALESCE(cm.history_floor_seq, 0)
             AND (cm.history_floor_seq IS NULL OR root.created_at >= cm.joined_at)
             AND (
               root.author_id = p_user_id
               OR EXISTS (SELECT 1 FROM chat_messages rep
                           WHERE rep.parent_message_id = root.id
                             AND rep.author_id = p_user_id
                             AND rep.deleted_at IS NULL
                             AND rep.seq > COALESCE(cm.history_floor_seq, 0)
                             AND (cm.history_floor_seq IS NULL OR rep.created_at >= cm.joined_at))
               OR EXISTS (SELECT 1 FROM chat_mentions men
                           WHERE men.message_id = root.id AND men.mentioned_user_id = p_user_id)
               OR EXISTS (SELECT 1 FROM chat_messages rep2
                           JOIN chat_mentions men2 ON men2.message_id = rep2.id
                          WHERE rep2.parent_message_id = root.id
                            AND rep2.deleted_at IS NULL
                            AND rep2.seq > COALESCE(cm.history_floor_seq, 0)
                            AND (cm.history_floor_seq IS NULL OR rep2.created_at >= cm.joined_at)
                            AND men2.mentioned_user_id = p_user_id)
             )
           ORDER BY counts.last_reply_at DESC
           LIMIT v_lim
        ) t
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;
