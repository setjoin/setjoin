-- chat_readers.sql: read-receipt watermark projection (Pillar A3 QoL Task 4).
--
-- Producer: chat_channel_readers.
--
-- BZ block (chat = BZ160-BZ179, this file's slice): BZ163 not a channel
-- member.
--
-- ADR DES-010 (docs/adr/DES-010-chat-read-receipts-watermark-not-fact-table.md):
-- read receipts are a PROJECTION over the A1 per-member last_read_seq
-- watermark, never a new per-message write path. "Read by" is always
-- derived client-side as last_read_seq >= msg.seq; this reducer only
-- exposes the watermark row set a member is entitled to see (membership,
-- R1) — names are visible, not just counts (ADR: the rows are
-- member-readable under RLS regardless, so hiding names would be a
-- curtain, not a guarantee).
--
-- App-level-primary (ARCH-006): membership scoped via a direct SELECT
-- against chat_channel_members, matching every other reducer in this
-- package.
CREATE OR REPLACE FUNCTION chat_channel_readers(
    p_user_id bigint, p_channel_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_floor bigint;
BEGIN
    SELECT history_floor_seq INTO v_floor FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    RETURN COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
               'userId', user_id, 'lastReadSeq', last_read_seq
             ) ORDER BY user_id)
        FROM chat_channel_members WHERE channel_id = p_channel_id
          -- GUEST_HISTORY_FLOOR: chat_channel_readers
          AND (v_floor IS NULL OR last_read_seq > v_floor)
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;
