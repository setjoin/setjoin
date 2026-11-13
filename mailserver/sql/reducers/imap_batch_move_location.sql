-- imap_batch_move_location: the batch front door for IMAP MOVE into a
-- `location` exclusive-group folder — ONE SQL round trip per UID MOVE command
-- instead of one per message. It is a thin ordinal-ordered loop over the
-- existing per-message seam transition_message_location (WP4, plan
-- 2026-09-30-review-remediation-wave.md): the location invariant guard, the
-- exclusive swap (set_message_location) and the per-message notify_state_change
-- are NOT reimplemented here and NOT coalesced. Every message still gets its
-- own guard check, its own state bump/journal row and its own pg_notify, in the
-- caller's source-ordinal order, inside the caller's transaction — any row
-- failure RAISEs out of the loop and the whole command rolls back (the IMAP
-- gateway wraps each MOVE in one per-command tx; there are no per-row commits
-- and no savepoints).
--
-- Input: TWO ALIGNED arrays — p_message_ids[i] / p_received_ats[i] describe the
-- i-th message in the source view's ascending effective-UID order (membership
-- UID when the session pinned it, legacy message UID otherwise). The pair is
-- one input relation; misaligned arrays are rejected (BZ285) instead of
-- silently cross-matching a message id with a foreign received_at.
--
-- Output: one row per input ordinal, IN ordinal order. out_message_id /
-- out_received_at echo the input pair so the gateway can match memberships on
-- (message_id, received_at) and reorder by input ordinal (it never trusts scan
-- order); out_imap_uid is the destination membership UID the
-- trg_imap_membership_uid_allocate trigger assigned during that row's swap —
-- allocation order follows the loop order, i.e. the source view's UID order.
--
-- Ownership: p_mailbox_id scopes the destination tag resolution (a foreign
-- mailbox resolves nothing → BZ019, the tag_message posture) and every
-- per-message transition_message_location call is mailbox-scoped, so no
-- cross-tenant write is reachable through this door.
CREATE OR REPLACE FUNCTION imap_batch_move_location(
    p_message_ids           BIGINT[],
    p_received_ats          TIMESTAMPTZ[],
    p_new_location_tag_name TEXT,
    p_mailbox_id            BIGINT,
    p_added_by              TEXT    DEFAULT 'imap'
) RETURNS TABLE (out_message_id BIGINT, out_received_at TIMESTAMPTZ, out_imap_uid BIGINT) AS $$
DECLARE
    v_count       INT;
    v_dest_tag_id BIGINT;
    v_i           INT;
BEGIN
    v_count := COALESCE(cardinality(p_message_ids), 0);
    IF v_count <> COALESCE(cardinality(p_received_ats), 0) THEN
        RAISE EXCEPTION 'imap_batch_move_location: input arrays are misaligned (ids=%, received_ats=%)',
                        v_count, COALESCE(cardinality(p_received_ats), 0)
          USING ERRCODE = 'BZ285',
                HINT = jsonb_build_object('type', 'batch_input_misaligned',
                                          'ids', v_count,
                                          'received_ats', COALESCE(cardinality(p_received_ats), 0))::TEXT;
    END IF;
    IF v_count = 0 THEN
        RETURN;
    END IF;

    -- Resolve the destination tag once, in the owning mailbox (mirrors
    -- tag_message's BZ019 posture; a foreign mailbox resolves nothing).
    SELECT id INTO v_dest_tag_id
    FROM tags
    WHERE mailbox_id = p_mailbox_id AND name = p_new_location_tag_name;
    IF v_dest_tag_id IS NULL THEN
        RAISE EXCEPTION 'Tag % not found in mailbox %', p_new_location_tag_name, p_mailbox_id
          USING ERRCODE = 'BZ019',
                HINT = jsonb_build_object('type', 'tag_not_found',
                                          'tag_name', p_new_location_tag_name,
                                          'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    -- Per message, in source-ordinal order: the deliberate front door (invariant
    -- guard + exclusive swap + its own single notify), then read back the
    -- destination membership UID the allocator trigger just assigned. The loop
    -- order IS the allocation order — the ordered input reaches the allocator
    -- before UID assignment, which is what pins destination UIDs (and the
    -- gateway's COPYUID pairing) to the source view's UID order.
    FOR v_i IN 1..v_count LOOP
        PERFORM transition_message_location(
            p_message_ids[v_i], p_received_ats[v_i],
            p_new_location_tag_name, p_mailbox_id, p_added_by);

        out_message_id  := p_message_ids[v_i];
        out_received_at := p_received_ats[v_i];
        SELECT mt.imap_uid INTO out_imap_uid
        FROM message_tags mt
        WHERE mt.message_id = p_message_ids[v_i]
          AND mt.received_at = p_received_ats[v_i]
          AND mt.tag_id = v_dest_tag_id;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
