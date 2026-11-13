-- chat_poll.sql: polls reducer (Pillar A3 QoL Task 9).
--
-- Producers: chat_poll_create, chat_poll_vote, chat_poll_close, chat_poll_results.
--
-- BZ block (chat = BZ160-BZ179, this file's slice): BZ177 "poll invalid" —
-- one code, no oracle on which of: poll/option not found, the poll's anchor
-- message soft-deleted, or the poll already closed (either via closes_at or
-- the anchor delete) — same anti-oracle posture as BZ165/BZ167/BZ170. BZ163
-- (not a channel member) is reused, resolved via the poll's own channel_id.
-- Manual close's actor gate ("creator OR channel owner/admin") reuses the
-- EXISTING BZ161 ("not owner/admin") rather than minting a second poll code —
-- the plan reserved exactly one new code for this task (BZ177, "poll
-- invalid": closed/duplicate/bad option), and BZ161's docstring already
-- covers multiple varied channel-scoped admin gates; the "OR creator"
-- caveat is encoded in this reducer's own logic, mirroring how
-- chat_message_delete (BZ167) extends "author OR owner/admin" under its own
-- dedicated code — here the caveat rides the ALREADY-shared forbidden code
-- instead, since a lumped code must keep one consistent HTTP class (BZ177 is
-- classified ClassUnprocessable/422 for its "invalid state/arguments"
-- raises; a wrong-actor close is a distinct ClassForbidden/403 concern, so
-- it cannot share BZ177 without breaking that class purity).
--
-- Lifecycle (grill-decided, plan Task 9): a poll is a domain object anchored
-- to its message (chat_polls.message_id UNIQUE, V122) — soft-deleting the
-- anchor message implicitly closes it (vote -> BZ177); poll + option + vote
-- rows are NEVER destroyed (A1's never-destroy/A4-retention posture) even
-- after the anchor is gone. No poll editing, ever (posture, not a v1 cut).
--
-- Non-anonymous (gate-approved): chat_poll_results returns per-option voter
-- lists — vote rows are member-readable under RLS regardless, so hiding
-- voters in the UI would be a curtain, not a guarantee (same posture as the
-- read-receipt "read by N with names" decision).
--
-- Votes do NOT bump the channel's change_seq (write-amplification ceiling) —
-- fan-out is 'poll_voted' only; clients refetch chat_poll_results on render
-- and on that event (reconnect staleness heals on next render, no seq-rail
-- replay needed here, unlike pin/save which DO re-stamp seq).
--
-- App-level-primary (ARCH-006): membership/channel scoping via direct
-- SELECTs against chat_channel_members/chat_polls, not the chat_member_role()
-- DEFINER helper (that helper exists solely for the latent FORCE-RLS policy).

-- chat_poll_create: posts the poll THROUGH chat_message_send (never a direct
-- INSERT into chat_messages) so the poll message rides the SAME seq/notify/
-- post-permission/archive/membership gate every other message uses (Task 6's
-- seam). The message body is the question itself — chat_message_send's own
-- BZ168 (empty/over-64KiB body) already validates it, no duplicate check
-- here (ponytail: one body-validation gate, not two).
CREATE OR REPLACE FUNCTION chat_poll_create(
    p_user_id bigint, p_channel_id bigint, p_question text, p_options text[],
    p_multi boolean DEFAULT false, p_closes_at timestamptz DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_send_result jsonb;
    v_msg_id      bigint;
    v_seq         bigint;
    v_poll_id     bigint;
BEGIN
    -- BZ177: at least 2 options, none blank (shape check — the reducer this
    -- task owns, not chat_message_send's job).
    IF p_options IS NULL OR array_length(p_options, 1) IS NULL OR array_length(p_options, 1) < 2 THEN
        RAISE EXCEPTION 'a poll requires at least 2 options'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments","detail":"at least 2 options required"}';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_options) o WHERE coalesce(btrim(o), '') = '') THEN
        RAISE EXCEPTION 'poll options may not be blank'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments","detail":"blank option label"}';
    END IF;

    -- Membership/post-permission/archive/broadcast/body-size checks all live
    -- in chat_message_send — reused verbatim (Task 6 seam). msg_type='poll'
    -- with a NULL payload for now; the pollId is unknown until the poll row
    -- below exists, so it's stamped in with an UPDATE, same transaction.
    v_send_result := chat_message_send(p_user_id, p_channel_id, p_question,
                        NULL, '{}', NULL, '[]'::jsonb, 'poll', NULL);
    v_msg_id := (v_send_result ->> 'messageId')::bigint;
    v_seq    := (v_send_result ->> 'seq')::bigint;

    INSERT INTO chat_polls (message_id, channel_id, question, multi, closes_at, created_by)
      VALUES (v_msg_id, p_channel_id, p_question, COALESCE(p_multi, false), p_closes_at, p_user_id)
      RETURNING id INTO v_poll_id;

    INSERT INTO chat_poll_options (poll_id, ordinal, label)
      SELECT v_poll_id, ord, opt FROM unnest(p_options) WITH ORDINALITY AS t(opt, ord);

    -- stamp the pollId into the already-sent message's payload — same
    -- transaction as the send above, so a client can never observe a poll
    -- message with a NULL payload.
    UPDATE chat_messages SET payload = jsonb_build_object('pollId', v_poll_id) WHERE id = v_msg_id;

    RETURN jsonb_build_object('messageId', v_msg_id, 'pollId', v_poll_id, 'seq', v_seq);
END;
$$ LANGUAGE plpgsql;

-- chat_poll_vote: SELECT..FOR UPDATE on the chat_polls row serializes
-- concurrent votes from the same user (the row lock is the mutex the
-- DELETE-then-INSERT dance below relies on to never leave two rows for a
-- single-vote poll under a race). BZ177 covers poll/option not found, the
-- anchor message soft-deleted, and the poll already closed — one code, no
-- oracle on which.
CREATE OR REPLACE FUNCTION chat_poll_vote(
    p_user_id bigint, p_poll_id bigint, p_option_id bigint
) RETURNS void AS $$
DECLARE
    v_channel_id bigint;
    v_message_id bigint;
    v_closes_at  timestamptz;
    v_multi      boolean;
    v_deleted    timestamptz;
    v_message_seq bigint;
    v_message_created_at timestamptz;
    v_floor      bigint;
    v_joined_at  timestamptz;
BEGIN
    SELECT p.channel_id, p.message_id, p.closes_at, p.multi,
           m.deleted_at, m.seq, m.created_at
      INTO v_channel_id, v_message_id, v_closes_at, v_multi,
           v_deleted, v_message_seq, v_message_created_at
      FROM chat_polls p JOIN chat_messages m ON m.id = p.message_id
     WHERE p.id = p_poll_id
     FOR UPDATE OF p;
    IF v_channel_id IS NULL THEN
        RAISE EXCEPTION 'poll not found'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'poll is closed (anchor message deleted)'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    IF v_closes_at IS NOT NULL AND v_closes_at <= now() THEN
        RAISE EXCEPTION 'poll is closed'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    PERFORM chat_require_role(v_channel_id, p_user_id);
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = v_channel_id AND user_id = p_user_id;
    -- GUEST_HISTORY_FLOOR: chat_poll_vote
    IF v_message_seq <= COALESCE(v_floor, 0)
       OR (v_floor IS NOT NULL AND v_message_created_at < v_joined_at) THEN
        RAISE EXCEPTION 'poll not found'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM chat_poll_options WHERE id = p_option_id AND poll_id = p_poll_id) THEN
        RAISE EXCEPTION 'invalid poll option'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;

    IF v_multi THEN
        -- multi allows N different options for the same voter; idempotent
        -- (voting the same option twice is a no-op, not an error or a toggle).
        INSERT INTO chat_poll_votes (poll_id, option_id, user_id)
          VALUES (p_poll_id, p_option_id, p_user_id)
          ON CONFLICT (poll_id, option_id, user_id) DO NOTHING;
    ELSE
        -- single-vote: delete any prior vote (any option) then insert the
        -- new one — the FOR UPDATE lock above serializes a racing double
        -- vote from the same user into delete-then-insert, never two rows.
        DELETE FROM chat_poll_votes WHERE poll_id = p_poll_id AND user_id = p_user_id;
        INSERT INTO chat_poll_votes (poll_id, option_id, user_id) VALUES (p_poll_id, p_option_id, p_user_id);
    END IF;

    -- votes do NOT bump change_seq (write-amplification ceiling, plan Task
    -- 9) — clients refetch chat_poll_results on this event, not via replay.
    PERFORM notify_chat_state(v_channel_id, 'poll_voted', v_message_id, NULL);
END;
$$ LANGUAGE plpgsql;

-- chat_poll_close: creator OR channel owner/admin may close (BZ161 for
-- anyone else); sets closes_at = now() (a poll is never re-opened). Fans out
-- 'poll_voted' too — no separate poll_closed event exists (V122's fan-out
-- list names only message_pinned/poll_voted/member_read as new events) — a
-- client re-fetching chat_poll_results on that event sees closed=true and
-- renders "Final results" regardless of what triggered the refetch.
CREATE OR REPLACE FUNCTION chat_poll_close(
    p_user_id bigint, p_poll_id bigint
) RETURNS void AS $$
DECLARE
    v_channel_id bigint;
    v_message_id bigint;
    v_created_by bigint;
    v_role       text;
    v_deleted    timestamptz;
    v_message_seq bigint;
    v_message_created_at timestamptz;
    v_floor      bigint;
    v_joined_at  timestamptz;
BEGIN
    SELECT p.channel_id, p.message_id, p.created_by,
           m.deleted_at, m.seq, m.created_at
      INTO v_channel_id, v_message_id, v_created_by,
           v_deleted, v_message_seq, v_message_created_at
      FROM chat_polls p JOIN chat_messages m ON m.id = p.message_id
     WHERE p.id = p_poll_id;
    IF v_channel_id IS NULL THEN
        RAISE EXCEPTION 'poll not found'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    v_role := chat_require_role(v_channel_id, p_user_id);
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = v_channel_id AND user_id = p_user_id;
    -- GUEST_HISTORY_FLOOR: chat_poll_close
    IF v_deleted IS NOT NULL
       OR v_message_seq <= COALESCE(v_floor, 0)
       OR (v_floor IS NOT NULL AND v_message_created_at < v_joined_at) THEN
        RAISE EXCEPTION 'poll not found'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_user_id <> v_created_by AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'poll creator or channel owner/admin required to close'
            USING ERRCODE='BZ161', HINT='{"type":"forbidden"}';
    END IF;
    UPDATE chat_polls SET closes_at = now() WHERE id = p_poll_id;
    PERFORM notify_chat_state(v_channel_id, 'poll_voted', v_message_id, NULL);
END;
$$ LANGUAGE plpgsql;

-- chat_poll_results: tally + per-option voter lists (non-anonymous,
-- gate-approved — vote rows are member-readable under RLS regardless).
CREATE OR REPLACE FUNCTION chat_poll_results(
    p_user_id bigint, p_poll_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_channel_id bigint;
    v_deleted    timestamptz;
    v_message_seq bigint;
    v_message_created_at timestamptz;
    v_floor      bigint;
    v_joined_at  timestamptz;
BEGIN
    SELECT p.channel_id, m.deleted_at, m.seq, m.created_at
      INTO v_channel_id, v_deleted, v_message_seq, v_message_created_at
      FROM chat_polls p JOIN chat_messages m ON m.id = p.message_id
     WHERE p.id = p_poll_id;
    IF v_channel_id IS NULL THEN
        RAISE EXCEPTION 'poll not found'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    PERFORM chat_require_role(v_channel_id, p_user_id);
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = v_channel_id AND user_id = p_user_id;
    -- GUEST_HISTORY_FLOOR: chat_poll_results
    IF v_deleted IS NOT NULL
       OR v_message_seq <= COALESCE(v_floor, 0)
       OR (v_floor IS NOT NULL AND v_message_created_at < v_joined_at) THEN
        RAISE EXCEPTION 'poll not found'
            USING ERRCODE='BZ177', HINT='{"type":"invalidArguments"}';
    END IF;
    RETURN (
      SELECT jsonb_build_object(
        'pollId', p.id,
        'question', p.question,
        'multi', p.multi,
        'closesAt', p.closes_at,
        'closed', (p.closes_at IS NOT NULL AND p.closes_at <= now()),
        'options', COALESCE((
          SELECT jsonb_agg(jsonb_build_object(
                   'optionId', o.id, 'ordinal', o.ordinal, 'label', o.label,
                   'count', COALESCE(v.cnt, 0),
                   'voters', COALESCE(v.voters, '[]'::jsonb))
                  ORDER BY o.ordinal)
            FROM chat_poll_options o
            LEFT JOIN (
              SELECT option_id, count(*) cnt, jsonb_agg(user_id ORDER BY created_at) voters
                FROM chat_poll_votes WHERE poll_id = p_poll_id GROUP BY option_id
            ) v ON v.option_id = o.id
           WHERE o.poll_id = p_poll_id
        ), '[]'::jsonb)
      )
      FROM chat_polls p WHERE p.id = p_poll_id
    );
END;
$$ LANGUAGE plpgsql STABLE;
