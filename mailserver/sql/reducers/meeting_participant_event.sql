--
-- meeting_participant_event.sql: Meet B1 Task 6 — the webhook-fact ingest
-- (C0 spike §2 finding 2: webhooks are facts, NEVER authorization). Called
-- ONLY from the LiveKit webhook receiver (Task 12 — which runs on the APP
-- pool, internal/meet/webhook.go) and the reconcile worker's lost-webhook
-- GC leg (workerPool) — no caller identity, no authority check, and it must
-- never raise: a raise 500s a retried webhook, and LiveKit will just retry
-- the same 500 forever.
--
-- SECURITY DEFINER + worker-owned (V134 / native-RLS W4 wave — the
-- meeting_lobby.sql create/poll precedent verbatim): the webhook surface has
-- NO caller GUC, so no invoker-rights policy can ever admit its writes under
-- the flipped setjoin_app posture. Safe as DEFINER because the reducer
-- self-scopes by the server-resolved room_name (never a caller identity)
-- and only projects loss-tolerant SFU facts. Pinned search_path per
-- ARCH-018 (the classic DEFINER escalation foot-gun).
--
-- Loss-tolerant + idempotent throughout: an unknown room, an unknown
-- identity, or an already-applied transition is a silent no-op, not an
-- error — retried/out-of-order webhook delivery is the expected case here,
-- not a fault. Emits notify_meet_state ONLY on a real state transition
-- (idempotent replays stay silent, matching every other meet reducer's
-- push contract).
CREATE OR REPLACE FUNCTION meeting_participant_event(
    p_room_name uuid, p_event text, p_identity text DEFAULT NULL,
    p_at timestamptz DEFAULT now()
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_meeting_id  bigint;
    v_state       text;
    v_breakout_id bigint;
    v_rec_flip    RECORD;
BEGIN
    -- B3: resolve parent OR child room (spec §4.1 — meetings.room_name UNION
    -- meeting_breakouts.room_name). v_breakout_id NULL ⇒ the event is about
    -- the parent room.
    SELECT id, state, NULL::bigint INTO v_meeting_id, v_state, v_breakout_id
      FROM meetings WHERE room_name = p_room_name;
    IF NOT FOUND THEN
        SELECT b.meeting_id, m.state, b.id INTO v_meeting_id, v_state, v_breakout_id
          FROM meeting_breakouts b JOIN meetings m ON m.id = b.meeting_id
         WHERE b.room_name = p_room_name;
        IF NOT FOUND THEN
            RETURN; -- unknown room: webhook noise about a room we didn't create
        END IF;
    END IF;

    IF p_event = 'participant_joined' THEN
        -- banned_at IS NULL guards against un-kicking a banned participant:
        -- a retried/out-of-order participant_joined (LiveKit retries
        -- webhooks; delivery is unordered and not guaranteed) must never
        -- restore authorization a reducer already revoked (spike §2 finding
        -- 2 — webhooks are facts, never authorization; meeting_member_role
        -- derives role from left_at IS NULL, so clearing it un-kicks the
        -- caller on the control plane). v_state <> 'ended' guards against
        -- resurrecting a ghost participant into a meeting that already
        -- concluded.
        UPDATE meeting_participants
           SET joined_at = COALESCE(joined_at, p_at), left_at = NULL
         WHERE meeting_id = v_meeting_id AND identity = p_identity
           AND banned_at IS NULL AND v_state <> 'ended';
        -- unknown identity, a banned identity, or an ended meeting: silent
        -- no-op; the reconcile sweep self-heals unknown-identity races.

    ELSIF p_event = 'participant_left' THEN
        -- B3 (§4.1, do not "simplify" this back): left_at stamps ONLY when
        -- the leave comes from the room the participant is currently
        -- ASSIGNED to (assignment is reducer truth, updated before the
        -- eviction fires). A leave from any other room is expected move
        -- churn → silent no-op. Both webhook orderings of a move are
        -- pgTAP-pinned (meet_breakouts.pg).
        UPDATE meeting_participants p
           SET left_at = COALESCE(p.left_at, p_at)
         WHERE p.meeting_id = v_meeting_id AND p.identity = p_identity
           AND ((v_breakout_id IS NULL AND p.breakout_id IS NULL)
             OR p.breakout_id = v_breakout_id);

    ELSIF p_event = 'room_started' THEN
        -- a child room going live never flips meeting state.
        UPDATE meetings SET state = 'live'
         WHERE id = v_meeting_id AND state = 'scheduled' AND v_breakout_id IS NULL;
        IF FOUND THEN
            PERFORM notify_meet_state(v_meeting_id, 'meeting_state', jsonb_build_object('state', 'live'));
        END IF;
        -- an already-live or already-ended meeting: no-op (never re-flips
        -- ended back to live).

    ELSIF p_event = 'room_finished' AND v_breakout_id IS NOT NULL THEN
        -- D12 accept-as-close: a child room_finished while its row is still
        -- 'open' is a breakout-close FACT for THAT one row (idempotent,
        -- never a meeting end) — the SFU never self-finishes an open
        -- breakout in practice (D12's pinned generous 86400/86400 params),
        -- but a lost/late webhook or a stray SFU housekeeping finish must
        -- still be absorbed honestly instead of leaving the row stuck open.
        UPDATE meeting_breakouts SET state = 'closed', closed_at = p_at
         WHERE id = v_breakout_id AND state = 'open';
        IF FOUND THEN
            UPDATE meeting_participants SET breakout_id = NULL
             WHERE breakout_id = v_breakout_id;
            PERFORM notify_meet_state(v_meeting_id, 'breakout_closed',
                                       jsonb_build_object('breakoutId', v_breakout_id));
        END IF;
        -- an already-closed child row: silent no-op (idempotent replay).

    ELSIF p_event = 'room_finished' THEN
        -- the meeting_end projection, without requiring a caller (idempotent
        -- replay-safe: a retried room_finished re-applies to no effect once
        -- the meeting is already 'ended').
        IF v_state <> 'ended' THEN
            UPDATE meetings SET state = 'ended', ended_at = COALESCE(ended_at, p_at)
             WHERE id = v_meeting_id;

            -- B3: mirror meeting_end's close-breakouts arm (same two
            -- statements) — the parent room ending drops every child too.
            UPDATE meeting_breakouts SET state = 'closed', closed_at = p_at
             WHERE meeting_id = v_meeting_id AND state = 'open';
            IF FOUND THEN
                UPDATE meeting_participants SET breakout_id = NULL
                 WHERE meeting_id = v_meeting_id AND breakout_id IS NOT NULL;
                PERFORM notify_meet_state(v_meeting_id, 'breakout_closed', NULL);
            END IF;

            -- B2 law 1 mirror (the meeting_end two-branch flip, verbatim):
            -- only a bound row may enter 'stopping' — an unbound 'requested'
            -- row goes straight to 'failed' with its own banner-off push
            -- (eng E-F2 / plan delta 11, the same wedge-4 fix as meeting_end).
            FOR v_rec_flip IN
                WITH flipped AS (
                    UPDATE meeting_recordings
                       SET state = CASE WHEN state = 'active' OR egress_id IS NOT NULL
                                        THEN 'stopping' ELSE 'failed' END,
                           stopped_at = CASE WHEN state = 'requested' AND egress_id IS NULL
                                             THEN p_at ELSE stopped_at END,
                           error = CASE WHEN state = 'requested' AND egress_id IS NULL
                                        THEN 'meeting ended before egress bind' ELSE error END
                     WHERE meeting_id = v_meeting_id AND state IN ('requested', 'active')
                     RETURNING id, state
                )
                SELECT id FROM flipped WHERE state = 'failed'
            LOOP
                PERFORM notify_meet_state(v_meeting_id, 'recording_state',
                    jsonb_build_object('recordingId', v_rec_flip.id, 'state', 'failed'));
            END LOOP;

            -- Emit BEFORE stamping left_at: notify_meet_state's fan-out
            -- filters WHERE left_at IS NULL, so firing after the mass-stamp
            -- below reaches zero recipients by construction — the terminal
            -- push must go out while the recipient set is still live.
            PERFORM notify_meet_state(v_meeting_id, 'meeting_state', jsonb_build_object('state', 'ended'));
            UPDATE meeting_participants SET left_at = COALESCE(left_at, p_at)
             WHERE meeting_id = v_meeting_id AND left_at IS NULL;
            UPDATE meeting_join_requests SET state = 'expired'
             WHERE meeting_id = v_meeting_id AND state = 'pending';
        END IF;

    END IF;
    -- an unrecognized p_event (B2's egress_* events, or anything else the
    -- SFU ever adds): silent no-op — Go only forwards the event names it
    -- knows, but a webhook body is untrusted input; never raise on it.
    -- egress_* events ride meeting_recording_event, not this reducer.
END;
$$;
SELECT apply_worker_ownership('meeting_participant_event(uuid,text,text,timestamptz)'::regprocedure);
