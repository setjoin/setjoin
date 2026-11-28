-- notify_meet_state.sql: the meet push seam (Meet B1 Task 3). Fans out to
-- each live member's self-scoped meet:{user_id} channel — the
-- notify_chat_state shape (drive-watch/chat self-channel pattern, fourth
-- use). Guests (user_id IS NULL) are never fan-out targets: they poll the
-- public join-request surface instead (meeting_join_request_poll).
--
--
-- p_meeting_id — the meetings.id whose participant set defines the fan-out.
--   Required (BZ188 on NULL) — there is no meeting-less push.
-- p_event       — the event name ('meeting_created' | 'meeting_state' |
--   'join_request_created' | 'join_request_decided' | 'participant_role' |
--   'participant_kicked' | 'recording_state' | 'recording_ready' — the
--   latter two added by Meet B2, meeting_recording.sql — | 'breakout_opened'
--   | 'breakout_assigned' | 'breakout_closed', added by Meet B3,
--   meeting_breakout.sql/meeting_control.sql/meeting_participant_event.sql;
--   breakout_assigned is targeted-by-payload, not per-user push — no
--   per-user targeting mechanism exists here, so the payload carries
--   {identity, breakoutId} and clients act when identity is self, the
--   participant_kicked genre), preserved verbatim in the payload — |
--   'captions_state' (Meet B3 Task 13, meeting_control.sql's
--   meeting_captions_set) — payload {on, botIdentity:'cc:'||meetingId}, an
--   ordinary all-live-members fan-out (no per-user targeting, unlike
--   breakout_assigned — every member renders the same captions chip). — |
--   'presentation_state' (MEET plan M2, meeting_presentation.sql/V265) —
--   payload {presentationId, status, checkpointSeq, presenterGeneration,
--   pageIndex, manifestGeneration[, driveNodeId, driveVersionId]}, an
--   ordinary all-live-members fan-out: every attendee sees the same stage
--   chip, and a fresh checkpointSeq is exactly the bounded invalidation
--   hint the client's coalesced checkpoint refresh (M1 CheckpointRefresher)
--   admits — never a state promotion (the M0 receive contract).
-- p_payload     — event-specific detail (e.g. {"locked":true} for
--   meeting_state); NULL for events that carry no extra detail.
-- p_roles       — when given, restricts fan-out to participants whose OWN
--   role is in this array (e.g. '{host,cohost}' for join_request_created,
--   so a plain member never sees another guest's knock).
--
-- ponytail: O(participants) in the write txn, same ceiling as
-- notify_chat_state; move to channel-scoped WS subscriptions if a
-- deployment's meeting size ever makes this the bottleneck.
CREATE OR REPLACE FUNCTION notify_meet_state(
    p_meeting_id bigint, p_event text,
    p_payload jsonb DEFAULT NULL, p_roles text[] DEFAULT NULL
) RETURNS void AS $$
DECLARE
    v_user_id bigint;
    v_payload text;
BEGIN
    IF p_meeting_id IS NULL THEN
        RAISE EXCEPTION 'notify_meet_state requires a meeting'
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"meeting_id required"}';
    END IF;
    v_payload := jsonb_build_object('event', p_event, 'meetingId', p_meeting_id,
                                     'payload', p_payload)::text;
    FOR v_user_id IN
        SELECT user_id FROM public.meeting_participants
         WHERE meeting_id = p_meeting_id AND user_id IS NOT NULL AND left_at IS NULL
           AND (p_roles IS NULL OR role = ANY (p_roles))
    LOOP
        PERFORM app_notify('meet:' || v_user_id, v_payload);
    END LOOP;
END; $$ LANGUAGE plpgsql;
