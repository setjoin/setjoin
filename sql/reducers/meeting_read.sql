-- meeting_read.sql: Meet B1 Task 10 — the read-only jsonb projections
-- behind the GET surface (list/detail/slug-resolve). B2 Task 4 extends both
-- projections with recordingActive (the D5 "rides EVERY admission
-- envelope" rule) and meeting_get with recordings[]/attendance[]. B2
-- Task 10 step 0 adds meeting_get's recordingEnabled (the "is recording
-- available at all" signal the ControlsBar button hides on). B3 Task 7
-- step 0 adds meeting_get's breakoutsEnabled/breakouts/myBreakoutId — the
-- BreakoutsPanel's read side. breakoutsEnabled is the recordingEnabled
-- genre (button-visibility signal). breakouts[] is ALWAYS present
-- (anti-oracle) for ANY participant (host/cohost/member) — open rows
-- {breakoutId, idx, title}, title NULL for a client-rendered default
-- (D5) — and EMPTY for a non-participant. Each row ADDITIONALLY carries
-- an 'assignees' key ({identity, displayName}[]) ONLY when the caller is
-- host/cohost — a plain member's row has no such key at all (not merely
-- an empty array) in THIS READ envelope. The real property this withholds
-- is narrower than "a member can never learn who else is assigned": the
-- breakout_assigned push (notify_meet_state, meeting_breakout.sql)
-- broadcasts {identity, breakoutId} to every live member of the meeting on
-- every assign, by accepted design (plan delta 1) — a member who is
-- present for the push already learns exactly that. What this key
-- withholds is a member's ability to RECONSTRUCT the roster from a bare
-- meeting_get poll (a late joiner, or a member who missed pushes) — the
-- assignees array is a read-side aggregate no member-role caller gets, not
-- an org-wide secret.
-- myBreakoutId is the caller's own meeting_participants.breakout_id — NULL
-- when unassigned, non-participant, or a roaming host/cohost (D7: host/
-- cohost are never assigned a breakout_id). B3 Task 13 adds meeting_get's
-- captionsEnabled (the recordingEnabled/breakoutsEnabled toggle-read genre)
-- and captionsOn (COALESCE((m.settings->>'captionsOn')::boolean, false)) —
-- the ControlsBar chip's read side, paired with meeting_captions_set
-- (meeting_control.sql).
--
--
-- (eng retro finding #9a: the header above must stay bare
-- space-separated function names, no comma, no trailing prose — reload-
-- reducers.sh's parser splits on whitespace only, so a comma-suffixed or
-- prose-carrying token like "meeting_recording_active," or "(both" is
-- silently dropped from the topo sort, never even attempted as a lookup
-- failure. meeting_recording_active/meeting_attendee_role are actually
-- defined in V129__meet_recording.sql — schema, not a reducer file — so
-- this header is inert for the topo sort either way (reload-reducers.sh
-- only resolves deps against sql/reducers/*.sql); kept here for
-- readability/documentation, not enforcement.)
--
-- BZ block (meet = BZ185-190, this file's slice): BZ185 meeting/slug not
-- found.
--
-- recordings[]/attendance[]/banned[] (A/B leftover item 1) are gated by
-- meeting_attendee_role, NOT meeting_member_role — its left_at IS NULL
-- filter meets meeting-end's mass-stamp AND meeting_kick's own left_at
-- stamp, so a banned identity would otherwise be invisible to this read
-- the instant it's kicked (spec §4 §B2). All three arrays follow the
-- existing pendingJoinRequests anti-oracle shape: the key is ALWAYS
-- present, populated only for an authorized caller, an empty array (never
-- an absent key) for everyone else — an unauthorized caller must never be
-- able to tell "nothing to show" from "not allowed to see".
--
-- Read posture (locked design choice): ordinary members mirror the org-open
-- JOIN posture. Guest G3 scopes numeric-id reads to channel/participant/knock
-- state, while exact high-entropy slug possession remains a prejoin-only
-- capability. Any ordinary authenticated org user may look up by id or slug,
-- including an ended one (so a stale deep link can render "Meeting ended"
-- instead of erroring). This is the same id-enumerable surface the join
-- route already exposes; a pre-join screen needs to show title/locked
-- state before the caller decides whether to join or knock. `roomName` is
-- already exposed to any joiner via the join grant spec, so including it
-- here is not a new leak.
--
-- meeting_list is the one narrower query — "my meetings" (owner or
-- participant), matching the HTTP surface's own wording; it is the sole
-- reducer here that filters by p_user_id in R1's sense (an ownership/
-- membership WHERE clause). meeting_get/_by_slug instead use p_user_id only
-- to compute myRole and to gate pendingJoinRequests visibility.

-- Guest G3 scope helpers. Join authority is deliberately narrower than read
-- authority: a current channel membership, ownership, or an admitted authed
-- knock permits a token; numeric-id reads additionally permit an existing
-- participant row or any authenticated knock owned by the caller. DEFINER is
-- required for the join-request arm under FORCE RLS (ordinary participants
-- cannot SELECT meeting_join_requests directly).
CREATE OR REPLACE FUNCTION meeting_guest_join_allowed(
    p_user_id bigint, p_meeting_id bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1
          FROM meetings m
         WHERE m.id = p_meeting_id
           AND (
               m.owner_user_id = p_user_id
               OR (m.chat_channel_id IS NOT NULL AND EXISTS (
                   SELECT 1 FROM chat_channel_members cm
                    WHERE cm.channel_id = m.chat_channel_id
                      AND cm.user_id = p_user_id
               ))
               OR EXISTS (
                   SELECT 1 FROM meeting_join_requests r
                    WHERE r.meeting_id = m.id
                      AND r.user_id = p_user_id
                      AND r.state = 'admitted'
               )
           )
    );
$$;
SELECT apply_worker_ownership('meeting_guest_join_allowed(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION meeting_guest_read_allowed(
    p_user_id bigint, p_meeting_id bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT meeting_guest_join_allowed(p_user_id, p_meeting_id)
       OR EXISTS (
           SELECT 1 FROM meeting_participants p
            WHERE p.meeting_id = p_meeting_id AND p.user_id = p_user_id
       )
       OR EXISTS (
           SELECT 1 FROM meeting_join_requests r
            WHERE r.meeting_id = p_meeting_id AND r.user_id = p_user_id
       );
$$;
SELECT apply_worker_ownership('meeting_guest_read_allowed(bigint,bigint)'::regprocedure);

-- meeting_list: owner or participant, excluding a meeting that both ended
-- AND ended more than 24h ago (the "declutter old huddles" rule; a
-- recently-ended meeting still shows with state='ended' so the client can
-- render an Ended badge, spec Task 16).
CREATE OR REPLACE FUNCTION meeting_list(p_user_id bigint) RETURNS jsonb AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'meetingId', m.id, 'slug', m.slug, 'title', m.title,
             'roomName', m.room_name,
             'state', m.state, 'locked', m.locked,
             'guestAllowed', COALESCE((m.settings ->> 'guestAllowed')::boolean, false),
             'scheduledStart', m.scheduled_start, 'scheduledEnd', m.scheduled_end,
             'chatChannelId', m.chat_channel_id, 'calendarEventId', m.calendar_event_id,
             'ownerUserId', m.owner_user_id, 'createdAt', m.created_at, 'endedAt', m.ended_at,
             'myRole', meeting_member_role(m.id, p_user_id),
             'recordingActive', meeting_recording_active(m.id)
           ) ORDER BY m.created_at DESC), '[]'::jsonb)
      FROM meetings m
     WHERE (m.owner_user_id = p_user_id
            OR EXISTS (SELECT 1 FROM meeting_participants p
                        WHERE p.meeting_id = m.id AND p.user_id = p_user_id))
       AND NOT (m.state = 'ended' AND m.ended_at < now() - interval '24 hours');
$$ LANGUAGE sql STABLE;

-- meeting_get: detail by id. pendingJoinRequests is ALWAYS present as a
-- jsonb array key but populated ONLY for a host/cohost caller — an empty
-- array for anyone else, never an absent-vs-empty distinguishing signal
-- (the same anti-oracle instinct as BZ185/BZ170 elsewhere: a non-privileged
-- caller cannot tell "no pending requests" from "not authorized to see
-- them").
CREATE OR REPLACE FUNCTION meeting_get_projection(
    p_user_id bigint, p_meeting_id bigint, p_slug_scope text
) RETURNS jsonb AS $$
DECLARE
    v_role text;
    v_out  jsonb;
    v_related boolean;
BEGIN
    IF is_guest_account(p_user_id) THEN
        PERFORM guest_require_active(p_user_id);
        IF NOT check_user_app_entitlement(p_user_id, 'meet') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
        -- A high-entropy slug is a pre-join capability only. It permits this
        -- projection (needed to show the title/recording disclosure and knock)
        -- but never reaches meeting_join's token authority.
        IF NOT meeting_guest_read_allowed(p_user_id, p_meeting_id)
           AND NOT EXISTS (
               SELECT 1 FROM meetings m
                WHERE m.id = p_meeting_id AND m.slug = p_slug_scope
           ) THEN
            RAISE EXCEPTION 'meeting not found'
                USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
        END IF;
    END IF;

    v_role := meeting_member_role(p_meeting_id, p_user_id);
    -- #378 (owner-approved security fix 2026-11-05): an unrelated caller (not the owner, a participant,
    -- a bound-channel member, nor a knocker) still gets the pre-join facts (title, state, locked, ...) but not the
    -- identifiers that are join/ownership capabilities: roomName, ownerUserId, chatChannelId and calendarEventId (#531) are NULL, and slug is returned
    -- only when the caller resolved it by that very slug. Join stays org-open by id (ratified); this closes
    -- the metadata disclosure of other users' meetings, not the join posture.
    v_related := meeting_guest_read_allowed(p_user_id, p_meeting_id);
    SELECT jsonb_build_object(
             'meetingId', m.id,
             'slug', CASE WHEN v_related OR p_slug_scope IS NOT NULL THEN m.slug END,
             'title', m.title,
             'roomName', CASE WHEN v_related THEN m.room_name END,
             'state', m.state, 'locked', m.locked,
             'guestAllowed', COALESCE((m.settings ->> 'guestAllowed')::boolean, false),
             'scheduledStart', m.scheduled_start, 'scheduledEnd', m.scheduled_end,
             'chatChannelId', CASE WHEN v_related THEN m.chat_channel_id END,
             'calendarEventId', CASE WHEN v_related THEN m.calendar_event_id END,
             'ownerUserId', CASE WHEN v_related THEN m.owner_user_id END, 'createdAt', m.created_at, 'endedAt', m.ended_at,
             'myRole', v_role,
             -- Huddle Slack semantics (pipeline review fix): whether the
             -- CALLER is actually a member of the bound chat channel — a
             -- huddle joiner can have chatChannelId set (they joined the
             -- MEETING) without ever gaining channel membership (V131).
             -- Always present, false when there is no bound channel at all.
             'chatChannelMember', (m.chat_channel_id IS NOT NULL AND EXISTS (
               SELECT 1 FROM chat_channel_members ccm
                WHERE ccm.channel_id = m.chat_channel_id AND ccm.user_id = p_user_id
             )),
             -- Task 10 step 0: the button-visibility signal — recording
             -- needs BOTH feature.meet_recording and feature.drive ON (spec
             -- header). A 503 (egress down) on click still surfaces as a
             -- toast; this key only hides the button when recording cannot
             -- possibly work.
             'recordingEnabled',
               COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.meet_recording'), false)
               AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'), false),
             -- Task 7 step 0: the BreakoutsPanel button-visibility signal.
             'breakoutsEnabled',
               COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.meet_breakouts'), false),
             -- Task 13: the captions button-visibility signal — the
             -- recordingEnabled/breakoutsEnabled toggle-read genre verbatim.
             'captionsEnabled',
               COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.meet_captions'), false),
             -- captionsOn: the live on/off flag driving the ControlsBar chip
             -- and the client's cc: data-channel render gate (F8).
             'captionsOn',
               COALESCE((m.settings ->> 'captionsOn')::boolean, false),
             -- breakouts[]: ALWAYS present (anti-oracle) — populated for ANY
             -- participant (v_role IS NOT NULL), empty for a non-participant.
             -- Each row's 'assignees' key exists ONLY for host/cohost —
             -- jsonb || merges it in; '{}'::jsonb || X is a no-op so a plain
             -- member's row stays exactly {breakoutId, idx, title}.
             'breakouts',
               CASE WHEN v_role IS NOT NULL THEN (
                 SELECT COALESCE(jsonb_agg(
                          jsonb_build_object('breakoutId', b.id, 'idx', b.idx, 'title', b.title)
                          || CASE WHEN v_role IN ('host', 'cohost') THEN
                               jsonb_build_object('assignees', (
                                 SELECT COALESCE(jsonb_agg(jsonb_build_object(
                                          'identity', p2.identity,
                                          'displayName', COALESCE(u2.display_name, p2.guest_display_name, p2.identity)
                                        ) ORDER BY p2.id), '[]'::jsonb)
                                   FROM meeting_participants p2
                                   LEFT JOIN users u2 ON u2.id = p2.user_id
                                  WHERE p2.meeting_id = m.id AND p2.breakout_id = b.id))
                             ELSE '{}'::jsonb END
                        ORDER BY b.idx), '[]'::jsonb)
                   FROM meeting_breakouts b
                  WHERE b.meeting_id = m.id AND b.state = 'open'
               ) ELSE '[]'::jsonb END,
             -- myBreakoutId: the caller's own assignment (NULL when
             -- unassigned, non-participant, or a roaming host/cohost).
             'myBreakoutId',
               (SELECT p3.breakout_id FROM meeting_participants p3
                 WHERE p3.meeting_id = m.id AND p3.identity = 'u:' || p_user_id),
             'pendingJoinRequests',
               CASE WHEN v_role IN ('host', 'cohost') THEN (
                 SELECT COALESCE(jsonb_agg(jsonb_build_object(
                          'requestId', r.id, 'displayName', r.display_name,
                          'isMemberKnock', r.user_id IS NOT NULL,
                          'createdAt', r.created_at, 'expiresAt', r.expires_at
                        ) ORDER BY r.created_at), '[]'::jsonb)
                   FROM meeting_join_requests r
                  WHERE r.meeting_id = m.id AND r.state = 'pending')
               ELSE '[]'::jsonb END,
             'recordingActive', meeting_recording_active(m.id),
             -- M2 (V265): the presentation button-visibility signal (the
             -- recordingEnabled genre — presentation needs BOTH
             -- feature.meet_document_presentation AND feature.drive ON,
             -- the toggle's own dependency pair) + the live-session
             -- summary. 'presentation' is ALWAYS present as a key:
             -- populated ONLY for a current participant (the same
             -- anti-oracle posture as breakouts[]), NULL for a
             -- non-participant. It carries exactly the committed
             -- checkpoint facts a late joiner validates against — never
             -- page bytes, notes, or source-derived content.
             'presentationEnabled',
               COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.meet_document_presentation'), false)
               AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'), false),
             'presentation',
               CASE WHEN v_role IS NOT NULL THEN (
                 SELECT jsonb_build_object(
                          'presentationId', mp.id, 'status', mp.status,
                          'checkpointSeq', mp.checkpoint_seq,
                          'presenterGeneration', mp.presenter_generation,
                          'presenterParticipantId', mp.presenter_participant_id,
                          'pageIndex', mp.page_index,
                          'manifestGeneration', mp.manifest_generation,
                          'manifestDigest', mp.manifest_digest,
                          'driveNodeId', mp.drive_node_id,
                          'driveVersionId', mp.drive_version_id)
                   FROM meeting_presentations mp
                  WHERE mp.meeting_id = m.id
                    AND mp.status IN ('PREPARING','READY','ACTIVE','DEGRADED')
                  ORDER BY mp.id DESC LIMIT 1)
               ELSE NULL END,
             'recordings',
               CASE WHEN meeting_attendee_role(m.id, p_user_id) IS NOT NULL THEN (
                 SELECT COALESCE(jsonb_agg(jsonb_build_object(
                          'recordingId', r.id, 'state', r.state,
                          'startedAt', r.started_at, 'stoppedAt', r.stopped_at,
                          'durationMs', r.duration_ms, 'sizeBytes', r.size_bytes,
                          'versionId', r.version_id, 'fileNodeId', r.file_node_id,
                          'error', r.error
                        ) ORDER BY r.id), '[]'::jsonb)
                   FROM meeting_recordings r WHERE r.meeting_id = m.id)
               ELSE '[]'::jsonb END,
             'attendance',
               CASE WHEN meeting_attendee_role(m.id, p_user_id) IN ('host', 'cohost') THEN (
                 SELECT COALESCE(jsonb_agg(jsonb_build_object(
                          'identity', p.identity,
                          -- never blank: displayName falls back to identity last.
                          'displayName', COALESCE(u.display_name, p.guest_display_name, p.identity),
                          'role', p.role, 'isGuest', p.user_id IS NULL,
                          'joinedAt', p.joined_at, 'leftAt', p.left_at
                        ) ORDER BY p.joined_at NULLS LAST, p.id), '[]'::jsonb)
                   FROM meeting_participants p
                   LEFT JOIN users u ON u.id = p.user_id
                  WHERE p.meeting_id = m.id)
               ELSE '[]'::jsonb END,
             -- A/B leftover item 1: banned[] — the durable re-admit-list
             -- projection (5ae8e665's webmail fix had to fall back to a
             -- session-only push-built map for lack of this). Same
             -- gate/shape as attendance[] (host/cohost attendee-only,
             -- meeting_attendee_role — the historical-row helper, so a host
             -- who has since left still sees who they banned).
             -- Deliberately narrower than the V134 RLS self-arm: a banned
             -- participant may SELECT their OWN meeting_participants row
             -- under RLS, but this JSON projection never leaks the FULL
             -- list to a non-host/cohost caller — the same anti-oracle
             -- posture as pendingJoinRequests/attendance.
             'banned',
               CASE WHEN meeting_attendee_role(m.id, p_user_id) IN ('host', 'cohost') THEN (
                 SELECT COALESCE(jsonb_agg(jsonb_build_object(
                          'identity', p.identity,
                          'displayName', COALESCE(u.display_name, p.guest_display_name, p.identity),
                          'bannedAt', p.banned_at
                        ) ORDER BY p.banned_at), '[]'::jsonb)
                   FROM meeting_participants p
                   LEFT JOIN users u ON u.id = p.user_id
                  WHERE p.meeting_id = m.id AND p.banned_at IS NOT NULL)
               ELSE '[]'::jsonb END
           ) INTO v_out
      FROM meetings m WHERE m.id = p_meeting_id;

    IF v_out IS NULL THEN
        RAISE EXCEPTION 'meeting % not found', p_meeting_id
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_out;
END;
$$ LANGUAGE plpgsql STABLE;

-- Numeric-id detail keeps the member org-open posture, while guest callers
-- get no slug capability and therefore must satisfy the scoped helper above.
CREATE OR REPLACE FUNCTION meeting_get(
    p_user_id bigint, p_meeting_id bigint
) RETURNS jsonb AS $$
    SELECT meeting_get_projection(p_user_id, p_meeting_id, NULL);
$$ LANGUAGE sql STABLE;

-- meeting_get_by_slug: the member deep-link resolve (GET /meet/by-slug/{slug}).
-- Same projection as meeting_get, resolved by slug instead of id.
CREATE OR REPLACE FUNCTION meeting_get_by_slug(p_user_id bigint, p_slug text) RETURNS jsonb AS $$
DECLARE
    v_meeting_id bigint;
BEGIN
    SELECT id INTO v_meeting_id FROM meetings WHERE slug = p_slug;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'meeting not found'
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;
    RETURN meeting_get_projection(p_user_id, v_meeting_id, p_slug);
END;
$$ LANGUAGE plpgsql STABLE;
