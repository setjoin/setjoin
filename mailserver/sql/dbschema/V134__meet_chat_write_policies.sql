-- V134__meet_chat_write_policies.sql — native-RLS W4 write-policy wave for
-- the meet + chat table families (the B1 live-gate flip blocker: under the
-- flipped runtime posture — setjoin_app, NOBYPASSRLS — meeting_participants/
-- meeting_join_requests/meeting_breakouts/meeting_recordings carried
-- SELECT-only policies and meetings/chat_channels had NO UPDATE policy, so
-- every Meet write (join/lock/kick/end) and chat's change_seq send rail were
-- inoperable; meeting_create 500'd live. TODOS.md "Meet B1" ledger item 1;
-- docs/superpowers/plans/archive/2026-06-18-native-rls-backstop.md W4).
--
-- Every membership/role check below routes through the SECURITY DEFINER
-- scope helpers (meeting_member_role / meeting_attendee_role /
-- chat_member_role — ARCH-018's recipe; an inline membership subquery on a
-- policy-protected table is the FORCE-RLS recursion trap). The auth-context
-- GUC is the V114 convention, written out verbatim each time:
--   (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
-- Fail-closed: no GUC ⇒ NULL ⇒ every arm below is false.
--
-- Role-ladder posture (deliberate, matches V119's chat_members_scope): these
-- policies are the TENANT-ISOLATION backstop (R4), not a re-implementation
-- of the in-reducer RBAC ladder (ARCH-006 app-level-primary). A self-scoped
-- arm admits the caller's own row without re-deriving the role vocabulary;
-- host/cohost arms bound who can touch OTHER participants' rows.
--
-- Four reducer-side SECURITY DEFINER conversions ship WITH this wave (in
-- sql/reducers/, not here — reducer reload would overwrite a migration-side
-- redefinition), each per the "legitimately cannot pass any sane policy"
-- criterion:
--   · meeting_participant_event + meeting_recording_event (the
--     meeting_lobby.sql create/poll precedent, verbatim): both are called
--     from the LiveKit webhook receiver, which runs on the APP pool with NO
--     caller GUC (internal/meet/webhook.go — a webhook has no user), so no
--     invoker-rights policy can ever admit them; both self-scope by
--     server-resolved room_name/egress_id (never caller identity) and are
--     loss-tolerant fact ingests, DES-011's "webhooks are facts, never
--     authorization".
--   · chat_dm_open: writes the OTHER founding members' rows (cross-member
--     inserts the owner/admin-or-self WITH CHECK can never admit — a DM
--     member's role is plain 'member').
--   · chat_member_remove: the Q7 owner-succession promote runs AFTER the
--     departing last owner deleted their own membership — under invoker
--     rights it silently no-ops and orphans the channel.
--
-- Worker-path surfaces deliberately get NO policies (BYPASSRLS workerPool):
-- chat_purge_expired, chat push/notify drains, meet worker reconcile legs,
-- meeting_recording_ingested, meeting_requests_expire, scheduled_actions
-- dispatch, admin consoles (admin_chat_compliance/admin_meet_recordings —
-- already on workerPool). Deny-all tables stay deny-all: chat_audit_log /
-- chat_case_holds / chat_case_hold_channels / chat_ediscovery_searches /
-- chat_link_previews (DEFINER writers already exist for each).

-- ══════════════════════════════════════════════════════════════════════════
-- §A — meetings: org-open SELECT + owner/host-cohost UPDATE.
--
-- SELECT: the read posture is LOCKED org-open (meeting_read.sql's header,
-- gate-ratified 2026-07-12 with the org-open join posture): any
-- authenticated org user may look up any meeting by id or slug, INCLUDING an
-- ended one (a stale deep link renders "Meeting ended"); roomName is already
-- exposed to any joiner via the grant spec. The old member/owner-only policy
-- contradicted that posture and broke meeting_join's pre-membership read
-- (org-open join: the joiner is BY DESIGN not yet a participant). Guests
-- never reach this surface (no GUC ⇒ denied; they ride the DEFINER lobby).
-- ══════════════════════════════════════════════════════════════════════════
DROP POLICY meetings_read ON public.meetings;
CREATE POLICY meetings_read ON public.meetings FOR SELECT TO public
  USING ((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint) IS NOT NULL);

-- UPDATE: owner arm is load-bearing for meeting_create's chat-bind UPDATE
-- (it runs BEFORE the creator's host participant row is inserted — the
-- f59bc436 ordering, so meeting_member_role is still NULL at that point);
-- host/cohost covers lock / set_guest_allowed / captions_set / end.
-- No DELETE policy: meetings are never hard-deleted (FORCE denies).
CREATE POLICY meetings_update ON public.meetings FOR UPDATE TO public
  USING (owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR meeting_member_role(id,
          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'))
  WITH CHECK (owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR meeting_member_role(id,
          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));

-- ══════════════════════════════════════════════════════════════════════════
-- §B — meeting_participants: SELECT breadth + self/host-cohost writes.
--
-- SELECT gains two arms the old live-member-only policy was missing:
--   · self (user_id = guc, NO liveness filter): meeting_join's ban check and
--     rejoin upsert read the caller's OWN row when it is banned/left (both
--     make meeting_member_role return NULL); meeting_list's participant arm
--     must still match after meeting_end's left_at mass-stamp.
--   · attendee (meeting_attendee_role — ARCH-018 row 6): post-end reads
--     (meeting_get's attendance/recordings legs) are dead under
--     meeting_member_role's left_at filter by construction.
-- ══════════════════════════════════════════════════════════════════════════
DROP POLICY meeting_participants_scope ON public.meeting_participants;
CREATE POLICY meeting_participants_scope ON public.meeting_participants FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR meeting_attendee_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- INSERT: self covers meeting_join's org-open upsert and meeting_create's
-- own host row; host/cohost covers meeting_admit (guest rows user_id IS
-- NULL, and knock-admitted members' rows — both created FOR another party).
CREATE POLICY meeting_participants_insert ON public.meeting_participants FOR INSERT TO public
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR meeting_member_role(meeting_id,
          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));

-- UPDATE: self covers the rejoin left_at clear (ON CONFLICT DO UPDATE on the
-- caller's own historical row); host/cohost covers set_role (re-admit),
-- kick, admit's ON CONFLICT re-admit, breakout assign/auto-assign/close, and
-- meeting_end's left_at mass-stamp (the helper reads the statement-start
-- snapshot, so the host's own row still counts mid-statement).
CREATE POLICY meeting_participants_update ON public.meeting_participants FOR UPDATE TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR meeting_member_role(meeting_id,
          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'))
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     OR meeting_member_role(meeting_id,
          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));
-- No DELETE policy: participant rows are history (kick/leave stamp, never delete).

-- ══════════════════════════════════════════════════════════════════════════
-- §C — meeting_join_requests: host/cohost UPDATE (the decide surface —
-- admit/deny, kick's guest-deny arm, meeting_end's pending-expiry). INSERT
-- stays policy-less on purpose: the ONLY writers are the DEFINER lobby pair
-- (guest create + member knock) and the worker sweep (BYPASSRLS); the
-- DEFINER poll's lazy clock-expiry UPDATE likewise needs no policy.
-- ══════════════════════════════════════════════════════════════════════════
CREATE POLICY meeting_join_requests_update ON public.meeting_join_requests FOR UPDATE TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'))
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));

-- ══════════════════════════════════════════════════════════════════════════
-- §D — meeting_breakouts: host/cohost INSERT (open) + UPDATE (close;
-- participant_event's accept-as-close arm is DEFINER, worker legs bypass).
-- INSERT..RETURNING in meeting_breakout_open passes the existing member
-- SELECT policy (the opener is a live host). No DELETE policy.
-- ══════════════════════════════════════════════════════════════════════════
CREATE POLICY meeting_breakouts_insert ON public.meeting_breakouts FOR INSERT TO public
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));
CREATE POLICY meeting_breakouts_update ON public.meeting_breakouts FOR UPDATE TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'))
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));

-- ══════════════════════════════════════════════════════════════════════════
-- §E — meeting_recordings: host/cohost writes via meeting_attendee_role
-- (NOT meeting_member_role — a host who already left, or a post-end flip,
-- must still be able to stop/settle a recording; ARCH-018 rows 5/6).
--   · INSERT (meeting_recording_start): started_by pinned to the caller.
--   · UPDATE: meeting_recording_stop, bind_egress (runs in the start
--     route's own request context), and meeting_end's same-txn flip.
-- meeting_recording_event is DEFINER (webhook, see header);
-- meeting_recording_ingested + the reconcile/ingest drains are worker-only
-- (BYPASSRLS). No DELETE policy: a record table never hard-deletes.
-- ══════════════════════════════════════════════════════════════════════════
CREATE POLICY meeting_recordings_insert ON public.meeting_recordings FOR INSERT TO public
  WITH CHECK (started_by = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     AND meeting_attendee_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));
CREATE POLICY meeting_recordings_update ON public.meeting_recordings FOR UPDATE TO public
  USING (meeting_attendee_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'))
  WITH CHECK (meeting_attendee_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));

-- ══════════════════════════════════════════════════════════════════════════
-- §F — chat_channels: member UPDATE. THE send rail: chat_message_send/edit/
-- delete and chat_pin_toggle all bump change_seq under the channel row lock
-- as an ORDINARY MEMBER — so the backstop scope is membership, not
-- owner/admin (rename/archive/permission flips are owner/admin-gated
-- app-level, BZ161; the compliance columns are written only by the DEFINER
-- admin reducers + guarded by the V126 no-downgrade trigger; the purge
-- sweep's last_purged_seq write is worker-only). No DELETE policy: channels
-- are never hard-deleted (archive is an UPDATE; purge destroys messages).
-- ══════════════════════════════════════════════════════════════════════════
CREATE POLICY chat_channels_update ON public.chat_channels FOR UPDATE TO public
  USING (chat_member_role(id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL)
  WITH CHECK (chat_member_role(id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- ══════════════════════════════════════════════════════════════════════════
-- §G — chat_channel_members: two additive arms.
--
-- 1. The Meet↔Chat bridge INSERT arm: meeting_admit auto-adds a
--    knock-admitted MEMBER to the meeting's PROVISIONED channel, and the
--    admitter can be a meeting cohost whose chat role is plain 'member' —
--    the existing chat_members_scope WITH CHECK (channel owner/admin OR
--    self) denies exactly that legitimate write. Scoped hard to the V131
--    bridge shape: provisioned channels only (a huddle bound to a
--    pre-existing channel/DM must never gain members through a meeting),
--    meeting host/cohost only. Policies are permissive, so this ORs with
--    chat_members_scope. Not recursive: meetings' policies never re-enter
--    chat tables, and meeting_member_role is DEFINER.
--
-- 2. A public-channel SELECT arm: chat_browse_channels surfaces memberCount
--    for DISCOVERABLE (public, non-archived) channels to any org user by
--    design (DES-008 — visibility is discovery); the member-only read
--    policy silently zeroed those counts under the flip. Read-only, and
--    scoped to exactly the channel rows the caller can already discover.
-- ══════════════════════════════════════════════════════════════════════════
CREATE POLICY chat_members_meet_bridge ON public.chat_channel_members FOR INSERT TO public
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.meetings m
     WHERE m.chat_channel_id = chat_channel_members.channel_id
       AND m.chat_channel_provisioned
       AND meeting_member_role(m.id,
             (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost')));

CREATE POLICY chat_members_public_read ON public.chat_channel_members FOR SELECT TO public
  USING (EXISTS (
    SELECT 1 FROM public.chat_channels c
     WHERE c.id = chat_channel_members.channel_id
       AND c.kind = 'channel' AND c.visibility = 'public' AND NOT c.is_archived));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (134, now())
    ON CONFLICT (version) DO NOTHING;
