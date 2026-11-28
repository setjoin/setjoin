-- federation_room_remove.sql — Pillar C2 Task 2: the hub channel owner/
-- admin's kick lever (Q3). Sets left_at/left_reason='removed' and appends
-- an OPEN coverage epoch (reason 'removed') on the target — without this a
-- kicked-then-re-admitted member's gap would never reach the Task 8
-- manifest's known-missing intervals; the re-invite UPSERT's trailing-epoch
-- close + gapFrom/gapTo carry + Task 5's local gap-marker message all
-- handle it with zero new machinery once the epoch exists.
--
-- Same lock-order law as federation_room_invite: sorted roster snapshot
-- FIRST (this time INCLUDING the target, since a removal target is by
-- definition still non-left), then the left_at UPDATE, then ONE sorted
-- loop emitting the target's own 'remove' op and everyone else's 'roster'
-- op via federation_room_enqueue_member.
--
-- Refusals (BZ211, this reducer's own family — the same code invite uses
-- for owner/admin, hub-shape, and unknown/already-left-member refusals):
-- owner/admin required; channel not hub-shaped; p_member_domain is not a
-- current (non-left) member of this room.
--
-- The removed member's already-enqueued unacked backlog is NOT reaped (the
-- Q9 amendment) — it drains harmlessly, or goes with the peer entirely via
-- federation_peer_delete's full-reap.
CREATE OR REPLACE FUNCTION federation_room_remove(
    p_user_id      bigint,
    p_channel_id   bigint,
    p_member_domain text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_role     text;
  v_room_id  text;
  v_fed_peer text;
  v_member   text;
  v_snapshot text[];
  v_roster   jsonb;
  v_domain   text;
  v_stanza   text;
  v_payload  jsonb;
BEGIN
  SELECT role INTO v_role FROM chat_channel_members
   WHERE channel_id = p_channel_id AND user_id = p_user_id;
  IF v_role IS NULL OR v_role NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION 'owner/admin required to remove a federated room member'
      USING ERRCODE='BZ211', HINT='{"type":"forbidden","detail":"owner/admin required"}';
  END IF;

  SELECT federated_room_id, federated_peer_domain INTO v_room_id, v_fed_peer
    FROM chat_channels WHERE id = p_channel_id;
  IF v_room_id IS NULL OR v_fed_peer IS NOT NULL THEN
    RAISE EXCEPTION 'channel % is not a federation hub room', p_channel_id
      USING ERRCODE='BZ211', HINT='{"type":"invalidArguments","detail":"channel is not a hub-bound room"}';
  END IF;

  v_member := lower(btrim(COALESCE(p_member_domain, '')));

  -- THE LOCK ORDER LAW: sorted roster snapshot FIRST (see
  -- federation_room_invite.sql's header for the FOR-UPDATE-vs-aggregate
  -- CTE-split reasoning).
  WITH locked AS (
    SELECT member_domain FROM federation_room_members
     WHERE room_id = v_room_id AND left_at IS NULL
     ORDER BY member_domain
     FOR UPDATE
  )
  SELECT array_agg(member_domain ORDER BY member_domain) INTO v_snapshot FROM locked;
  v_snapshot := COALESCE(v_snapshot, '{}');

  IF NOT (v_member = ANY(v_snapshot)) THEN
    RAISE EXCEPTION 'domain % is not a current member of this room', v_member
      USING ERRCODE='BZ211', HINT='{"type":"notFound","detail":"unknown or already-left member"}';
  END IF;

  UPDATE federation_room_members
     SET left_at = now(), left_reason = 'removed',
         coverage_epochs = coverage_epochs || jsonb_build_object('parkedAt', now(), 'reason', 'removed')
   WHERE room_id = v_room_id AND member_domain = v_member;

  SELECT jsonb_agg(jsonb_build_object('domain', member_domain,
           'state', CASE WHEN parked_at IS NOT NULL THEN 'parked' ELSE 'active' END)
         ORDER BY member_domain)
    INTO v_roster
    FROM federation_room_members WHERE room_id = v_room_id AND left_at IS NULL;
  v_roster := COALESCE(v_roster, '[]'::jsonb);

  -- ONE sorted loop over the PRE-removal snapshot (it still includes the
  -- target — that is exactly who needs the 'remove' op).
  FOREACH v_domain IN ARRAY v_snapshot LOOP
    IF v_domain = v_member THEN
      v_stanza  := v_room_id || ':remove:' || gen_random_uuid()::text;
      v_payload := jsonb_build_object('op', 'remove', 'roomId', v_room_id);
    ELSE
      v_stanza  := v_room_id || ':roster:' || gen_random_uuid()::text;
      v_payload := jsonb_build_object('op', 'roster', 'roomId', v_room_id, 'roster', v_roster);
    END IF;
    PERFORM federation_room_enqueue_member(v_room_id, p_channel_id, v_domain, v_stanza,
      'application/x-setjoin-room', v_payload);
  END LOOP;

  PERFORM audit_write(p_user_id, 'federation.room_remove', 'federation_room', NULL, NULL,
    jsonb_build_object('roomId', v_room_id, 'memberDomain', v_member), NULL, v_room_id, 'core');
  PERFORM notify_chat_state(p_channel_id, 'federation_roster');
END;
$$;
SELECT apply_worker_ownership('federation_room_remove(bigint,bigint,text)'::regprocedure);
