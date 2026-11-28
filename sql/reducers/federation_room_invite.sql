-- federation_room_invite.sql — Pillar C2 Task 2: the hub channel owner/
-- admin's invite/re-admit lever (Q3 two-key membership authority — the
-- federation admin's allow-list scope decides WHO CAN be invited, checked
-- here via federation_peer_authorize; the hub channel owner/admin decides
-- WHAT rooms they join). Invite IS re-admit (Q9) — one lever, no separate
-- endpoint: an existing parked OR revoked/removed target is un-parked/
-- un-left by the SAME upsert a brand-new target goes through.
--
-- THE LOCK ORDER LAW (contract section): roster rows FIRST (ONE sorted
-- `FOR UPDATE` snapshot of every currently non-left member), THEN the
-- target upsert, THEN federation_peers locks (inside
-- federation_room_enqueue_member's federation_enqueue call) in sorted
-- member_domain order, in a SINGLE loop over the sorted union of
-- snapshot ∪ target. An existing non-left target is already IN the
-- snapshot (its row lock already held in sorted order); a brand-new or
-- left_at-set target has no row visible to a concurrent fan-out's own
-- `left_at IS NULL` snapshot, so upserting it next contends with nothing.
-- NEVER "invite target first, then the sorted rest" — the unsorted union
-- is the eng-review AB/BA deadlock against a concurrent message fan-out.
--
-- Refusals (BZ211, the membership-authority-refusal family — owner/admin
-- required, channel not hub-shaped, target is the hub's own domain,
-- contactAddr domain mismatch, peer not allow-listed/enabled at scope
-- 'room'): all one code, mirroring how BZ163 lumps three different
-- reducers' "not a member" checks under one wire meaning.
CREATE OR REPLACE FUNCTION federation_room_invite(
    p_user_id      bigint,
    p_channel_id   bigint,
    p_member_domain text,
    p_contact_addr text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_role        text;
  v_room_id     text;
  v_fed_peer    text;
  v_title       text;
  v_archived    boolean;
  v_hub_domain  text;
  v_member      text;
  v_contact_dom text;
  v_snapshot    text[];
  v_union       text[];
  v_prev_epochs jsonb;
  v_new_epochs  jsonb;
  v_gap_from    timestamptz;
  v_gap_to      timestamptz;
  v_epoch_idx   int;
  v_epoch_open  timestamptz;
  v_audit       jsonb;
  v_roster      jsonb;
  v_domain      text;
  v_stanza      text;
  v_payload     jsonb;
BEGIN
  SELECT role INTO v_role FROM chat_channel_members
   WHERE channel_id = p_channel_id AND user_id = p_user_id;
  IF v_role IS NULL OR v_role NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION 'owner/admin required to invite a federated room member'
      USING ERRCODE='BZ211', HINT='{"type":"forbidden","detail":"owner/admin required"}';
  END IF;

  SELECT federated_room_id, federated_peer_domain, name, is_archived
    INTO v_room_id, v_fed_peer, v_title, v_archived
    FROM chat_channels WHERE id = p_channel_id;
  IF v_room_id IS NULL OR v_fed_peer IS NOT NULL THEN
    RAISE EXCEPTION 'channel % is not a federation hub room', p_channel_id
      USING ERRCODE='BZ211', HINT='{"type":"invalidArguments","detail":"channel is not a hub-bound room"}';
  END IF;
  -- Task 2 review finding: an archived hub channel must refuse re-invite.
  -- The Q13 close flow is "remove all member orgs, THEN archive" — without
  -- this guard, an owner could re-invite into that archived channel and
  -- silently re-open fan-out against a channel the archive flow declared
  -- closed (chat_message_send's own BZ171 archive guard would still block
  -- ordinary posts, but the room membership/roster machinery would have
  -- quietly resumed regardless).
  IF v_archived THEN
    RAISE EXCEPTION 'channel % is archived; a room cannot be (re-)invited into an archived channel', p_channel_id
      USING ERRCODE='BZ211', HINT='{"type":"conflict","detail":"channel is archived"}';
  END IF;

  SELECT hub_domain INTO v_hub_domain FROM federation_rooms WHERE room_id = v_room_id;

  v_member := lower(btrim(COALESCE(p_member_domain, '')));
  IF v_member = '' OR v_member = lower(v_hub_domain) THEN
    RAISE EXCEPTION 'cannot invite the room''s own hub domain'
      USING ERRCODE='BZ211', HINT='{"type":"invalidArguments","detail":"member domain invalid or equals the hub"}';
  END IF;

  v_contact_dom := lower(split_part(COALESCE(p_contact_addr, ''), '@', 2));
  IF v_contact_dom <> v_member THEN
    RAISE EXCEPTION 'contact address domain must match the invited member domain'
      USING ERRCODE='BZ211', HINT='{"type":"invalidArguments","detail":"contact address domain mismatch"}';
  END IF;

  -- Q3 two-key gate: the federation admin's allow-list scope decides who is
  -- invitable; the federation_dm_ensure catch-and-reraise pattern.
  BEGIN
    PERFORM federation_peer_authorize(v_member, 'room');
  EXCEPTION WHEN SQLSTATE 'BZ203' THEN
    RAISE EXCEPTION 'federation: peer % is not allow-listed/enabled for room scope', v_member
      USING ERRCODE='BZ211', HINT='{"type":"forbidden","detail":"peer not allow-listed/enabled for room scope"}';
  END;

  -- THE LOCK ORDER LAW: sorted roster snapshot FIRST. FOR UPDATE cannot be
  -- combined with an aggregate in the same SELECT (Postgres restriction),
  -- so the CTE below locks (no aggregate), the outer query aggregates
  -- (no FOR UPDATE) — one statement, no TOCTOU window between locking and
  -- reading.
  WITH locked AS (
    SELECT member_domain FROM federation_room_members
     WHERE room_id = v_room_id AND left_at IS NULL
     ORDER BY member_domain
     FOR UPDATE
  )
  SELECT array_agg(member_domain ORDER BY member_domain) INTO v_snapshot FROM locked;
  v_snapshot := COALESCE(v_snapshot, '{}');

  -- The just-upserted-newcomer/re-admit epoch close (Q9 coverage epochs):
  -- if the target's trailing epochs are still open (no resumedAt key), close
  -- them now and carry the gap window to the invite payload below (the
  -- spoke's local gap-marker message, Task 5). A brand-new target has no
  -- prior row at all (v_prev_epochs NULL -> COALESCE '[]', no gap).
  --
  -- er5-s12 (occ_90331fd14cba7e6aadc3bfd9, audit-integrity
  -- .federated-coverage-epochs): the Task 8 eDiscovery manifest reports
  -- knownMissingIntervals verbatim from these epochs, so a trailing run of
  -- open epochs closed only at its LAST element (park/repark appends without
  -- resuming) would leave earlier open entries dangling as perpetual
  -- "gap ongoing" rows — and a single-element close hid the reparked span
  -- entirely. Close the WHOLE trailing run in one pass: the carried gap is
  -- the contiguous window from the EARLIEST trailing parkedAt to now, and
  -- the same window is written to admin_audit_log below so the hub's own
  -- record carries the gap evidence even if the wire delivery to the spoke
  -- is lost.
  SELECT coverage_epochs INTO v_prev_epochs
    FROM federation_room_members WHERE room_id = v_room_id AND member_domain = v_member;
  v_new_epochs := COALESCE(v_prev_epochs, '[]'::jsonb);
  v_gap_from := NULL;
  v_gap_to   := NULL;
  v_epoch_idx := jsonb_array_length(v_new_epochs) - 1;
  WHILE v_epoch_idx >= 0 AND NOT (v_new_epochs -> v_epoch_idx ? 'resumedAt') LOOP
    v_gap_to := COALESCE(v_gap_to, now());
    v_epoch_open := (v_new_epochs -> v_epoch_idx ->> 'parkedAt')::timestamptz;
    IF v_epoch_open IS NOT NULL AND (v_gap_from IS NULL OR v_epoch_open < v_gap_from) THEN
      v_gap_from := v_epoch_open;
    END IF;
    v_new_epochs := jsonb_set(v_new_epochs, ARRAY[v_epoch_idx::text],
                              v_new_epochs -> v_epoch_idx || jsonb_build_object('resumedAt', v_gap_to));
    v_epoch_idx := v_epoch_idx - 1;
  END LOOP;

  -- invite IS re-admit: an existing parked/revoked/removed row is cleared
  -- back to active by the SAME upsert a brand-new row goes through.
  INSERT INTO federation_room_members (room_id, member_domain, coverage_epochs)
    VALUES (v_room_id, v_member, v_new_epochs)
    ON CONFLICT (room_id, member_domain) DO UPDATE
      SET parked_at = NULL, parked_reason = NULL, left_at = NULL, left_reason = NULL,
          coverage_epochs = v_new_epochs;

  SELECT array_agg(DISTINCT d ORDER BY d) INTO v_union FROM unnest(v_snapshot || ARRAY[v_member]) d;

  -- roster wire array: every non-left member (active + parked), computed
  -- AFTER the upsert so it naturally includes the freshly un-parked/
  -- un-left target.
  SELECT jsonb_agg(jsonb_build_object('domain', member_domain,
           'state', CASE WHEN parked_at IS NOT NULL THEN 'parked' ELSE 'active' END)
         ORDER BY member_domain)
    INTO v_roster
    FROM federation_room_members WHERE room_id = v_room_id AND left_at IS NULL;

  -- ONE sorted loop over the union — never target-first-then-rest.
  FOREACH v_domain IN ARRAY v_union LOOP
    IF v_domain = v_member THEN
      v_stanza  := v_room_id || ':invite:' || gen_random_uuid()::text;
      v_payload := jsonb_build_object('op', 'invite', 'roomId', v_room_id, 'hubDomain', v_hub_domain,
                     'title', v_title, 'contactAddr', p_contact_addr, 'roster', v_roster);
      IF v_gap_from IS NOT NULL THEN
        v_payload := v_payload || jsonb_build_object('gapFrom', v_gap_from, 'gapTo', v_gap_to);
      END IF;
    ELSE
      v_stanza  := v_room_id || ':roster:' || gen_random_uuid()::text;
      v_payload := jsonb_build_object('op', 'roster', 'roomId', v_room_id, 'roster', v_roster);
    END IF;
    PERFORM federation_room_enqueue_member(v_room_id, p_channel_id, v_domain, v_stanza,
      'application/x-setjoin-room', v_payload);
  END LOOP;

  -- CA-0b audit, now carrying the closed gap window (er5-s12
  -- audit-integrity.federated-coverage-epochs): the hub's audit trail is the
  -- durable record that the member's delivery gap [gapFrom, gapTo] was
  -- closed at this invite, independent of the wire payload's delivery.
  v_audit := jsonb_build_object('roomId', v_room_id, 'memberDomain', v_member);
  IF v_gap_from IS NOT NULL AND v_gap_to IS NOT NULL THEN
    v_audit := v_audit || jsonb_build_object('gapFrom', v_gap_from, 'gapTo', v_gap_to);
  END IF;
  PERFORM audit_write(p_user_id, 'federation.room_invite', 'federation_room', NULL, NULL,
    v_audit, NULL, v_room_id, 'core');
  PERFORM notify_chat_state(p_channel_id, 'federation_roster');
END;
$$;
SELECT apply_worker_ownership('federation_room_invite(bigint,bigint,text,text)'::regprocedure);
