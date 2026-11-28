-- federation_typing_notify.sql — Pillar C2 Task 6: federated typing, the
-- ONE table-read the ephemeral (KindEphemeral) wire class ever does. Product/
-- compliance name is "federated typing", NEVER "presence" (Q5, ratified at
-- the grill) — this file has nothing to do with online/offline status.
--
-- READ-ONLY + NOTIFY, ZERO TABLE WRITES. There is no seq, no outbox row, no
-- ack for an ephemeral frame (wire.go's KindEphemeral doc comment) — an
-- inbound typing frame that fails any check below is silently dropped, never
-- RAISEd. Unlike federation_apply_chat's poison contract (which MUST consume
-- a seq to avoid a replay livelock), there is no bookkeeping to protect here:
-- a dropped typing frame costs nothing and is never resent by anything.
--
-- Called by internal/federation/sender.go's Sender.HandleEphemeral (NOT
-- Receiver — Task 4, built in parallel, owns receiver.go; Task 6 keeps the
-- ephemeral seam entirely in sender.go/service.go per the C2 plan's explicit
-- placement note) for every inbound KindEphemeral frame whose payload op is
-- 'typing'. Go's own per-peer inbound token bucket (sender.go) already
-- dropped a throttled frame BEFORE this call ever runs — this reducer is
-- never the rate-limiting layer, only the trust/resolution layer.
--
-- Three payload shapes (the wire contract, plan's "Rooms, roster, and the
-- relay trust contract" section):
--   room:  {"op":"typing","roomId":...}
--   DM:    {"op":"typing","fromAddr":...,"toAddr":...}
-- p_peer_domain is the STREAM-authenticated peer (verified at handshake —
-- stream.go), never trusted from the payload — the same anti-spoof posture
-- as federation_apply_chat's fromAddr check.
--
-- Room resolution reuses V140's hub self-check verbatim: federation_rooms
-- carries this org's OWN local channel_id for room_id (hub: the real
-- channel; spoke: the mirror — federation_room_create.sql's header); on that
-- local channel row, federated_peer_domain IS NULL marks the HUB shape
-- (streams to N roster members) and NOT NULL marks the SPOKE shape (streams
-- through exactly one bound hub). A reducer can't see process config, so
-- this shape check IS the hub/spoke self-check, not a config read.
--
--   HUB shape: the stream peer must be a live (non-left) roster member
--   (federation_room_members, left_at IS NULL — a cap-parked member is
--   still a valid message/typing origin, only a REVOKED/REMOVED member is
--   excluded, the Q9 posture). Returns relay:true so the Go caller fans the
--   frame out to the rest of the roster (Service.wireAndRun's relay hook).
--
--   SPOKE shape: the stream peer must equal the mirror's bound hub domain,
--   and the mirror must not be kicked/closed (federated_room_removed_at
--   NULL). Returns relay:false — a spoke never re-relays (it has no other
--   roster to relay to; it just applies locally).
--
-- DM resolution recomputes the symmetric federated_local_key SERVER-SIDE
-- from (toAddr, fromAddr) — verbatim federation_apply_chat's own formula,
-- NEVER trusting a stanza-carried key (the C1 invariant). No channel is ever
-- created here (unlike federation_apply_chat's lazy-mirror step) — typing
-- before the first real message exists on a not-yet-established DM is
-- simply dropped; there is nothing to notify yet.
CREATE OR REPLACE FUNCTION federation_typing_notify(
    p_peer_domain text,
    p_payload     jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_peer       text;
  v_room_id    text;
  v_channel_id bigint;
  v_fed_peer   text;
  v_removed_at timestamptz;
  v_from_raw   text;
  v_to_raw     text;
  v_from_addr  text;
  v_to_addr    text;
  v_key        text;
BEGIN
  v_peer := lower(btrim(COALESCE(p_peer_domain, '')));
  IF v_peer = '' OR (p_payload ->> 'op') IS DISTINCT FROM 'typing' THEN
    RETURN jsonb_build_object('ok', false);
  END IF;

  v_room_id := NULLIF(btrim(p_payload ->> 'roomId'), '');

  IF v_room_id IS NOT NULL THEN
    SELECT channel_id INTO v_channel_id
      FROM federation_rooms WHERE room_id = v_room_id;
    IF v_channel_id IS NULL THEN
      RETURN jsonb_build_object('ok', false); -- unknown room (never invited / already deleted)
    END IF;

    SELECT federated_peer_domain, federated_room_removed_at
      INTO v_fed_peer, v_removed_at
      FROM chat_channels WHERE id = v_channel_id;

    IF v_fed_peer IS NULL THEN
      -- HUB shape: sender must be a live (non-left) roster member.
      IF NOT EXISTS (
        SELECT 1 FROM federation_room_members
         WHERE room_id = v_room_id AND member_domain = v_peer AND left_at IS NULL
      ) THEN
        RETURN jsonb_build_object('ok', false);
      END IF;
      PERFORM notify_chat_state(v_channel_id, 'typing');
      RETURN jsonb_build_object('ok', true, 'relay', true);
    END IF;

    -- SPOKE shape: stream peer must be the bound hub, mirror must be live.
    IF lower(v_fed_peer) <> v_peer OR v_removed_at IS NOT NULL THEN
      RETURN jsonb_build_object('ok', false);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'typing');
    RETURN jsonb_build_object('ok', true, 'relay', false);
  END IF;

  -- DM shape.
  v_from_raw := NULLIF(btrim(p_payload ->> 'fromAddr'), '');
  v_to_raw   := NULLIF(btrim(p_payload ->> 'toAddr'), '');
  IF v_from_raw IS NULL OR v_to_raw IS NULL THEN
    RETURN jsonb_build_object('ok', false);
  END IF;
  v_from_addr := lower(v_from_raw);
  v_to_addr   := lower(v_to_raw);

  -- anti-spoof: fromAddr's domain MUST equal the stream-authenticated peer.
  IF split_part(v_from_addr, '@', 2) <> v_peer THEN
    RETURN jsonb_build_object('ok', false);
  END IF;

  v_key := encode(digest(
      least(v_to_addr, v_from_addr) || ':' || greatest(v_to_addr, v_from_addr),
      'sha256'), 'hex');

  SELECT id INTO v_channel_id FROM chat_channels
   WHERE federated_peer_domain = v_peer AND federated_local_key = v_key;
  IF v_channel_id IS NULL THEN
    RETURN jsonb_build_object('ok', false); -- no established DM channel yet — drop
  END IF;

  PERFORM notify_chat_state(v_channel_id, 'typing');
  RETURN jsonb_build_object('ok', true, 'relay', false);
END;
$$;
SELECT apply_worker_ownership('federation_typing_notify(text,jsonb)'::regprocedure);
