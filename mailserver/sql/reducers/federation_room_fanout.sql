-- federation_room_fanout.sql — Pillar C2 Task 3: the PROMOTED hub-per-room
-- fan-out (Pillar C0 spike Task 4 (E3) is this function's origin; this
-- promotion supersedes it). HUB-SIDE ONLY (Global Constraints: hub-per-room,
-- not P2P-room — the MUC-shaped model; non-hub members route room sends TO
-- the hub, never peer-to-peer). Callers: chat_message_send's HUB arm (the
-- hub's own local sends) and federation_apply_room's relay leg (Task 4 —
-- re-fanning an inbound spoke message to every OTHER member, same txn).
--
-- Promoted from the C0 4-arg scaffolding
-- (federation_room_fanout(text,text,text,jsonb)) to the 5-arg production
-- shape carrying p_origin_domain (Q2 — the hub asserts origin; NULL means
-- "this is the hub's own send", non-NULL means "relaying member X's
-- message"). DROP FUNCTION IF EXISTS the 4-arg overload first (the C1
-- widening convention) so no stale scaffolding signature survives alongside
-- the new one.
--
-- Per-member disposition (park/revoke/warn/enqueue) is now delegated
-- ENTIRELY to federation_room_enqueue_member (Task 2's ONE choke point,
-- shared with the control-op fan-outs in federation_room_invite/_remove) —
-- this function's own job shrinks to: resolve the room, stamp origin,
-- exclude the origin member (no-re-relay), and drive the sorted loop.
--
-- THE LOCK ORDER LAW (contract section, both control AND message fan-outs):
-- the sorted `FOR UPDATE` roster snapshot below is taken as a STANDALONE
-- statement, BEFORE any federation_peers lock (federation_room_enqueue_
-- member -> federation_enqueue takes those) — the Task 2 CTE-split shape
-- (`WITH locked AS (...) SELECT array_agg(...) INTO ... FROM locked`, NOT a
-- fused CTE, because FOR UPDATE cannot combine with an aggregate in the
-- same SELECT). ALL roster locks are acquired before ANY peer lock, in
-- sorted member_domain order, exactly matching federation_room_invite's/
-- federation_room_remove's own snapshot-first shape — a mid-loop park/
-- revoke here that acquired peer locks before roster locks would invert
-- against those reducers' snapshot-first invite/remove, the eng-review
-- AB/BA deadlock one lock class down. A park or revoke inside the helper
-- never aborts this loop (Q9 — the room stays alive for everyone else).
--
-- Origin exclusion: `member_domain <> v_origin` in the snapshot's WHERE IS
-- the no-re-relay exclusion — the hub never re-sends a message back to the
-- org that authored it (whether the hub itself, p_origin_domain NULL, or a
-- relayed spoke, p_origin_domain set).
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership): federation_rooms/
-- federation_room_members are FORCE RLS deny-all-to-setjoin_app.
DROP FUNCTION IF EXISTS federation_room_fanout(text,text,text,jsonb);
CREATE OR REPLACE FUNCTION federation_room_fanout(
    p_room_id       text,
    p_stanza_id     text,
    p_content_type  text,
    p_payload       jsonb,
    p_origin_domain text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_hub_domain text;
  v_channel_id bigint;
  v_origin     text;
  v_payload    jsonb;
  v_snapshot   text[];
  v_member     text;
BEGIN
  SELECT hub_domain, channel_id INTO v_hub_domain, v_channel_id
    FROM federation_rooms WHERE room_id = p_room_id;
  IF v_hub_domain IS NULL THEN
    -- an internal-invariant breach: callers only ever reach this function
    -- through a channel already bound to a known room (chat_message_send's
    -- HUB arm reads federated_room_id off the channel itself;
    -- federation_apply_room resolves the room before relaying).
    RAISE EXCEPTION 'federation: unknown room % (internal invariant)', p_room_id
      USING ERRCODE='BZ211',
            HINT='{"type":"notFound","detail":"federation_room_fanout called against an unknown roomId"}';
  END IF;

  -- Q2: the hub asserts origin. NULL p_origin_domain means this IS the
  -- hub's own send (origin = the room's own hub_domain); a non-NULL value
  -- means a relay of a member's message (federation_apply_room, Task 4).
  v_origin  := lower(COALESCE(p_origin_domain, v_hub_domain));
  v_payload := p_payload || jsonb_build_object('originDomain', v_origin);

  -- THE LOCK ORDER LAW: sorted roster snapshot FIRST, as a standalone
  -- statement (see header). member_domain <> v_origin is the origin-skip /
  -- no-re-relay exclusion, applied in the SAME statement that takes the
  -- locks (no separate filter pass needed).
  WITH locked AS (
    SELECT member_domain FROM federation_room_members
     WHERE room_id = p_room_id AND left_at IS NULL AND member_domain <> v_origin
     ORDER BY member_domain
     FOR UPDATE
  )
  SELECT array_agg(member_domain ORDER BY member_domain) INTO v_snapshot FROM locked;
  v_snapshot := COALESCE(v_snapshot, '{}');

  FOREACH v_member IN ARRAY v_snapshot LOOP
    PERFORM federation_room_enqueue_member(p_room_id, v_channel_id, v_member,
      p_stanza_id, p_content_type, v_payload);
  END LOOP;
END;
$$;
SELECT apply_worker_ownership('federation_room_fanout(text,text,text,jsonb,text)'::regprocedure);
