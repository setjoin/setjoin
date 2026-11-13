-- federation_outbox_redact_purged.sql — Pillar C2 Task 8 Step 4: the outbox
-- purge scrub (the "compliance for free" honesty leg — closes a gap C1
-- CREATED for DMs and rooms multiply xN).
--
-- federation_outbox.payload carries full message bodies; chat_purge_expired
-- ("the ONE place chat content is ever destroyed") never touched it, so a
-- lawful purge wrote destroyed-leaf digests while the same bodies sat live
-- in a deny-all table (falsifiable retention claim). Framing (the ratified
-- Q1 wording, see the plan's "Rooms, roster, and the relay trust contract"
-- section + Task 8 Step 4): the outbox is TRANSPORT RESIDUE, never an
-- archive copy — the archive copy lives in chat_messages; this scrub makes
-- the residue honor the purge, it does not make the outbox an archive.
--
-- Called from chat_purge_expired's destroy leg (ONE new call site at the
-- existing choke point), p_origin_keys captured from the doomed rows
-- BEFORE the DELETE as origin-qualified pairs:
--   jsonb_agg(jsonb_build_object('origin', federated_origin_domain,
--                                 'key', COALESCE(federated_stanza_id, id::text)))
-- because clientMsgId collides across origins (the SAME collision V140's
-- dedup fix exists for: bravo's 42 vs charlie's 42 — an origin-blind
-- matcher would redact charlie's still-retained body when bravo's 42 is
-- purged, and the receiving applier would then poison it on drain: silent
-- cross-org loss manufactured by an unrelated purge). origin NULL means the
-- purged row was locally authored (federated_stanza_id IS NULL, key =
-- id::text).
--
-- It REDACTS (never deletes — the seq rail stays intact) matching payloads
-- to the funnel's shape {"redacted":true,"op":...,"roomId":...,"clientMsgId":...}:
--
--   federated-DM channel: keys taken ONLY from NULL-origin pairs (a
--   remote-origin DM body has NO local outbox copy at all — DMs never
--   relay), matched on (peer_domain = the channel's peer, content_type =
--   'application/x-setjoin-chat', clientMsgId = key).
--
--   room-bound channel, this org is the HUB: every hub outbox room row
--   carries a stamped originDomain (federation_room_fanout stamps it
--   unconditionally — NULL p_origin_domain becomes the room's own
--   hub_domain), so match on (content_type = 'application/x-setjoin-room',
--   roomId = the channel's room, clientMsgId = key, originDomain =
--   COALESCE(pair origin, lower(hub_domain))) — a NULL-origin pair is a
--   hub-local author, whose fan-out rows were stamped with the hub's own
--   domain.
--
--   room-bound channel, this org is a SPOKE: its outbox room rows for this
--   channel all target the hub and are ALL locally authored (a spoke never
--   relays), so NULL-origin keys matching clientMsgId = key alone are
--   collision-free within its own id space (chat_messages.id is a single,
--   globally-unique bigserial across every channel in this org's own DB) —
--   remote-origin pairs are EXCLUDED, a spoke never enqueued that body and
--   their keys live in a foreign id space that can numerically collide with
--   local ids.
--
-- A redacted row that later drains is safe by the poison discipline: the
-- receiving applier poisons it (malformed — no body), consumes the seq,
-- acks — no livelock, and the content is gone from the wire.
--
-- Idempotent: a row already carrying {"redacted":true,...} is skipped (a
-- purge sweep can revisit the same channel across ticks; there is nothing
-- left to redact the second time and no reason to write it again).
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership) — federation_outbox
-- is FORCE RLS deny-all-to-setjoin_app (Global Constraints), and
-- chat_purge_expired (its one caller) itself runs on the same posture as
-- every other cron/worker-owned reducer in this repo.
CREATE OR REPLACE FUNCTION federation_outbox_redact_purged(
    p_channel_id  bigint,
    p_origin_keys jsonb
) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_peer_domain text;
  v_room_id     text;
  v_hub_domain  text;
  v_is_hub      boolean;
  v_n           int;
BEGIN
  IF p_origin_keys IS NULL OR jsonb_array_length(p_origin_keys) = 0 THEN
    RETURN 0;
  END IF;

  SELECT federated_peer_domain, federated_room_id
    INTO v_peer_domain, v_room_id
    FROM chat_channels WHERE id = p_channel_id;

  -- Not a federated channel at all: nothing in federation_outbox could ever
  -- reference it (a plain channel never calls federation_enqueue/
  -- federation_room_fanout) — a no-op, not an error, matching every other
  -- "not applicable" shape in this reducer family.
  IF v_room_id IS NULL AND v_peer_domain IS NULL THEN
    RETURN 0;
  END IF;

  IF v_room_id IS NOT NULL THEN
    SELECT hub_domain INTO v_hub_domain FROM federation_rooms WHERE room_id = v_room_id;
    -- "chat_channels.federated_room_id set + federated_peer_domain NULL" IS
    -- the hub self-check (the plan's "Rooms, roster, and the relay trust
    -- contract" section — a reducer can't see process config, the shape
    -- carries the proof forward, the admin_federation.go precedent).
    v_is_hub := (v_peer_domain IS NULL);
  END IF;

  WITH doomed AS (
    SELECT (elem->>'origin') AS origin, (elem->>'key') AS key
      FROM jsonb_array_elements(p_origin_keys) elem
  )
  UPDATE federation_outbox fo
     SET payload = jsonb_build_object(
           'redacted', true,
           'op', fo.payload->>'op',
           'roomId', fo.payload->>'roomId',
           'clientMsgId', fo.payload->>'clientMsgId')
    FROM doomed d
   WHERE NOT (fo.payload ? 'redacted')
     AND (
       -- federated-DM channel: NULL-origin pairs only (a remote-origin DM
       -- body never had a local outbox copy — DMs never relay).
       (v_room_id IS NULL AND d.origin IS NULL
          AND fo.peer_domain = v_peer_domain
          AND fo.content_type = 'application/x-setjoin-chat'
          AND fo.payload->>'clientMsgId' = d.key)
       OR
       -- room-bound, this org is the hub: every hub outbox row for this
       -- room carries a stamped originDomain (fan-out stamps it
       -- unconditionally); COALESCE mirrors the fan-out's own
       -- COALESCE(p_origin_domain, hub_domain).
       (v_room_id IS NOT NULL AND v_is_hub
          AND fo.content_type = 'application/x-setjoin-room'
          AND fo.payload->>'roomId' = v_room_id
          AND fo.payload->>'clientMsgId' = d.key
          AND fo.payload->>'originDomain' = COALESCE(d.origin, lower(v_hub_domain)))
       OR
       -- room-bound, this org is a spoke: only ever enqueues its OWN sends
       -- (NULL-origin pairs); remote-origin pairs are excluded on purpose.
       -- BOTH belts guard the SAME cross-org collision (a dual-role org
       -- that is ALSO a hub of some OTHER room whose roster includes this
       -- same peer): federation_room_fanout stamps every relay row it
       -- writes to this peer with a DIFFERENT roomId (belt 1) AND an
       -- originDomain key the spoke's own send never stamps (belt 2, see
       -- chat_message.sql's SPOKE arm ~line 376 vs federation_room_fanout.sql
       -- ~line 77) — clientMsgId alone can numerically collide across rooms
       -- because chat_messages.id is one global bigserial per org, not
       -- per-room, so a foreign-room relay row can match this purge's key.
       (v_room_id IS NOT NULL AND NOT v_is_hub AND d.origin IS NULL
          AND fo.peer_domain = v_peer_domain
          AND fo.content_type = 'application/x-setjoin-room'
          AND fo.payload->>'roomId' = v_room_id
          AND NOT (fo.payload ? 'originDomain')
          AND fo.payload->>'clientMsgId' = d.key)
     );

  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;
SELECT apply_worker_ownership('federation_outbox_redact_purged(bigint,jsonb)'::regprocedure);
