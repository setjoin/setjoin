-- federation_room_roster.sql — Pillar C2 Task 7: the ONE read surface over
-- `federation_room_members`/`federation_rooms` (both FORCE-RLS deny-all to
-- setjoin_app) a webmail client can call. SECURITY DEFINER, worker-owned —
-- the federation_room_create/invite/remove precedent (the deny-all-writer
-- family a plain invoker-rights read cannot cross).
--
-- R1 proof FIRST: any channel member may read (chat_require_role with no
-- min-role restriction, the chat_channel_readers precedent) — only the
-- Task 2 mutations (create/invite/remove) are owner/admin-gated. A member
-- who cannot manage the room can still SEE its state (roster sheet, badge,
-- archive-affordance messaging).
--
-- Works identically on hub AND spoke: federation_room_members is keyed by
-- the globally-unique room_id, and Task 5's op:'roster'/'invite' control-op
-- applier mirrors it into the SAME table on a spoke (never a second,
-- hub-only roster table) — so this reducer needs no hub/spoke branch beyond
-- computing `isHub` and gating `depthWarn` to the hub side.
--
-- `state` derivation (Q9 split): 'revoked' iff left_at IS NOT NULL AND
-- left_reason='revoked'; 'left' for any other left_at IS NOT NULL row
-- (left_reason='removed'); 'parked' iff still non-left with parked_at set;
-- 'active' otherwise. Every row is returned regardless of left_at — the
-- roster sheet's whole point is showing revoked/left history alongside the
-- live membership (the C1 admin-console precedent: history stays visible,
-- never deleted).
--
-- `depthWarn` (Task 7's live amber-chip signal, distinct from Task 2's
-- ALREADY-FIRED `federation.room_member_depth_warn` audit act — this is the
-- CURRENT state, re-evaluated on every read, using the exact same
-- cap/warn-pct formula federation_room_enqueue_member.sql uses): true only
-- when isHub AND the member is still non-left AND its federation_peers
-- unacked depth is at/over the warn threshold. Always false on a spoke read
-- (a spoke has no federation_peers row per member — it has exactly one
-- peer, the hub, and that is not what this per-MEMBER field means).
CREATE OR REPLACE FUNCTION federation_room_roster(
    p_user_id    bigint,
    p_channel_id bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_room_id    text;
  v_removed_at timestamptz;
  v_fed_peer   text;
  v_is_hub     boolean;
  v_hub_domain text;
  v_cap        bigint;
  v_warn_pct   int;
  v_warn       bigint;
  v_members    jsonb;
BEGIN
  PERFORM chat_require_role(p_channel_id, p_user_id);

  SELECT federated_room_id, federated_room_removed_at, federated_peer_domain
    INTO v_room_id, v_removed_at, v_fed_peer
    FROM chat_channels WHERE id = p_channel_id;

  IF v_room_id IS NULL THEN
    RAISE EXCEPTION 'channel % is not bound to a federated room', p_channel_id
      USING ERRCODE='BZ211', HINT='{"type":"invalidArguments","detail":"channel is not room-bound"}';
  END IF;

  v_is_hub := v_fed_peer IS NULL;

  SELECT hub_domain INTO v_hub_domain FROM federation_rooms WHERE room_id = v_room_id;

  v_cap      := COALESCE((SELECT value::int FROM system_config WHERE key = 'federation.outbox_cap'), 10000);
  v_warn_pct := COALESCE((SELECT value::int FROM system_config WHERE key = 'federation.outbox_warn_pct'), 80);
  v_warn     := v_cap * v_warn_pct / 100;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'domain', frm.member_domain,
           'state', CASE
                      WHEN frm.left_at IS NOT NULL AND frm.left_reason = 'revoked' THEN 'revoked'
                      WHEN frm.left_at IS NOT NULL THEN 'left'
                      WHEN frm.parked_at IS NOT NULL THEN 'parked'
                      ELSE 'active'
                    END,
           'invitedAt', frm.invited_at,
           'parkedReason', frm.parked_reason,
           'depthWarn', v_is_hub AND frm.left_at IS NULL
                        AND (COALESCE(fp.last_seq, 0) - COALESCE(fp.last_acked_seq, 0)) >= v_warn
         ) ORDER BY frm.member_domain), '[]'::jsonb)
    INTO v_members
    FROM federation_room_members frm
    LEFT JOIN federation_peers fp ON fp.peer_domain = frm.member_domain
   WHERE frm.room_id = v_room_id;

  RETURN jsonb_build_object(
    'roomId', v_room_id,
    'hubDomain', v_hub_domain,
    'isHub', v_is_hub,
    'removedAt', v_removed_at,
    'members', v_members
  );
END;
$$;
SELECT apply_worker_ownership('federation_room_roster(bigint,bigint)'::regprocedure);
