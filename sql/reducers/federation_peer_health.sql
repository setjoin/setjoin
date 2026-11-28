-- federation_peer_health.sql — Pillar C1 Task 7: a read-only observability
-- reducer for the admin allow-list/anchor console (Task 8) and general
-- ops visibility.
--
-- Reads federation_peers/federation_outbox directly (both FORCE RLS
-- deny-all-to-setjoin_app, same as every other federation_* reducer) —
-- SECURITY DEFINER + apply_worker_ownership + pinned search_path, matching
-- federation_enqueue/federation_ack.
--
-- unacked_depth = last_seq - last_acked_seq (the same math federation_enqueue
-- checks against `federation.outbox_cap`). last_ack_age is measured from the
-- most recent federation_outbox.acked_at for this peer if one exists, else
-- from federation_peers.updated_at (the row's own last-touch time, a
-- reasonable stand-in for "how long has this peer been silent" before it has
-- ever acked anything).
--
-- Returns NULL for an unknown peer_domain (no federation_peers row) — a
-- non-oracle miss, not an error; the admin console can render "no peer" for
-- a NULL the same way it would for a zero-traffic peer.
CREATE OR REPLACE FUNCTION federation_peer_health(
    p_peer_domain text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_last_seq       bigint;
  v_last_acked_seq bigint;
  v_updated_at     timestamptz;
  v_last_acked_at  timestamptz;
BEGIN
  SELECT last_seq, last_acked_seq, updated_at
    INTO v_last_seq, v_last_acked_seq, v_updated_at
    FROM federation_peers WHERE peer_domain = p_peer_domain;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT MAX(acked_at) INTO v_last_acked_at
    FROM federation_outbox WHERE peer_domain = p_peer_domain AND acked_at IS NOT NULL;

  RETURN jsonb_build_object(
    'peerDomain', p_peer_domain,
    'lastSeq', v_last_seq,
    'lastAckedSeq', v_last_acked_seq,
    'unackedDepth', v_last_seq - v_last_acked_seq,
    'lastAckAgeSeconds', EXTRACT(EPOCH FROM (now() - COALESCE(v_last_acked_at, v_updated_at)))::bigint
  );
END;
$$;
SELECT apply_worker_ownership('federation_peer_health(text)'::regprocedure);
