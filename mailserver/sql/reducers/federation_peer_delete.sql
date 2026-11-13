-- federation_peer_delete.sql — Pillar C1 Task 8: admin allow-list peer
-- removal, with the disable-before-delete lifecycle the plan's Task 8
-- section names: a peer must already be disabled (federation_peer_set with
-- p_enabled=false) before it can be deleted. That ordering matters because
-- disabling is what makes the Task 5 Service reconcile drop the peer's live
-- stream (DES-011 eviction, via the same federation_allowlist_changed NOTIFY
-- this reducer also emits) — deleting an ENABLED row out from under a live
-- stream would race the reconcile loop instead of strictly preceding it.
--
-- FULL transport-state reap (C2 planning found the original unacked-only
-- reap was a livelock trap): delete reaps ALL federation_outbox rows for the
-- peer, the federation_peers row (its last_seq — federation_enqueue lazily
-- recreates at 0 on re-add), and the peer's federation_inbox +
-- federation_inbox_cursor rows, in the SAME transaction. Rationale: the old
-- shape deleted unacked rows 5..10 while last_seq stayed at 10 — a later
-- RE-ADD of the same peer enqueued seq 11 against the remote cursor at 4 →
-- BZ202 gap → replay-req into rows that no longer exist → permanent
-- livelock. Full reap makes BILATERAL delete → re-add a clean restart (both
-- sides back to seq 0/cursor 0); a one-sided delete+re-add still requires
-- the remote org to delete+re-add too — that bilateral requirement is the
-- documented admin contract (mirrors the bilateral allow-list itself).
-- Counts are recorded on the audit act (never a silent drop).
--
-- Idempotent-on-missing: deleting an unknown domain is a no-op (returns
-- false) rather than an error — the admin console's Delete action racing a
-- second tab's delete should not surface as a 500/409 to either caller.
--
-- SECURITY DEFINER + apply_worker_ownership + pinned search_path, matching
-- federation_peer_set: federation_allowlist/federation_outbox are FORCE RLS
-- deny-all-to-setjoin_app.
CREATE OR REPLACE FUNCTION federation_peer_delete(
    p_actor  bigint,
    p_domain text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_domain       text := lower(btrim(COALESCE(p_domain, '')));
  v_enabled      boolean;
  v_reaped       bigint;
  v_inbox_reaped bigint;
BEGIN
  SELECT enabled INTO v_enabled FROM federation_allowlist WHERE peer_domain = v_domain;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  IF v_enabled THEN
    RAISE EXCEPTION 'federation: peer % must be disabled before it can be deleted', v_domain
      USING ERRCODE='BZ208',
            HINT='{"type":"conflict","detail":"peer must be disabled before delete"}';
  END IF;

  DELETE FROM federation_allowlist WHERE peer_domain = v_domain;

  -- FK order: outbox references federation_peers; inbox references
  -- federation_inbox_cursor — children first.
  DELETE FROM federation_outbox WHERE peer_domain = v_domain;
  GET DIAGNOSTICS v_reaped = ROW_COUNT;
  DELETE FROM federation_peers WHERE peer_domain = v_domain;
  DELETE FROM federation_inbox WHERE peer_domain = v_domain;
  GET DIAGNOSTICS v_inbox_reaped = ROW_COUNT;
  DELETE FROM federation_inbox_cursor WHERE peer_domain = v_domain;

  PERFORM audit_write(
    p_actor, 'federation.peer_delete', 'federation_peer', NULL,
    NULL,
    jsonb_build_object('domain', v_domain, 'reapedOutboxRows', v_reaped,
                       'reapedInboxRows', v_inbox_reaped),
    NULL, v_domain, 'core'
  );

  PERFORM app_notify('federation_allowlist_changed',
                      jsonb_build_object('peerDomain', v_domain)::text);

  RETURN true;
END;
$$;
SELECT apply_worker_ownership('federation_peer_delete(bigint,text)'::regprocedure);
