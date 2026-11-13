-- federation_enqueue.sql — Pillar C0 spike Task 2 (E2, THE crux): the
-- commit-ordered outbox writer.
--
-- peer_seq = federation_peers.last_seq + 1, assigned under THAT ROW's OWN
-- LOCK (UPDATE ... RETURNING) INSIDE this function's transaction — verbatim
-- the chat_message.sql change_seq rail, NOT a bigserial. A bigserial's
-- nextval() is non-transactional (it burns a value even when the enclosing
-- statement/transaction rolls back), which would produce a permanent,
-- unrecoverable gap the receiver's in-order applier can never fill. Because
-- the UPDATE is a normal row-locked statement, an abort of this transaction
-- rolls the increment back too — the outbox is gap-free BY CONSTRUCTION, not
-- by a separate reconciliation step (mailserver/sql/tests/federation_ordering.pg
-- "rollback-of-enqueue leaves no gap" pins this).
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership): federation_peers/
-- federation_outbox are FORCE RLS deny-all-to-setjoin_app (Global
-- Constraints — no membership axis on per-domain transport infrastructure,
-- the chat_audit_log shape) — this reducer is the ONE writer for both.
--
-- Notifies federation_outbox:<peer_domain> via app_notify (the single
-- pg_notify choke point every reducer routes through, reducers/app_notify.sql)
-- so the per-peer sender goroutine (internal/federation/sender.go) wakes
-- immediately instead of waiting out its 3s tick fallback — "Why not
-- pushjobs" / the plan's Task 2. NOTIFY coalescing is harmless: a wakeup
-- means "go check the cursor," not "here is exactly one message."
--
-- Pillar C1 Task 7 — backpressure / dead-peer cap: p_user_initiated (DEFAULT
-- false) gates a pair of pre-assign refusals (BZ205) that exist ONLY to
-- protect a human sender from queuing into a peer that will never drain —
-- system/harness frames (federation_room_fanout.sql's fanout loop, the C0
-- fedharness /enqueue control endpoint, every existing 4-arg pgTAP call
-- site) pass no 5th arg and stay exempt by construction, never even
-- evaluating the checks below:
--   (a) unacked depth (last_seq - last_acked_seq) > `federation.outbox_cap`
--       (system_config, DEFAULT 10000) — the peer isn't draining fast enough,
--       stop piling on.
--   (b) the oldest unacked outbox row is older than
--       `federation.peer_stale_minutes` (system_config, DEFAULT 30) — the
--       peer hasn't acked ANYTHING in that long, treat it as dead rather
--       than queue into a void forever.
-- Both checks run BEFORE the seq is assigned (the depth read is a plain
-- SELECT, not a row lock — a refuse here writes nothing, so there is nothing
-- to roll back). ponytail: a fixed cap + last-ack-age is enough; a
-- per-peer-tunable knob is a named later upgrade if one peer's traffic
-- profile ever needs to differ from the org default.
--
-- Task 4B added p_spam_quarantined bookkeeping to federation_apply_chat, a
-- DIFFERENT function widened the same way this one is: an existing 4-arg
-- CREATE OR REPLACE cannot append a 5th parameter and have Postgres treat it
-- as a replace — Postgres resolves overloads by name+input-arg-types, so a
-- bare CREATE OR REPLACE here would leave the OLD 4-arg
-- federation_enqueue(text,text,text,jsonb) lingering as a second overload
-- instead of being replaced (federation_apply_chat.sql's own header explains
-- this in more detail). Drop it first.
DROP FUNCTION IF EXISTS federation_enqueue(text, text, text, jsonb);

CREATE OR REPLACE FUNCTION federation_enqueue(
    p_peer_domain     text,
    p_stanza_id       text,
    p_content_type    text,
    p_payload         jsonb,
    p_user_initiated  boolean DEFAULT false
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_seq              bigint;
  v_last_seq         bigint;
  v_last_acked_seq   bigint;
  v_depth            bigint;
  v_cap              bigint;
  v_stale_minutes    int;
  v_oldest_unacked   timestamptz;
BEGIN
  INSERT INTO federation_peers (peer_domain) VALUES (p_peer_domain)
    ON CONFLICT (peer_domain) DO NOTHING;

  IF p_user_initiated THEN
    SELECT last_seq, last_acked_seq INTO v_last_seq, v_last_acked_seq
      FROM federation_peers WHERE peer_domain = p_peer_domain;

    v_depth := v_last_seq - v_last_acked_seq;
    v_cap := COALESCE((SELECT value::int FROM system_config WHERE key = 'federation.outbox_cap'), 10000);

    IF v_depth > v_cap THEN
      RAISE EXCEPTION 'federation: peer % unacked outbox depth % exceeds cap %',
        p_peer_domain, v_depth, v_cap
        USING ERRCODE='BZ205',
              HINT='{"type":"conflict","detail":"peer outbox backpressure cap exceeded"}';
    END IF;

    IF v_depth > 0 THEN
      v_stale_minutes := COALESCE((SELECT value::int FROM system_config WHERE key = 'federation.peer_stale_minutes'), 30);

      SELECT MIN(created_at) INTO v_oldest_unacked
        FROM federation_outbox WHERE peer_domain = p_peer_domain AND acked_at IS NULL;

      IF v_oldest_unacked IS NOT NULL AND v_oldest_unacked < now() - make_interval(mins => v_stale_minutes) THEN
        RAISE EXCEPTION 'federation: peer % appears unreachable — oldest unacked frame is over % minutes old',
          p_peer_domain, v_stale_minutes
          USING ERRCODE='BZ205',
                HINT='{"type":"conflict","detail":"peer appears unreachable (stale)"}';
      END IF;
    END IF;
  END IF;

  UPDATE federation_peers SET last_seq = last_seq + 1, updated_at = now()
    WHERE peer_domain = p_peer_domain
    RETURNING last_seq INTO v_seq;

  INSERT INTO federation_outbox (peer_domain, peer_seq, stanza_id, content_type, payload)
    VALUES (p_peer_domain, v_seq, p_stanza_id, p_content_type, p_payload);

  PERFORM app_notify('federation_outbox:' || p_peer_domain,
                      jsonb_build_object('peerDomain', p_peer_domain, 'peerSeq', v_seq)::text);

  RETURN v_seq;
END;
$$;
SELECT apply_worker_ownership('federation_enqueue(text,text,text,jsonb,boolean)'::regprocedure);
