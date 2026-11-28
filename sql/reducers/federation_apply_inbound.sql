-- federation_apply_inbound.sql — Pillar C0 spike Task 2 (E2, THE crux): the
-- in-order, exactly-once inbound applier.
--
-- Idempotent on the (peer_domain, peer_seq) PRIMARY KEY: a duplicate apply
-- (the same peer_seq re-delivered — the apply-committed/ack-lost crash
-- window wire.go's KindAck doc comment names) is a SAFE NO-OP, returning
-- FALSE, never an error. The caller (internal/federation/receiver.go) MUST
-- STILL SEND AN ACK for a dup — if it didn't, the sender's cursor (gated on
-- federation_peers.last_acked_seq) would never advance past a row it keeps
-- re-sending, livelocking the peer forever.
--
-- A GAP (p_peer_seq > federation_inbox_cursor.last_applied_seq + 1) raises
-- BZ202 so the receiver pauses the stream and sends a replay_req frame
-- (wire.go's KindReplayReq) instead of silently skipping ahead — ordering
-- is the one invariant this whole mechanism exists to prove (E2/R2).
--
-- Runs on the worker/BYPASSRLS pool (this is cross-tenant, cross-org
-- infrastructure — no per-user scoping is possible or meaningful here).
-- SECURITY DEFINER + apply_worker_ownership + pinned search_path, matching
-- federation_enqueue: federation_inbox/federation_inbox_cursor are FORCE RLS
-- deny-all-to-setjoin_app (Global Constraints — no membership axis), this
-- reducer is the ONE writer for both.
CREATE OR REPLACE FUNCTION federation_apply_inbound(
    p_peer_domain  text,
    p_peer_seq     bigint,
    p_stanza_id    text,
    p_content_type text,
    p_payload      jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_last bigint;
BEGIN
  -- Idempotency check FIRST, before touching the cursor: a re-delivered
  -- already-applied seq is a dup no matter what the current cursor says.
  IF EXISTS (
    SELECT 1 FROM federation_inbox
     WHERE peer_domain = p_peer_domain AND peer_seq = p_peer_seq
  ) THEN
    RETURN false;
  END IF;

  INSERT INTO federation_inbox_cursor (peer_domain) VALUES (p_peer_domain)
    ON CONFLICT (peer_domain) DO NOTHING;

  -- Row lock: serializes concurrent applies for the same peer (a single
  -- in-order receiver never actually contends this, but a stray concurrent
  -- call can never desync the cursor from federation_inbox's contents).
  SELECT last_applied_seq INTO v_last FROM federation_inbox_cursor
    WHERE peer_domain = p_peer_domain FOR UPDATE;

  -- Task 8 Step 2 (the cursor-regression guard) — verbatim from
  -- federation_apply_chat.sql/federation_apply_room.sql: the EXISTS check
  -- above only catches a dup whose federation_inbox row still exists. Once
  -- federation_reap deletes old applied rows (this reducer is now also the
  -- funnel's landing path for unknown content types, Task 8 Step 5 —
  -- same residue, same reaper, same exposure), a replayed p_peer_seq
  -- at-or-below the cursor must still dup, never fall through to the
  -- unconditional cursor SET below (which would move it BACKWARD). The old
  -- comment claiming this case was "unreachable" is exactly the gap this
  -- guard closes — it was only unreachable as long as federation_inbox rows
  -- were never deleted.
  IF p_peer_seq <= v_last THEN
    RETURN false;
  END IF;

  IF p_peer_seq > v_last + 1 THEN
    RAISE EXCEPTION 'federation: sequence gap for peer % — got % expected %',
      p_peer_domain, p_peer_seq, v_last + 1
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"sequence gap — replay required"}';
  END IF;

  INSERT INTO federation_inbox (peer_domain, peer_seq, stanza_id, content_type, payload)
    VALUES (p_peer_domain, p_peer_seq, p_stanza_id, p_content_type, p_payload);

  UPDATE federation_inbox_cursor SET last_applied_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain;

  RETURN true;
END;
$$;
SELECT apply_worker_ownership('federation_apply_inbound(text,bigint,text,text,jsonb)'::regprocedure);
