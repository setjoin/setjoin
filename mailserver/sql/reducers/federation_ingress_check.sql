-- federation_ingress_check.sql — Pillar C0 spike Task 3 (E4): the s2s
-- ingress abuse gate. Called once per inbound `msg` frame, from an
-- ALREADY-authorized peer (federation_peer_authorize already gated the
-- handshake) — this reducer covers a DIFFERENT risk: an allow-listed peer
-- that misbehaves per-message (oversized/spammy content, or floods).
--
-- Returns one of 'ok' / 'throttled' / 'spam'. Never raises — a verdict is a
-- return value, not an exception, because (internal/federation/receiver.go)
-- the caller must decide what to do with it WITHOUT breaking the E2 ordering
-- invariant (see receiver.go's own comment on why the verdict is
-- advisory-logged, not enforced, in C0).
--
-- Content check (the 'spam' verdict): a MINIMAL size/shape heuristic ONLY.
-- The real content-classification engine (shared/spam: tokenizer, composite
-- scoring, forged-header/spamtrap detection) runs Go-side against a decoded
-- MIME message (mailserver/internal/smtp/inbound.go) and is NOT
-- reducer-callable — it has no PL/pgSQL entry point. Routing federation
-- ingress through that same pipeline (or a federation-specific analog) is a
-- NAMED C1 SEAM, not built here; this oversized-payload check proves the
-- ENFORCEMENT POINT exists, it does not claim content-classification
-- coverage (E4 finding, Task 3 Step 5).
--
-- Rate check (the 'throttled' verdict): reuses chat_send_counters' per-minute
-- window-counter SHAPE (chat_message.sql, A4a Task 10) keyed by peer_domain
-- instead of user_id, in federation_ingress_counters (a NEW table on the same
-- shape, per the plan — not a new key on chat's own table, which is
-- user-scoped and would conflate chat users with federation peer domains).
--
-- SECURITY DEFINER, worker-owned: federation_ingress_counters is FORCE RLS
-- deny-all-to-setjoin_app (no membership axis, the family posture).
CREATE OR REPLACE FUNCTION federation_ingress_check(
    p_peer_domain text,
    p_payload     jsonb
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_rate  int;
  v_count int;
BEGIN
  -- ponytail: a flat 64KiB shape cap (chat_message.sql's BZ168 body-size
  -- genre) — no admin knob yet; a tunable config key only if a real
  -- deployment needs one.
  IF pg_column_size(p_payload) > 65536 THEN
    RETURN 'spam';
  END IF;

  v_rate := COALESCE((SELECT (value #>> '{}')::int FROM system_config
                       WHERE key = 'federation.ingress_rate_per_minute'), 120);

  INSERT INTO federation_ingress_counters AS c (peer_domain, window_start, msg_count)
  VALUES (p_peer_domain, date_trunc('minute', now()), 1)
  ON CONFLICT (peer_domain, window_start) DO UPDATE
    SET msg_count = c.msg_count + 1
  RETURNING msg_count INTO v_count;

  IF v_rate > 0 AND v_count > v_rate THEN
    RETURN 'throttled';
  END IF;

  RETURN 'ok';
END;
$$;
SELECT apply_worker_ownership('federation_ingress_check(text,jsonb)'::regprocedure);
