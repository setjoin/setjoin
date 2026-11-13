-- security_event_enqueue(p_event_type, p_payload) → event id
--
-- The single writer of security_event_outbox (V253, L2-C4): inserts the durable
-- row and tees the latency-optimization wakeup through app_notify ATOMICALLY in
-- this transaction (mutator invariant: data + notify commit together — a rolled
-- back enqueue leaves neither row nor wakeup). The channel payload carries the
-- stable event id for convenience only; per the outbox contract a wakeup means
-- "drain due rows", never "here is the event" (federation_enqueue.sql:20-25).
--
-- PRODUCER ADMISSION: NO production producer is authorized yet (L2-C4 ships the
-- substrate with behavior OFF). The only callers at HEAD are pgTAP tests; the
-- first production producer (a reducer or gateway path that calls this) is a
-- SEPARATE admission. This header comment must be updated by that admission.
--
-- WORKER-ONLY FUNCTION ACLS — deliberately NOT apply_worker_ownership(): that
-- applicator's contract includes GRANT EXECUTE TO setjoin_app (V118:19-20),
-- which would let the app credential enqueue through this SECURITY DEFINER
-- function and defeat the table-level FORCE RLS deny-all. The footer below
-- follows webhook_delivery_complete.sql:50-53 (OWNER TO setjoin_worker + REVOKE
-- from PUBLIC/setjoin_app + GRANT to setjoin_worker), and the exact signature
-- is registered in scripts/provision-roles.sql's worker-only carve-out block so
-- every provisioning run re-establishes the denial AFTER the broad
-- GRANT EXECUTE ON ALL FUNCTIONS at provision-roles.sql:168.
--
-- SET search_path=pg_catalog,public is required for a definer-privilege
-- function (webhook_delivery_complete.sql:11 precedent — the SECURITY DEFINER
-- escalation foot-gun belt).
CREATE OR REPLACE FUNCTION security_event_enqueue(
  p_event_type TEXT,
  p_payload    JSONB
) RETURNS BIGINT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_event_id BIGINT;
BEGIN
  -- BZ040 (generic invalidArguments): the table CHECK constraints are the
  -- durable backstop; these raise BEFORE any write so an invalid enqueue
  -- leaves neither row nor notify tee (atomicity).
  IF p_event_type IS NULL OR p_event_type !~ '^[a-z][a-z0-9_.]{0,127}$' THEN
    RAISE EXCEPTION 'security_event_enqueue: invalid event_type (must match ^[a-z][a-z0-9_.]{0,127}$)'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalid_security_event_type"}';
  END IF;
  IF p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR octet_length(p_payload::text) > 16384 THEN
    RAISE EXCEPTION 'security_event_enqueue: payload must be a JSON object of at most 16384 octets'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalid_security_event_payload"}';
  END IF;

  INSERT INTO security_event_outbox (event_type, payload)
  VALUES (p_event_type, p_payload)
  RETURNING id INTO v_event_id;

  PERFORM app_notify('security_event_outbox',
    jsonb_build_object('event_id', v_event_id, 'event_type', p_event_type)::text);

  RETURN v_event_id;
END;
$$;

COMMENT ON FUNCTION security_event_enqueue(TEXT, JSONB) IS
  'Security-event outbox enqueue (V253, L2-C4): single writer of '
  'security_event_outbox; inserts the row and emits the security_event_outbox '
  'wakeup atomically. SECURITY DEFINER owned by setjoin_worker; the app '
  'credential is denied EXECUTE (worker-only carve-out in provision-roles.sql). '
  'At-least-once delivery: consumers dedupe on the returned stable event id. '
  'No production producer is admitted yet — behavior OFF (L2-C4).';

-- ── Worker-only function ACLs (webhook_delivery_complete.sql:50-53 form) ───
-- NOT apply_worker_ownership(): that applicator grants setjoin_app EXECUTE by
-- contract (V118:19-20) — the grant this substrate must not have.
ALTER FUNCTION security_event_enqueue(TEXT, JSONB) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION security_event_enqueue(TEXT, JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION security_event_enqueue(TEXT, JSONB) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION security_event_enqueue(TEXT, JSONB) TO setjoin_worker;
