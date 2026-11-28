-- rust_outbound_queue_enqueue.sql — Wave 1.8c (#546c)
-- Owning reducer for enqueueing a single-recipient outbound email (retiring
-- guests' direct cross-domain INSERT into outbound_queue). Strictly worker-only:
-- fail closed (42501) unless called from a privileged role, and revoked from
-- PUBLIC and setjoin_app (restated in scripts/provision-roles.sql exact_worker).

CREATE OR REPLACE FUNCTION rust_outbound_queue_enqueue(
  p_message_id TEXT,
  p_from_addr  TEXT,
  p_rcpt_addr  TEXT,
  p_raw_ref    TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  INSERT INTO public.outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
  VALUES (p_message_id, p_from_addr, ARRAY[p_rcpt_addr], p_raw_ref, 'pending')
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_outbound_queue_enqueue(text,text,text,text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_outbound_queue_enqueue(text,text,text,text) TO setjoin_worker;
