-- Return a transiently failed purge to the recoverable worker queue.

CREATE OR REPLACE FUNCTION mailbox_purge_fail(p_worker_id text,p_purge_request_id uuid,p_error text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_p mailbox_purge_requests%ROWTYPE; v_delay integer;
BEGIN
  SELECT * INTO v_p FROM mailbox_purge_requests WHERE id=p_purge_request_id FOR UPDATE;
  IF NOT FOUND OR v_p.state<>'claimed' OR v_p.claimed_by<>p_worker_id THEN RETURN; END IF;
  v_delay:=LEAST(900,GREATEST(5,v_p.attempts*v_p.attempts*5));
  UPDATE mailbox_purge_requests SET state='failed',claimed_by=NULL,
    lease_until=statement_timestamp()+make_interval(secs=>v_delay),
    blocker_snapshot=jsonb_build_array(jsonb_build_object('domain','worker','code','transient_failure',
      'detail',left(COALESCE(p_error,'purge failed'),512))) WHERE id=v_p.id;
END $$;

ALTER FUNCTION mailbox_purge_fail(text,uuid,text) OWNER TO setjoin_worker;
