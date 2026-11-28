-- Release a failed lifecycle effect with bounded retry backoff.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_effect_fail(p_worker_id text,p_effect_id bigint,p_error text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_e mailbox_lifecycle_effects%ROWTYPE; v_delay integer;
BEGIN
  SELECT * INTO v_e FROM mailbox_lifecycle_effects WHERE id=p_effect_id FOR UPDATE;
  IF NOT FOUND OR v_e.state<>'claimed' OR v_e.claimed_by<>p_worker_id THEN RETURN; END IF;
  v_delay:=LEAST(900,GREATEST(5,v_e.attempts*v_e.attempts*5));
  UPDATE mailbox_lifecycle_effects SET state='failed',claimed_by=NULL,
    lease_until=statement_timestamp()+make_interval(secs=>v_delay),last_error=left(COALESCE(p_error,'effect failed'),1024)
   WHERE id=v_e.id;
  IF v_e.effect_kind='lifecycle_webhook' THEN
    UPDATE mailbox_lifecycle_outbox SET state='failed',claimed_by=NULL,
      lease_until=statement_timestamp()+make_interval(secs=>v_delay),last_error=left(COALESCE(p_error,'effect failed'),1024)
     WHERE operation_id=v_e.operation_id AND state<>'completed';
  END IF;
END $$;

ALTER FUNCTION mailbox_lifecycle_effect_fail(text,bigint,text) OWNER TO setjoin_worker;
