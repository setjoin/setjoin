CREATE OR REPLACE FUNCTION webhook_delivery_complete(
  p_delivery_id bigint,
  p_worker_id uuid,
  p_succeeded boolean,
  p_retryable boolean,
  p_response_code integer DEFAULT NULL,
  p_response_body text DEFAULT NULL,
  p_latency_ms integer DEFAULT NULL,
  p_error text DEFAULT NULL
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_attempt integer;
  v_retry_enabled boolean;
  v_max_retries integer;
  v_event_id text;
BEGIN
  SELECT d.attempt,s.retry_enabled,s.max_retries,d.event_id
    INTO v_attempt,v_retry_enabled,v_max_retries,v_event_id
    FROM webhook_deliveries d
    JOIN webhook_subscriptions s ON s.id=d.subscription_id
   WHERE d.id=p_delivery_id AND d.lease_owner=p_worker_id
   FOR UPDATE OF d;
  IF NOT FOUND THEN RETURN false; END IF;

  IF p_succeeded THEN
    UPDATE webhook_deliveries SET status='success',lease_owner=NULL,lease_expires_at=NULL,
      response_code=p_response_code,response_body=left(p_response_body,1024),
      latency_ms=p_latency_ms,error_message=NULL,completed_at=statement_timestamp()
     WHERE id=p_delivery_id;
  ELSIF p_retryable AND v_retry_enabled AND v_attempt<v_max_retries THEN
    UPDATE webhook_deliveries SET status='failed',lease_owner=NULL,lease_expires_at=NULL,
      response_code=p_response_code,response_body=left(p_response_body,1024),
      latency_ms=p_latency_ms,error_message=left(COALESCE(p_error,'delivery failed'),2048),
      completed_at=statement_timestamp(),
      next_attempt_at=statement_timestamp()
        + interval '1 second' * LEAST(1024,power(2,GREATEST(v_attempt-1,0)))
          * (0.75 + ((hashtextextended(v_event_id,0) & 9223372036854775807) % 51)::numeric/100)
     WHERE id=p_delivery_id;
  ELSE
    UPDATE webhook_deliveries SET status='exhausted',lease_owner=NULL,lease_expires_at=NULL,
      response_code=p_response_code,response_body=left(p_response_body,1024),
      latency_ms=p_latency_ms,error_message=left(COALESCE(p_error,'delivery failed'),2048),
      completed_at=statement_timestamp()
     WHERE id=p_delivery_id;
  END IF;
  RETURN true;
END $$;

ALTER FUNCTION webhook_delivery_complete(bigint,uuid,boolean,boolean,integer,text,integer,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_delivery_complete(bigint,uuid,boolean,boolean,integer,text,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_delivery_complete(bigint,uuid,boolean,boolean,integer,text,integer,text) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_delivery_complete(bigint,uuid,boolean,boolean,integer,text,integer,text) TO setjoin_worker;
