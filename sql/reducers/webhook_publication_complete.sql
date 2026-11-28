CREATE OR REPLACE FUNCTION webhook_publication_complete(
  p_publication_id bigint,
  p_worker_id uuid,
  p_succeeded boolean,
  p_error text DEFAULT NULL
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_attempt integer;
BEGIN
  SELECT attempt_count INTO v_attempt FROM webhook_publications
   WHERE id=p_publication_id AND state='leased' AND lease_owner=p_worker_id
   FOR UPDATE;
  IF v_attempt IS NULL THEN RETURN false; END IF;

  IF p_succeeded THEN
    UPDATE webhook_publications SET state='delivered',lease_owner=NULL,
      lease_expires_at=NULL,completed_at=statement_timestamp(),last_error=NULL
     WHERE id=p_publication_id;
  ELSIF v_attempt>=12 THEN
    UPDATE webhook_publications SET state='exhausted',lease_owner=NULL,
      lease_expires_at=NULL,completed_at=statement_timestamp(),
      last_error=left(COALESCE(p_error,'delivery handoff failed'),2048)
     WHERE id=p_publication_id;
  ELSE
    UPDATE webhook_publications SET state='pending',lease_owner=NULL,
      lease_expires_at=NULL,
      next_attempt_at=statement_timestamp()
        + interval '1 second' * LEAST(1024,power(2,GREATEST(v_attempt-1,0)))
          * (0.75 + ((hashtextextended(event_id,0) & 9223372036854775807) % 51)::numeric/100),
      last_error=left(COALESCE(p_error,'delivery handoff failed'),2048)
     WHERE id=p_publication_id;
  END IF;
  RETURN true;
END $$;

ALTER FUNCTION webhook_publication_complete(bigint,uuid,boolean,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_publication_complete(bigint,uuid,boolean,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_publication_complete(bigint,uuid,boolean,text) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_publication_complete(bigint,uuid,boolean,text) TO setjoin_worker;
