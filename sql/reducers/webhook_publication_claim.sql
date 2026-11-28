CREATE OR REPLACE FUNCTION webhook_publication_claim(
  p_worker_id uuid,
  p_limit integer DEFAULT 100
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_rows jsonb;
BEGIN
  IF p_worker_id IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'invalid webhook publication claim' USING ERRCODE='BZ301';
  END IF;

  UPDATE webhook_publications
     SET state='exhausted',lease_owner=NULL,lease_expires_at=NULL,
         completed_at=statement_timestamp(),last_error='maximum attempts exhausted'
   WHERE state IN ('pending','leased') AND attempt_count>=12
     AND (state='pending' OR lease_expires_at<statement_timestamp());

  WITH candidates AS (
    SELECT id FROM webhook_publications
     WHERE attempt_count<12 AND next_attempt_at<=statement_timestamp()
       AND (state='pending' OR (state='leased' AND lease_expires_at<statement_timestamp()))
     ORDER BY next_attempt_at,id
     FOR UPDATE SKIP LOCKED LIMIT p_limit
  ), claimed AS (
    UPDATE webhook_publications p
       SET state='leased',lease_owner=p_worker_id,
           lease_expires_at=statement_timestamp()+interval '2 minutes',
           attempt_count=attempt_count+1,last_error=NULL
      FROM candidates c WHERE p.id=c.id
    RETURNING p.id,p.event_id,p.event_type,p.source,p.audience,
              p.subject_user_id,p.subject_mailbox_id,p.payload,p.attempt_count
  )
  SELECT COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY id),'[]'::jsonb)
    INTO v_rows FROM claimed;
  RETURN v_rows;
END $$;

ALTER FUNCTION webhook_publication_claim(uuid,integer) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_publication_claim(uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_publication_claim(uuid,integer) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_publication_claim(uuid,integer) TO setjoin_worker;
