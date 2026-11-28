CREATE OR REPLACE FUNCTION mail_work_outbox_claim(
  p_consumer_kinds text[],
  p_limit integer DEFAULT 100
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_rows jsonb;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 500 OR p_consumer_kinds IS NULL
     OR NOT p_consumer_kinds<@ARRAY['push','digest','metric','task','chat','drive','webhook']::text[] THEN
    RAISE EXCEPTION 'invalid mail-work outbox claim' USING ERRCODE='BZ301';
  END IF;
  WITH candidates AS (
    SELECT id FROM mail_work_outbox
     WHERE consumer_kind=ANY(p_consumer_kinds)
       AND (state='pending' OR (state='claimed' AND lease_until<statement_timestamp()))
     ORDER BY id FOR UPDATE SKIP LOCKED LIMIT p_limit
  ), claimed AS (
    UPDATE mail_work_outbox o SET state='claimed',attempts=attempts+1,
      lease_until=statement_timestamp()+interval '2 minutes',last_error=NULL
    FROM candidates c WHERE o.id=c.id
    RETURNING o.id,o.event_id,o.consumer_kind,o.payload_version,o.payload,o.attempts
  ) SELECT COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY id),'[]'::jsonb) INTO v_rows FROM claimed;
  RETURN v_rows;
END $$;

ALTER FUNCTION mail_work_outbox_claim(text[],integer) OWNER TO setjoin_worker;
