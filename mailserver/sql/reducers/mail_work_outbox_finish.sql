CREATE OR REPLACE FUNCTION mail_work_outbox_finish(
  p_id bigint,
  p_success boolean,
  p_receipt jsonb,
  p_error text DEFAULT NULL
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF p_id IS NULL OR (NOT p_success AND (p_error IS NULL OR octet_length(p_error)>2048)) THEN
    RAISE EXCEPTION 'invalid mail-work outbox result' USING ERRCODE='BZ301';
  END IF;
  UPDATE mail_work_outbox SET
    state=CASE WHEN p_success THEN 'completed' WHEN attempts>=10 THEN 'failed' ELSE 'pending' END,
    receipt=CASE WHEN p_success THEN COALESCE(p_receipt,'{}'::jsonb) ELSE receipt END,
    last_error=CASE WHEN p_success THEN NULL ELSE p_error END,
    lease_until=NULL,completed_at=CASE WHEN p_success OR attempts>=10 THEN statement_timestamp() ELSE NULL END
   WHERE id=p_id AND state='claimed';
  RETURN FOUND;
END $$;

ALTER FUNCTION mail_work_outbox_finish(bigint,boolean,jsonb,text) OWNER TO setjoin_worker;
