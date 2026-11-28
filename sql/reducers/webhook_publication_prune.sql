CREATE OR REPLACE FUNCTION webhook_publication_prune(
  p_retain_days integer DEFAULT 30,
  p_limit integer DEFAULT 500
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_count integer;
BEGIN
  IF p_retain_days NOT BETWEEN 7 AND 365 OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid webhook publication retention' USING ERRCODE='BZ301';
  END IF;
  WITH candidates AS (
    SELECT id FROM webhook_publications
     WHERE state IN ('delivered','exhausted')
       AND completed_at<statement_timestamp()-make_interval(days=>p_retain_days)
     ORDER BY completed_at,id FOR UPDATE SKIP LOCKED LIMIT p_limit
  ), deleted AS (
    DELETE FROM webhook_publications p USING candidates c
     WHERE p.id=c.id RETURNING 1
  ) SELECT count(*)::integer INTO v_count FROM deleted;
  RETURN v_count;
END $$;

ALTER FUNCTION webhook_publication_prune(integer,integer) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_publication_prune(integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_publication_prune(integer,integer) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_publication_prune(integer,integer) TO setjoin_worker;
