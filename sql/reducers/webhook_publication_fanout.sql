CREATE OR REPLACE FUNCTION webhook_publication_fanout(
  p_publication_id bigint,
  p_worker_id uuid
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_count integer;
BEGIN
  WITH fact AS (
    SELECT * FROM webhook_publications
     WHERE id=p_publication_id AND state='leased' AND lease_owner=p_worker_id
       AND lease_expires_at>=statement_timestamp()
     FOR UPDATE
  ), inserted AS (
    INSERT INTO webhook_deliveries(
      subscription_id,event_id,event_type,request_body,attempt,status)
    SELECT s.id,f.event_id,f.event_type,
      jsonb_build_object(
        'specversion','1.0','id',f.event_id,'source',f.source,
        'type',f.event_type,'time',f.created_at,'data',f.payload
      ),0,'pending'
      FROM fact f
      JOIN webhook_subscriptions s
        ON s.is_active
       AND s.event_types @> jsonb_build_array(f.event_type)
       AND (s.scope='organization'
            OR (s.scope='self' AND s.user_id=f.subject_user_id))
    ON CONFLICT(subscription_id,event_id) DO NOTHING
    RETURNING 1
  ) SELECT count(*)::integer INTO v_count FROM inserted;

  IF NOT EXISTS (SELECT 1 FROM webhook_publications
                  WHERE id=p_publication_id AND state='leased'
                    AND lease_owner=p_worker_id) THEN
    RAISE EXCEPTION 'webhook publication lease lost' USING ERRCODE='BZ301';
  END IF;
  RETURN v_count;
END $$;

ALTER FUNCTION webhook_publication_fanout(bigint,uuid) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_publication_fanout(bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_publication_fanout(bigint,uuid) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_publication_fanout(bigint,uuid) TO setjoin_worker;
