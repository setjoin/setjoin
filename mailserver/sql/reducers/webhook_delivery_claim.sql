CREATE OR REPLACE FUNCTION webhook_delivery_claim(
  p_worker_id uuid,
  p_limit integer DEFAULT 16,
  p_event_id text DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_rows jsonb;
BEGIN
  IF p_worker_id IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'invalid webhook delivery claim' USING ERRCODE='BZ301';
  END IF;

  -- An expired in-flight attempt still consumes the bounded attempt budget.
  -- If retry is disabled (or the total-attempt ceiling was reached), make the
  -- crash residue terminal instead of leaving it pending forever or reclaiming
  -- it without limit.
  UPDATE webhook_deliveries d
     SET status='exhausted',lease_owner=NULL,lease_expires_at=NULL,
         completed_at=statement_timestamp(),error_message='delivery lease expired'
    FROM webhook_subscriptions s
   WHERE s.id=d.subscription_id AND d.status='pending' AND d.attempt>0
     AND d.lease_expires_at<statement_timestamp()
     AND (NOT s.retry_enabled OR d.attempt>=s.max_retries);

  WITH candidates AS (
    SELECT d.id
      FROM webhook_deliveries d
      JOIN webhook_subscriptions s ON s.id=d.subscription_id
     WHERE s.is_active
       AND (p_event_id IS NULL OR d.event_id=p_event_id)
       AND d.next_attempt_at<=statement_timestamp()
       AND (d.lease_owner IS NULL OR d.lease_expires_at<statement_timestamp())
       AND (
         (d.status='pending' AND (d.attempt=0 OR (
           d.lease_owner IS NOT NULL AND d.lease_expires_at<statement_timestamp()
           AND s.retry_enabled AND d.attempt<s.max_retries
         )))
         OR (d.status='failed' AND s.retry_enabled AND d.attempt<s.max_retries)
       )
     ORDER BY d.next_attempt_at,d.id
     FOR UPDATE OF d SKIP LOCKED LIMIT p_limit
  ), claimed AS (
    UPDATE webhook_deliveries d
       SET lease_owner=p_worker_id,
           lease_expires_at=statement_timestamp()+interval '45 seconds',
           attempt=d.attempt+1
      FROM candidates c
     WHERE d.id=c.id
    RETURNING d.id,d.subscription_id,d.event_id,d.event_type,d.request_body,d.attempt
  )
  SELECT COALESCE(jsonb_agg(
           to_jsonb(claimed)
           -- D6/DBSCHEMA-005: the signing secret is NOT copied into the claim
           -- envelope. It is stored as an AES-256-GCM _enc envelope SQL cannot
           -- open (the master key never enters the database); the dispatcher
           -- loads and opens it per claim via the process codec
           -- (shared/webhook LoadSubscriptionSecret), which also lazily
           -- re-seals a legacy plaintext row on first delivery.
           || jsonb_build_object('url',s.url)
           ORDER BY claimed.id
         ),'[]'::jsonb)
    INTO v_rows
    FROM claimed
    JOIN webhook_subscriptions s ON s.id=claimed.subscription_id;
  RETURN v_rows;
END $$;

ALTER FUNCTION webhook_delivery_claim(uuid,integer,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_delivery_claim(uuid,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_delivery_claim(uuid,integer,text) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_delivery_claim(uuid,integer,text) TO setjoin_worker;
