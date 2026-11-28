CREATE OR REPLACE FUNCTION office_app_operation_heartbeat(
  p_operation_id uuid,p_expected_generation bigint,p_executor_id text,
  p_lease_id uuid,p_lease_seconds integer DEFAULT 30
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_expires_at timestamptz;
BEGIN
  IF p_operation_id IS NULL OR COALESCE(p_expected_generation,0)<=0
     OR p_executor_id IS NULL OR p_executor_id !~ '^[A-Za-z0-9._:-]{1,128}$'
     OR p_lease_id IS NULL OR p_lease_seconds NOT BETWEEN 10 AND 300 THEN
    RAISE EXCEPTION 'invalid managed Office heartbeat' USING ERRCODE='BZ322';
  END IF;
  UPDATE public.office_app_operations
     SET last_heartbeat_at=statement_timestamp(),
         lease_expires_at=statement_timestamp()+make_interval(secs=>p_lease_seconds),
         updated_at=statement_timestamp()
   WHERE id=p_operation_id AND state_generation=p_expected_generation
     AND executor_id=p_executor_id AND lease_id=p_lease_id
     AND lease_expires_at>statement_timestamp()
  RETURNING lease_expires_at INTO v_expires_at;
  IF v_expires_at IS NULL THEN
    RAISE EXCEPTION 'managed Office operation lease changed or expired' USING ERRCODE='BZ324';
  END IF;
  RETURN jsonb_build_object('operationId',p_operation_id::text,
    'stateGeneration',p_expected_generation,'leaseExpiresAt',v_expires_at);
END;
$$;
SELECT apply_worker_ownership('office_app_operation_heartbeat(uuid,bigint,text,uuid,integer)'::regprocedure);
