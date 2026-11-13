CREATE OR REPLACE FUNCTION office_app_operation_claim_next(
  p_executor_id text,
  p_lease_id uuid
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_op office_app_operations%ROWTYPE;
  v_state text;
  v_generation bigint;
  v_enabled boolean;
BEGIN
  IF p_executor_id IS NULL OR p_executor_id !~ '^[A-Za-z0-9._:-]{1,128}$'
     OR p_lease_id IS NULL THEN
    RAISE EXCEPTION 'invalid managed Office claim' USING ERRCODE='BZ322';
  END IF;
  v_enabled:=COALESCE((SELECT enabled FROM public.feature_toggles
                        WHERE key='feature.office_managed_delivery'),false);
  -- Reclaim arm (state/recovery acceptance matrix): expired-lease in-flight
  -- rows — including rolling_back and paused_recoverable — re-enter execution
  -- through a state_generation bump and an executor/lease swap that never
  -- clears recorded failures or ownership fences. Terminal rows
  -- (rolled_back, failed_terminal, ...) are NEVER reclaimed here: terminal
  -- recovery runs only through the admin-authorized
  -- office_app_operation_recover_request path, which re-arms a cleanup retry
  -- by moving the row back into the reclaimable rolling_back window.
  SELECT * INTO v_op FROM public.office_app_operations
   WHERE (state='requested' AND v_enabled)
      OR (state IN ('claimed','preflight','pulling','verifying','staging','starting',
                    'qualifying','disabling_launches','draining','blocked_drain',
                    'rolling_back','paused_recoverable')
          AND lease_expires_at<=statement_timestamp())
   ORDER BY CASE WHEN state='requested' THEN 1 ELSE 0 END,created_at,id
   FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN '{}'::jsonb; END IF;
  v_state:=CASE WHEN v_op.state='requested' THEN 'claimed' ELSE v_op.state END;
  UPDATE public.office_app_operations
     SET state=v_state,state_generation=state_generation+1,
         phase=CASE WHEN v_op.state='requested' THEN 'claimed' ELSE 'reclaimed' END,
         executor_id=p_executor_id,lease_id=p_lease_id,
         claimed_at=COALESCE(claimed_at,statement_timestamp()),
         last_heartbeat_at=statement_timestamp(),
         lease_expires_at=statement_timestamp()+interval '30 seconds',
         completed_at=NULL,updated_at=statement_timestamp()
   WHERE id=v_op.id RETURNING state_generation INTO v_generation;
  PERFORM public.app_notify('office_app_operation_changed',json_build_object(
    'operation_id',v_op.id,'state',v_state,'generation',v_generation)::text);
  RETURN jsonb_build_object('operationId',v_op.id::text,'appId',v_op.app_id,
    'kind',v_op.kind,'state',v_state,'stateGeneration',v_generation,
    'executorId',p_executor_id,'leaseId',p_lease_id::text,
    'leaseExpiresAt',statement_timestamp()+interval '30 seconds',
    'reclaimed',v_op.state<>'requested','request',v_op.request);
END;
$$;
SELECT apply_worker_ownership('office_app_operation_claim_next(text,uuid)'::regprocedure);
