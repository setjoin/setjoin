CREATE OR REPLACE FUNCTION office_app_operation_recover_request(
  p_user_id bigint,p_operation_id uuid,p_expected_generation bigint,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_op office_app_operations%ROWTYPE;
  v_generation bigint;
  v_state text;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'apps.manage') THEN
    RAISE EXCEPTION 'application management forbidden' USING ERRCODE='BZ323';
  END IF;
  IF p_operation_id IS NULL OR COALESCE(p_expected_generation,0)<=0
     OR NULLIF(btrim(p_reason),'') IS NULL THEN
    RAISE EXCEPTION 'invalid managed Office recovery request' USING ERRCODE='BZ322';
  END IF;
  SELECT * INTO v_op FROM public.office_app_operations
   WHERE id=p_operation_id AND app_id='collabora-code' FOR UPDATE;
  IF NOT FOUND OR v_op.state_generation<>p_expected_generation THEN
    RAISE EXCEPTION 'managed Office operation is not recoverable' USING ERRCODE='BZ324';
  END IF;
  IF v_op.state='paused_recoverable' THEN
    -- Already-paused row: expire the lease so the reclaim arm swaps the
    -- executor and the resumed run advances paused_recoverable -> preflight.
    v_state:='paused_recoverable';
    UPDATE public.office_app_operations
       SET state_generation=state_generation+1,phase='recovery_requested',
           progress=progress||jsonb_build_object('recoveryRequestedAt',statement_timestamp()),
           lease_expires_at=statement_timestamp()-interval '1 second',
           last_heartbeat_at=LEAST(last_heartbeat_at,statement_timestamp()-interval '2 seconds'),
           updated_at=statement_timestamp()
     WHERE id=p_operation_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
  ELSIF v_op.state='failed_terminal'
        AND v_op.error->>'code'='ROLLBACK_FAILED'
        AND v_op.executor_id IS NOT NULL AND v_op.lease_id IS NOT NULL THEN
    -- Persistent-cleanup-failure recovery: re-arm the in-flight rollback
    -- window so the executor reclaim completes the fence-checked test-runtime
    -- removal. The ownership fence itself is never cleared here; a cleanup
    -- that fails again lands ROLLBACK_FAILED on failed_terminal and stays
    -- admin-recoverable, never silently cleared.
    v_state:='rolling_back';
    UPDATE public.office_app_operations
       SET state='rolling_back',state_generation=state_generation+1,
           phase='recovery_requested',completed_at=NULL,
           progress=progress||jsonb_build_object('recoveryRequestedAt',statement_timestamp(),
             'recoveryKind','rollback_cleanup_retry'),
           lease_expires_at=statement_timestamp()-interval '1 second',
           last_heartbeat_at=statement_timestamp()-interval '2 seconds',
           updated_at=statement_timestamp()
     WHERE id=p_operation_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
  ELSE
    RAISE EXCEPTION 'managed Office operation is not recoverable' USING ERRCODE='BZ324';
  END IF;
  PERFORM public.audit_write(p_user_id,'office.app.operation.recovery_requested',
    'office_app_operation',NULL,NULL,jsonb_build_object(
      'operationId',p_operation_id::text,'generation',v_generation,
      'recoveredState',v_state),NULL,p_reason,'core');
  PERFORM public.app_notify('office_app_operation_changed',json_build_object(
    'operation_id',p_operation_id,'state',v_state,'generation',v_generation)::text);
  RETURN jsonb_build_object('operationId',p_operation_id::text,
    'state',v_state,'stateGeneration',v_generation,
    'phase','recovery_requested','recoveryRequested',true);
END;
$$;
SELECT apply_worker_ownership('office_app_operation_recover_request(bigint,uuid,bigint,text)'::regprocedure);
