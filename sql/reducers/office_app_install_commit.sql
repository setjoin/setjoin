CREATE OR REPLACE FUNCTION office_app_install_commit(
  p_operation_id uuid,p_expected_generation bigint,p_executor_id text,p_lease_id uuid,
  p_image_reference text,p_image_digest text,p_artifact_receipt jsonb,p_runtime_config jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_op office_app_operations%ROWTYPE;
  v_existing office_app_revisions%ROWTYPE;
  v_revision bigint;
  v_id uuid;
  v_generation bigint;
  v_replayed boolean:=false;
BEGIN
  IF p_image_reference IS NULL OR octet_length(p_image_reference) NOT BETWEEN 1 AND 512
     OR p_image_digest !~ '^sha256:[0-9a-f]{64}$'
     OR jsonb_typeof(p_artifact_receipt)<>'object'
     OR jsonb_typeof(p_runtime_config)<>'object'
     OR octet_length(p_artifact_receipt::text)>262144
     OR octet_length(p_runtime_config::text)>65536 THEN
    RAISE EXCEPTION 'invalid managed Office install evidence' USING ERRCODE='BZ322';
  END IF;
  SELECT * INTO v_op FROM public.office_app_operations
   WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND OR v_op.state_generation<>p_expected_generation
     OR v_op.executor_id<>p_executor_id OR v_op.lease_id<>p_lease_id
     OR v_op.lease_expires_at<=statement_timestamp() THEN
    RAISE EXCEPTION 'managed Office install lease or generation changed' USING ERRCODE='BZ324';
  END IF;
  SELECT * INTO v_existing FROM public.office_app_revisions
   WHERE created_by_operation_id=p_operation_id;
  IF FOUND THEN
    v_replayed:=true;
    IF v_existing.image_reference<>p_image_reference
       OR v_existing.image_digest<>p_image_digest
       OR v_existing.artifact_receipt<>p_artifact_receipt
       OR v_existing.runtime_config<>p_runtime_config THEN
      RAISE EXCEPTION 'managed Office install replay changed evidence' USING ERRCODE='BZ326';
    END IF;
    IF v_op.state='connected_inactive' THEN
      RETURN jsonb_build_object('revisionId',v_existing.id::text,
        'revision',v_existing.revision,'state',v_op.state,
        'stateGeneration',v_op.state_generation,'replayed',true);
    END IF;
  ELSIF v_op.state='qualifying' THEN
    -- Serialize the per-app revision allocator without widening the lock to the
    -- whole table. The operation row already prevents duplicate commits for a
    -- single request; this advisory lock prevents two distinct installs from
    -- selecting the same next revision.
    PERFORM pg_advisory_xact_lock(hashtextextended('office_app_revisions:collabora-code',225));
    SELECT COALESCE(max(revision),0)+1 INTO v_revision
      FROM public.office_app_revisions WHERE app_id='collabora-code';
    INSERT INTO public.office_app_revisions(
      app_id,revision,provider_id,state,image_reference,image_digest,
      artifact_receipt,runtime_config,created_by_operation_id
    ) VALUES('collabora-code',v_revision,v_op.request->>'providerId','installed_inactive',
      p_image_reference,p_image_digest,p_artifact_receipt,p_runtime_config,p_operation_id)
    RETURNING id INTO v_id;
  ELSE
    RAISE EXCEPTION 'managed Office install is not ready to commit' USING ERRCODE='BZ324';
  END IF;
  IF v_replayed THEN
    v_id:=v_existing.id;
    v_revision:=v_existing.revision;
  END IF;
  UPDATE public.office_app_operations
     SET app_revision_id=v_id,state='connected_inactive',
         state_generation=state_generation+1,phase='installed_inactive',
         progress=jsonb_build_object('digest',p_image_digest),error=NULL,
         completed_at=statement_timestamp(),updated_at=statement_timestamp()
   WHERE id=p_operation_id AND state_generation=p_expected_generation
     AND executor_id=p_executor_id AND lease_id=p_lease_id
     AND lease_expires_at>statement_timestamp()
  RETURNING state_generation INTO v_generation;
  IF v_generation IS NULL THEN
    RAISE EXCEPTION 'managed Office install commit raced another executor' USING ERRCODE='BZ324';
  END IF;
  PERFORM public.app_notify('office_app_operation_changed',json_build_object(
    'operation_id',p_operation_id,'state','connected_inactive','generation',v_generation)::text);
  RETURN jsonb_build_object('revisionId',v_id::text,'revision',v_revision,
    'state','connected_inactive','stateGeneration',v_generation,'replayed',false);
END;
$$;
SELECT apply_worker_ownership('office_app_install_commit(uuid,bigint,text,uuid,text,text,jsonb,jsonb)'::regprocedure);
