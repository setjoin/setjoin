-- Lock and classify one calendar/contact source object before projection.
CREATE OR REPLACE FUNCTION migration_aux_object_begin(
  p_job_id bigint,p_operation_id uuid,p_object_type text,
  p_source_object_id text,p_source_version text,p_source_folder_id text,
  p_source_change text,p_content_hash text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_instance_id uuid;
  v_existing public.migration_source_objects%ROWTYPE;
  v_operation public.migration_object_operations%ROWTYPE;
BEGIN
  IF p_object_type NOT IN ('calendar','contact') OR p_source_object_id IS NULL
     OR p_source_object_id='' OR p_source_change NOT IN ('upsert','move','delete') THEN
    RAISE EXCEPTION 'Invalid auxiliary source object envelope' USING ERRCODE='BZ265';
  END IF;
  SELECT i.id INTO v_instance_id
    FROM public.migration_source_instances i
    JOIN public.migration_jobs j ON j.id=i.job_id
   WHERE i.job_id=p_job_id AND j.target_mailbox_id IS NOT NULL
   FOR UPDATE OF i,j;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Migration source instance is not bound' USING ERRCODE='BZ265';
  END IF;

  INSERT INTO public.migration_object_operations(
    operation_id,job_id,source_instance_id,object_type,source_object_id,
    source_version,source_folder_id,source_change,content_hash,state)
  VALUES(p_operation_id,p_job_id,v_instance_id,p_object_type,p_source_object_id,
    COALESCE(p_source_version,''),COALESCE(p_source_folder_id,''),p_source_change,
    p_content_hash,'accepted')
  ON CONFLICT(operation_id) DO NOTHING;
  SELECT * INTO v_operation FROM public.migration_object_operations
   WHERE operation_id=p_operation_id FOR UPDATE;
  IF v_operation.job_id<>p_job_id OR v_operation.object_type<>p_object_type
     OR v_operation.source_object_id<>p_source_object_id
     OR v_operation.source_version<>COALESCE(p_source_version,'')
     OR v_operation.source_change<>p_source_change
     OR v_operation.content_hash IS DISTINCT FROM p_content_hash THEN
    RAISE EXCEPTION 'Migration operation replay conflict' USING ERRCODE='BZ266';
  END IF;
  IF v_operation.state='completed' THEN
    RETURN jsonb_build_object('action','replay','targetKind',v_operation.target_kind,
      'targetId',v_operation.target_id);
  END IF;

  SELECT * INTO v_existing FROM public.migration_source_objects
   WHERE source_instance_id=v_instance_id AND object_type=p_object_type
     AND source_object_id=p_source_object_id FOR UPDATE;
  IF FOUND AND v_existing.source_version=COALESCE(p_source_version,'')
     AND ((p_source_change='delete' AND v_existing.projection_state='tombstoned')
       OR (p_source_change<>'delete' AND v_existing.projection_state='applied')) THEN
    UPDATE public.migration_object_operations SET state='completed',
      target_kind=v_existing.target_kind,target_id=v_existing.target_id,completed_at=now()
     WHERE operation_id=p_operation_id;
    RETURN jsonb_build_object('action','unchanged','targetKind',v_existing.target_kind,
      'targetId',v_existing.target_id);
  END IF;
  RETURN jsonb_build_object('action',CASE WHEN p_source_change='delete' THEN 'delete' ELSE 'apply' END,
    'targetKind',v_existing.target_kind,'targetId',v_existing.target_id);
END;
$$;

-- Worker-only function ACLs (security_event_enqueue.sql:72-78 form, #536). NOT
-- apply_worker_ownership(): that applicator grants setjoin_app EXECUTE, and these definer
-- functions take a caller-chosen job id that alone selects the target mailbox, so only the
-- migration worker credential may run them.
ALTER FUNCTION migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text) FROM setjoin_app;
REVOKE ALL ON FUNCTION migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text) FROM setjoin_owner;
GRANT EXECUTE ON FUNCTION migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text) TO setjoin_worker;
