-- Complete one auxiliary projection inside the caller's projection transaction.
CREATE OR REPLACE FUNCTION migration_aux_object_complete(
  p_job_id bigint,p_operation_id uuid,p_projection_state text,
  p_target_kind text,p_target_id bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_operation public.migration_object_operations%ROWTYPE;
  v_mailbox_id bigint;
BEGIN
  SELECT j.target_mailbox_id INTO v_mailbox_id
    FROM public.migration_jobs j WHERE j.id=p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Migration job not found' USING ERRCODE='BZ265';
  END IF;
  SELECT * INTO v_operation FROM public.migration_object_operations op
   WHERE op.operation_id=p_operation_id AND op.job_id=p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Migration operation not found' USING ERRCODE='BZ265';
  END IF;
  IF p_projection_state NOT IN ('applied','tombstoned')
     OR (p_projection_state='tombstoned' AND (p_target_kind IS NOT NULL OR p_target_id IS NOT NULL))
     OR (p_projection_state='applied' AND (p_target_kind IS NULL OR p_target_id IS NULL)) THEN
    RAISE EXCEPTION 'Invalid migration projection completion' USING ERRCODE='BZ265';
  END IF;
  IF p_projection_state='applied' THEN
    IF v_operation.object_type='calendar' AND p_target_kind='calendar_event' THEN
      IF NOT EXISTS (SELECT 1 FROM public.calendar_events ce JOIN public.calendars c ON c.id=ce.calendar_id
                      WHERE ce.id=p_target_id AND c.mailbox_id=v_mailbox_id) THEN
        RAISE EXCEPTION 'Calendar projection target is not owned' USING ERRCODE='BZ265';
      END IF;
    ELSIF v_operation.object_type='contact' AND p_target_kind='contact' THEN
      IF NOT EXISTS (SELECT 1 FROM public.contacts c JOIN public.addressbooks a ON a.id=c.addressbook_id
                      WHERE c.id=p_target_id AND a.mailbox_id=v_mailbox_id) THEN
        RAISE EXCEPTION 'Contact projection target is not owned' USING ERRCODE='BZ265';
      END IF;
    ELSE
      RAISE EXCEPTION 'Migration projection target kind mismatch' USING ERRCODE='BZ265';
    END IF;
  END IF;

  INSERT INTO public.migration_source_objects(
    source_instance_id,object_type,source_object_id,source_version,source_folder_id,
    projection_state,target_kind,target_id,content_hash,applied_operation_id,applied_at)
  VALUES(v_operation.source_instance_id,v_operation.object_type,v_operation.source_object_id,
    v_operation.source_version,v_operation.source_folder_id,p_projection_state,
    p_target_kind,p_target_id,v_operation.content_hash,p_operation_id,now())
  ON CONFLICT(source_instance_id,object_type,source_object_id) DO UPDATE SET
    source_version=EXCLUDED.source_version,source_folder_id=EXCLUDED.source_folder_id,
    projection_state=EXCLUDED.projection_state,target_kind=EXCLUDED.target_kind,
    target_id=EXCLUDED.target_id,content_hash=EXCLUDED.content_hash,
    applied_operation_id=EXCLUDED.applied_operation_id,applied_at=now();
  UPDATE public.migration_object_operations SET state='completed',target_kind=p_target_kind,
    target_id=p_target_id,completed_at=now() WHERE operation_id=p_operation_id;
  RETURN jsonb_build_object('targetKind',p_target_kind,'targetId',p_target_id);
END;
$$;

-- Worker-only function ACLs (security_event_enqueue.sql:72-78 form, #536). NOT
-- apply_worker_ownership(): that applicator grants setjoin_app EXECUTE, and these definer
-- functions take a caller-chosen job id that alone selects the target mailbox, so only the
-- migration worker credential may run them.
ALTER FUNCTION migration_aux_object_complete(bigint,uuid,text,text,bigint) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION migration_aux_object_complete(bigint,uuid,text,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION migration_aux_object_complete(bigint,uuid,text,text,bigint) FROM setjoin_app;
REVOKE ALL ON FUNCTION migration_aux_object_complete(bigint,uuid,text,text,bigint) FROM setjoin_owner;
GRANT EXECUTE ON FUNCTION migration_aux_object_complete(bigint,uuid,text,text,bigint) TO setjoin_worker;
