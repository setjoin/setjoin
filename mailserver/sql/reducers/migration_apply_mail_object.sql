-- migration_apply_mail_object.sql: exactly-once mail projection for one source object.
CREATE OR REPLACE FUNCTION migration_apply_mail_object(
  p_job_id bigint,
  p_operation_id uuid,
  p_source_object_id text,
  p_source_version text,
  p_source_folder_id text,
  p_source_change text,
  p_content_hash text,
  p_tag_id bigint,
  p_message_id text,
  p_subject text,
  p_from_addr text,
  p_from_name text,
  p_to_addrs jsonb,
  p_cc_addrs jsonb,
  p_bcc_addrs jsonb,
  p_in_reply_to text,
  p_references_hdr text,
  p_body_text text,
  p_body_html text,
  p_size_bytes bigint,
  p_is_read boolean,
  p_is_flagged boolean,
  p_raw_ref text,
  p_date timestamptz
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_instance_id uuid;
  v_mailbox_id bigint;
  v_existing public.migration_source_objects%ROWTYPE;
  v_operation public.migration_object_operations%ROWTYPE;
  v_target_id bigint;
  v_target_received_at timestamptz;
  v_had_existing boolean := false;
  v_outcome text;
BEGIN
  SELECT i.id, j.target_mailbox_id INTO v_instance_id, v_mailbox_id
    FROM public.migration_source_instances i
    JOIN public.migration_jobs j ON j.id = i.job_id
   WHERE i.job_id = p_job_id FOR UPDATE OF i, j;
  IF NOT FOUND OR v_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'Migration source instance is not bound'
      USING ERRCODE='BZ265', HINT='Call migration_source_bind first';
  END IF;
  IF p_source_object_id IS NULL OR p_source_object_id = ''
     OR p_source_change NOT IN ('upsert','move','delete') THEN
    RAISE EXCEPTION 'Invalid source object envelope' USING ERRCODE='BZ265';
  END IF;

  INSERT INTO public.migration_object_operations (
    operation_id, job_id, source_instance_id, object_type, source_object_id,
    source_version, source_folder_id, source_change, content_hash, state)
  VALUES (p_operation_id, p_job_id, v_instance_id, 'mail', p_source_object_id,
    COALESCE(p_source_version,''), COALESCE(p_source_folder_id,''), p_source_change,
    p_content_hash, 'accepted')
  ON CONFLICT (operation_id) DO NOTHING;

  SELECT * INTO v_operation FROM public.migration_object_operations
   WHERE operation_id = p_operation_id FOR UPDATE;
  IF v_operation.job_id <> p_job_id
     OR v_operation.source_object_id <> p_source_object_id
     OR v_operation.source_version <> COALESCE(p_source_version,'')
     OR v_operation.source_change <> p_source_change
     OR v_operation.content_hash IS DISTINCT FROM p_content_hash THEN
    RAISE EXCEPTION 'Migration operation replay conflict' USING ERRCODE='BZ266';
  END IF;
  IF v_operation.state = 'completed' THEN
    RETURN jsonb_build_object('replayed',true,'outcome','replayed','targetKind',v_operation.target_kind,
      'targetId',v_operation.target_id);
  END IF;

  SELECT * INTO v_existing FROM public.migration_source_objects
   WHERE source_instance_id = v_instance_id AND object_type='mail'
     AND source_object_id = p_source_object_id FOR UPDATE;
  v_had_existing := FOUND;

  IF FOUND AND v_existing.source_version = COALESCE(p_source_version,'')
     AND ((p_source_change = 'delete' AND v_existing.projection_state='tombstoned')
       OR (p_source_change <> 'delete' AND v_existing.projection_state='applied'
           AND v_existing.source_folder_id=COALESCE(p_source_folder_id,''))) THEN
    UPDATE public.migration_object_operations SET state='completed',
      target_kind=v_existing.target_kind, target_id=v_existing.target_id,
      completed_at=now() WHERE operation_id=p_operation_id;
    RETURN jsonb_build_object('replayed',true,'outcome','unchanged','targetKind',v_existing.target_kind,
      'targetId',v_existing.target_id);
  END IF;

  -- Graph message delta is folder-scoped. During a move, the destination
  -- upsert and old-folder removal can arrive in either order. Once an applied
  -- object names a different current folder, the old-folder removal is stale
  -- evidence and must not tombstone the destination projection.
  IF v_had_existing AND p_source_change='delete'
     AND v_existing.projection_state='applied'
     AND v_existing.source_folder_id<>'' AND COALESCE(p_source_folder_id,'')<>''
     AND v_existing.source_folder_id<>p_source_folder_id THEN
    UPDATE public.migration_object_operations SET state='completed',
      target_kind=v_existing.target_kind,target_id=v_existing.target_id,completed_at=now()
     WHERE operation_id=p_operation_id;
    RETURN jsonb_build_object('replayed',false,'outcome','unchanged',
      'targetKind',v_existing.target_kind,'targetId',v_existing.target_id);
  END IF;

  IF FOUND AND v_existing.projection_state='applied' THEN
    SELECT received_at INTO v_target_received_at FROM public.messages
     WHERE id=v_existing.target_id AND mailbox_id=v_mailbox_id FOR UPDATE;
    IF FOUND THEN
      DELETE FROM public.messages
       WHERE id=v_existing.target_id AND received_at=v_target_received_at
         AND mailbox_id=v_mailbox_id;
    END IF;
  END IF;

  IF p_source_change = 'delete' THEN
    INSERT INTO public.migration_source_objects (
      source_instance_id,object_type,source_object_id,source_version,
      source_folder_id,projection_state,target_kind,target_id,content_hash,
      applied_operation_id,applied_at)
    VALUES (v_instance_id,'mail',p_source_object_id,COALESCE(p_source_version,''),
      COALESCE(p_source_folder_id,''),'tombstoned',NULL,NULL,p_content_hash,
      p_operation_id,now())
    ON CONFLICT (source_instance_id,object_type,source_object_id) DO UPDATE SET
      source_version=EXCLUDED.source_version, source_folder_id=EXCLUDED.source_folder_id,
      projection_state='tombstoned', target_kind=NULL, target_id=NULL,
      content_hash=EXCLUDED.content_hash, applied_operation_id=EXCLUDED.applied_operation_id,
      applied_at=now();
  ELSE
    -- System migration path (round 4, Astra r13): import_message carries an
    -- authorization tail (p_actor_id/p_domain_scope). This reducer has no human
    -- actor, so the tail is passed as explicit NULLs by name — p_actor_id IS NULL
    -- selects the reducer's system arm that skips the statement-level
    -- authorization predicate, and named notation pins the tail so positional
    -- drift can never land an actor in the vestigial p_user_id/p_list_id params
    -- or resolve against a stale overload.
    v_target_id := public.import_message(v_mailbox_id,p_tag_id,p_message_id,p_subject,
      p_from_addr,p_from_name,p_to_addrs,p_cc_addrs,p_bcc_addrs,p_in_reply_to,
      p_references_hdr,p_body_text,p_body_html,p_size_bytes,p_is_read,p_is_flagged,
      p_raw_ref,p_date,
      p_actor_id => NULL, p_domain_scope => NULL);
    INSERT INTO public.migration_source_objects (
      source_instance_id,object_type,source_object_id,source_version,
      source_folder_id,projection_state,target_kind,target_id,content_hash,
      applied_operation_id,applied_at)
    VALUES (v_instance_id,'mail',p_source_object_id,COALESCE(p_source_version,''),
      COALESCE(p_source_folder_id,''),'applied','message',v_target_id,p_content_hash,
      p_operation_id,now())
    ON CONFLICT (source_instance_id,object_type,source_object_id) DO UPDATE SET
      source_version=EXCLUDED.source_version, source_folder_id=EXCLUDED.source_folder_id,
      projection_state='applied', target_kind='message', target_id=EXCLUDED.target_id,
      content_hash=EXCLUDED.content_hash, applied_operation_id=EXCLUDED.applied_operation_id,
      applied_at=now();
  END IF;

  UPDATE public.migration_object_operations SET state='completed',
    target_kind=CASE WHEN p_source_change='delete' THEN NULL ELSE 'message' END,
    target_id=CASE WHEN p_source_change='delete' THEN NULL ELSE v_target_id END,
    completed_at=now() WHERE operation_id=p_operation_id;

  v_outcome := CASE
    WHEN p_source_change='delete' THEN 'deleted'
    WHEN p_source_change='move' THEN 'moved'
    WHEN v_had_existing AND v_existing.source_folder_id<>COALESCE(p_source_folder_id,'') THEN 'moved'
    WHEN v_had_existing THEN 'updated'
    ELSE 'imported'
  END;
  RETURN jsonb_build_object('replayed',false,'outcome',v_outcome,'targetKind',
    CASE WHEN p_source_change='delete' THEN NULL ELSE 'message' END,
    'targetId',CASE WHEN p_source_change='delete' THEN NULL ELSE v_target_id END);
END;
$$;

SELECT public.apply_worker_ownership('migration_apply_mail_object(bigint,uuid,text,text,text,text,text,bigint,text,text,text,text,jsonb,jsonb,jsonb,text,text,text,text,bigint,boolean,boolean,text,timestamptz)'::regprocedure);
