-- #446: frozen orchestrator.importAuxItem's complete transaction in one call.
-- The trusted migration worker supplies the job id; the job, never the provider,
-- determines the target mailbox, user, calendar and address book.
CREATE OR REPLACE FUNCTION rust_migration_apply_aux_object(
  p_job_id bigint, p_operation_id uuid, p_object_type text,
  p_source_object_id text, p_source_version text, p_source_folder_id text,
  p_source_change text, p_content_hash text, p_objects jsonb, p_parse_error text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_decision jsonb;
  v_result jsonb;
  v_created jsonb;
  v_mailbox_id bigint;
  v_user_id bigint;
  v_email text;
  v_calendar_id bigint;
  v_target_id bigint;
  v_old_id bigint;
  v_kind text;
BEGIN
  SELECT j.target_mailbox_id,j.user_id,u.email INTO v_mailbox_id,v_user_id,v_email
    FROM public.migration_jobs j JOIN public.users u ON u.id=j.user_id WHERE j.id=p_job_id;
  v_decision := public.migration_aux_object_begin(p_job_id,p_operation_id,p_object_type,
    p_source_object_id,p_source_version,p_source_folder_id,p_source_change,p_content_hash);
  IF v_decision->>'action' IN ('replay','unchanged') THEN
    RETURN jsonb_build_object('outcome',v_decision->>'action');
  END IF;
  v_old_id := (v_decision->>'targetId')::bigint;
  IF v_old_id IS NOT NULL THEN
    CASE v_decision->>'targetKind'
      WHEN 'calendar_event' THEN PERFORM public.jmap_calendar_event_set_destroy(v_mailbox_id,ARRAY[v_old_id]);
      WHEN 'contact' THEN PERFORM public.jmap_contact_set_destroy(v_mailbox_id,ARRAY[v_old_id]);
      WHEN '' THEN NULL;
      ELSE RAISE EXCEPTION 'unsupported migration target kind %',v_decision->>'targetKind' USING ERRCODE='BZ265';
    END CASE;
  END IF;
  IF p_source_change='delete' THEN
    PERFORM public.migration_aux_object_complete(p_job_id,p_operation_id,'tombstoned',NULL,NULL);
    RETURN jsonb_build_object('outcome','deleted');
  END IF;
  IF p_parse_error IS NOT NULL THEN
    RAISE EXCEPTION '%',p_parse_error USING ERRCODE='BZ265';
  END IF;
  IF p_object_type='calendar' THEN
    SELECT c.id INTO STRICT v_calendar_id FROM public.calendars c
      WHERE c.mailbox_id=v_mailbox_id AND c.is_default LIMIT 1;
    v_result := public.calendar_import_ics(v_mailbox_id,v_user_id,v_email,v_calendar_id,p_objects,'skip');
    v_kind := 'calendar_event';
  ELSE
    v_result := public.jmap_contact_set_create(v_mailbox_id,jsonb_build_object('source',p_objects->0));
    v_kind := 'contact';
  END IF;
  FOR v_created IN SELECT value FROM jsonb_each(v_result->'created') LOOP
    BEGIN
      v_target_id := (v_created->>'id')::bigint;
      EXIT WHEN v_target_id > 0;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
      v_target_id := NULL;
    END;
  END LOOP;
  IF COALESCE(v_target_id,0)<=0 THEN
    RAISE EXCEPTION 'projection reducer did not create an object' USING ERRCODE='BZ265';
  END IF;
  PERFORM public.migration_aux_object_complete(p_job_id,p_operation_id,'applied',v_kind,v_target_id);
  RETURN jsonb_build_object('outcome',CASE WHEN v_old_id IS NULL THEN 'imported'
    WHEN p_source_change='move' THEN 'moved' ELSE 'updated' END);
END;
$$;
-- Worker-only function ACLs (security_event_enqueue.sql:72-78 form, #536). NOT
-- apply_worker_ownership(): that applicator grants setjoin_app EXECUTE, and these definer
-- functions take a caller-chosen job id that alone selects the target mailbox, so only the
-- migration worker credential may run them.
ALTER FUNCTION rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text) FROM setjoin_app;
REVOKE ALL ON FUNCTION rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text) FROM setjoin_owner;
GRANT EXECUTE ON FUNCTION rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text) TO setjoin_worker;
