-- migration_thread_reconcile_batch.sql: reconcile at most 1,000 projected messages.
CREATE OR REPLACE FUNCTION migration_thread_reconcile_batch(
  p_job_id bigint,p_limit integer DEFAULT 1000
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_job public.migration_thread_reconcile_jobs%ROWTYPE;
        v_row record; v_thread text; v_processed integer:=0; v_changed integer:=0;
BEGIN
  IF p_limit<1 OR p_limit>1000 THEN
    RAISE EXCEPTION 'Thread reconcile limit must be 1..1000' USING ERRCODE='BZ271';
  END IF;
  SELECT * INTO v_job FROM public.migration_thread_reconcile_jobs
   WHERE job_id=p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Thread reconcile job not found' USING ERRCODE='BZ270';
  END IF;
  IF v_job.state='completed' THEN
    RETURN jsonb_build_object('processed',0,'changed',0,'remaining',0);
  END IF;
  UPDATE public.migration_thread_reconcile_jobs SET state='running',attempts=attempts+1,
    lease_until=now()+interval '2 minutes',updated_at=now() WHERE job_id=p_job_id;
  FOR v_row IN
    SELECT m.id,m.message_id,m.in_reply_to,m.references_hdr,m.thread_id
      FROM public.migration_source_objects o
      JOIN public.migration_source_instances i ON i.id=o.source_instance_id
      JOIN public.messages m ON m.id=o.target_id AND m.mailbox_id=v_job.target_mailbox_id
     WHERE i.job_id=p_job_id AND o.object_type='mail' AND o.projection_state='applied'
       AND m.id>v_job.after_message_id
     ORDER BY m.id LIMIT p_limit FOR UPDATE OF m
  LOOP
    v_thread:=public.compute_thread_id(v_row.message_id,v_row.in_reply_to,
      v_row.references_hdr,v_job.target_mailbox_id);
    IF v_thread IS DISTINCT FROM v_row.thread_id THEN
      UPDATE public.messages SET thread_id=v_thread
       WHERE id=v_row.id AND mailbox_id=v_job.target_mailbox_id;
      PERFORM public.notify_state_change(v_job.target_mailbox_id,NULL,v_row.id,'updated');
      v_changed:=v_changed+1;
    END IF;
    v_job.after_message_id:=v_row.id;
    v_processed:=v_processed+1;
  END LOOP;
  SELECT count(*) INTO v_job.remaining
    FROM public.migration_source_objects o
    JOIN public.migration_source_instances i ON i.id=o.source_instance_id
   WHERE i.job_id=p_job_id AND o.object_type='mail' AND o.projection_state='applied'
     AND o.target_id>v_job.after_message_id;
  UPDATE public.migration_thread_reconcile_jobs SET after_message_id=v_job.after_message_id,
    remaining=v_job.remaining,state=CASE WHEN v_job.remaining=0 THEN 'completed' ELSE 'pending' END,
    lease_until=NULL,updated_at=now() WHERE job_id=p_job_id;
  RETURN jsonb_build_object('processed',v_processed,'changed',v_changed,'remaining',v_job.remaining);
END;
$$;

SELECT public.apply_worker_ownership('migration_thread_reconcile_batch(bigint,integer)'::regprocedure);
