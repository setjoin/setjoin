-- migration_thread_reconcile_start.sql: create or resume bounded reconciliation.
CREATE OR REPLACE FUNCTION migration_thread_reconcile_start(p_job_id bigint)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_mailbox_id bigint; v_remaining bigint;
BEGIN
  SELECT target_mailbox_id INTO v_mailbox_id FROM public.migration_jobs
   WHERE id=p_job_id FOR UPDATE;
  IF v_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'Migration target mailbox is missing' USING ERRCODE='BZ270';
  END IF;
  INSERT INTO public.migration_thread_reconcile_jobs
    (job_id,target_mailbox_id,after_message_id,remaining,state,updated_at)
  VALUES(p_job_id,v_mailbox_id,0,0,'pending',now())
  ON CONFLICT(job_id) DO UPDATE SET target_mailbox_id=EXCLUDED.target_mailbox_id,
    updated_at=now();
  PERFORM 1 FROM public.migration_thread_reconcile_jobs WHERE job_id=p_job_id FOR UPDATE;
  SELECT count(*) INTO v_remaining
    FROM public.migration_source_objects o
    JOIN public.migration_source_instances i ON i.id=o.source_instance_id
    JOIN public.migration_thread_reconcile_jobs r ON r.job_id=i.job_id
   WHERE i.job_id=p_job_id AND o.object_type='mail' AND o.projection_state='applied'
     AND o.target_id>r.after_message_id;
  UPDATE public.migration_thread_reconcile_jobs SET remaining=v_remaining,
    state=CASE WHEN v_remaining=0 THEN 'completed' ELSE 'pending' END,
    lease_until=NULL,attempts=0,updated_at=now() WHERE job_id=p_job_id;
  RETURN jsonb_build_object('remaining',v_remaining);
END;
$$;

SELECT public.apply_worker_ownership('migration_thread_reconcile_start(bigint)'::regprocedure);
