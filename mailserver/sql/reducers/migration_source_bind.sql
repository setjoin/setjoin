-- migration_source_bind.sql: bind one job to one immutable source mailbox.
CREATE OR REPLACE FUNCTION migration_source_bind(
  p_job_id bigint,
  p_source_type text,
  p_source_mailbox_key text,
  p_selector_digest text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_instance public.migration_source_instances%ROWTYPE;
  v_job_source text;
BEGIN
  SELECT source_type INTO v_job_source FROM public.migration_jobs
   WHERE id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Migration job not found' USING ERRCODE='BZ049';
  END IF;
  IF NOT (p_source_type = ANY(string_to_array(v_job_source,'|'))) THEN
    RAISE EXCEPTION 'Migration source type mismatch' USING ERRCODE='BZ264';
  END IF;

  INSERT INTO public.migration_source_instances
    (job_id, source_type, source_mailbox_key, selector_digest)
  VALUES (p_job_id, p_source_type, p_source_mailbox_key, p_selector_digest)
  ON CONFLICT (job_id) DO NOTHING;

  SELECT * INTO v_instance FROM public.migration_source_instances
   WHERE job_id = p_job_id FOR UPDATE;
  IF v_instance.source_type <> p_source_type
     OR v_instance.source_mailbox_key <> p_source_mailbox_key
     OR v_instance.selector_digest <> p_selector_digest THEN
    RAISE EXCEPTION 'Migration source identity changed'
      USING ERRCODE='BZ264', HINT=jsonb_build_object(
        'type','source_identity_conflict','job_id',p_job_id)::text;
  END IF;
  RETURN v_instance.id;
END;
$$;

SELECT public.apply_worker_ownership('migration_source_bind(bigint,text,text,text)'::regprocedure);
