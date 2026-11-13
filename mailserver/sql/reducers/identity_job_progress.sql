CREATE OR REPLACE FUNCTION identity_job_progress(
    p_job_id UUID,
    p_worker_id UUID,
    p_progress JSONB,
    p_next_action TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_progress IS NULL OR jsonb_typeof(p_progress) <> 'object'
       OR octet_length(p_progress::text) > 65536
       OR p_next_action IS NULL
       OR octet_length(p_next_action) NOT BETWEEN 1 AND 256
       OR p_next_action ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity job progress'
            USING ERRCODE = 'BZ228';
    END IF;
    UPDATE public.identity_jobs
       SET state = 'queued',
           progress = p_progress,
           next_action = p_next_action,
           worker_id = NULL,
           lease_expires_at = NULL,
           updated_at = statement_timestamp()
     WHERE id = p_job_id
       AND state = 'running'
       AND worker_id = p_worker_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity job lease is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_progress(uuid,uuid,jsonb,text)'::regprocedure
);
