CREATE OR REPLACE FUNCTION identity_job_fail(
    p_job_id UUID,
    p_worker_id UUID,
    p_error_code TEXT,
    p_retryable BOOLEAN
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_failures INTEGER;
BEGIN
    IF p_error_code IS NULL OR octet_length(p_error_code) NOT BETWEEN 1 AND 64
       OR p_error_code !~ '^[A-Z0-9_.:-]+$' THEN
        RAISE EXCEPTION 'invalid identity job error code'
            USING ERRCODE = 'BZ228';
    END IF;
    SELECT failure_count + 1 INTO v_failures
      FROM public.identity_jobs
     WHERE id = p_job_id AND state = 'running' AND worker_id = p_worker_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity job lease is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;

    UPDATE public.identity_jobs
       SET state = CASE WHEN p_retryable AND v_failures < 20
                        THEN 'queued' ELSE 'failed' END,
           failure_count = v_failures,
           progress = progress || jsonb_build_object(
               'lastErrorCode', p_error_code
           ),
           next_action = CASE WHEN p_retryable AND v_failures < 20
                              THEN 'wait' ELSE 'inspect diagnostics' END,
           worker_id = NULL,
           lease_expires_at = NULL,
           completed_at = CASE WHEN p_retryable AND v_failures < 20
                               THEN NULL ELSE statement_timestamp() END,
           updated_at = statement_timestamp()
     WHERE id = p_job_id;
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_fail(uuid,uuid,text,boolean)'::regprocedure
);
