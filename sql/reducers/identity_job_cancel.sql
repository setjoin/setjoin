CREATE OR REPLACE FUNCTION identity_job_cancel(
    p_actor_user_id BIGINT,
    p_job_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_job public.identity_jobs%ROWTYPE;
BEGIN
    SELECT * INTO v_job
      FROM public.identity_jobs
     WHERE id = p_job_id AND actor_user_id = p_actor_user_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF v_job.state IN (
        'completed','completed_with_failures','failed','cancelled','expired'
    ) THEN
        RETURN identity_job_read(p_actor_user_id, p_job_id);
    END IF;
    IF v_job.state = 'queued' THEN
        UPDATE public.identity_jobs
           SET state = 'cancelled',
               cancel_requested = TRUE,
               completed_at = statement_timestamp(),
               updated_at = statement_timestamp(),
               next_action = 'none'
         WHERE id = p_job_id;
    ELSE
        UPDATE public.identity_jobs
           SET cancel_requested = TRUE,
               updated_at = statement_timestamp(),
               next_action = 'wait for current batch'
         WHERE id = p_job_id;
    END IF;
    RETURN identity_job_read(p_actor_user_id, p_job_id);
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_cancel(bigint,uuid)'::regprocedure
);
