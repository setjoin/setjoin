CREATE OR REPLACE FUNCTION identity_job_claim(
    p_worker_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_job public.identity_jobs%ROWTYPE;
BEGIN
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'identity job worker id is required'
            USING ERRCODE = 'BZ228';
    END IF;

    UPDATE public.identity_jobs
       SET state = 'expired',
           completed_at = statement_timestamp(),
           updated_at = statement_timestamp(),
           next_action = 'create a new job',
           worker_id = NULL,
           lease_expires_at = NULL
     WHERE state IN ('queued','running')
       AND expires_at <= statement_timestamp();

    SELECT * INTO v_job
      FROM public.identity_jobs
     WHERE (
            state = 'queued'
            OR (state = 'running' AND lease_expires_at <= statement_timestamp())
           )
       AND expires_at > statement_timestamp()
     ORDER BY created_at, id
     FOR UPDATE SKIP LOCKED
     LIMIT 1;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF v_job.cancel_requested THEN
        UPDATE public.identity_jobs
           SET state = 'cancelled',
               completed_at = statement_timestamp(),
               updated_at = statement_timestamp(),
               next_action = 'none',
               worker_id = NULL,
               lease_expires_at = NULL
         WHERE id = v_job.id;
        RETURN NULL;
    END IF;

    UPDATE public.identity_jobs
       SET state = 'running',
           worker_id = p_worker_id,
           lease_expires_at = statement_timestamp() + interval '60 seconds',
           attempt_count = attempt_count + 1,
           started_at = COALESCE(started_at, statement_timestamp()),
           updated_at = statement_timestamp(),
           next_action = 'wait'
     WHERE id = v_job.id
     RETURNING * INTO v_job;

    RETURN jsonb_build_object(
        'jobId', v_job.id,
        'kind', v_job.kind,
        'actorUserId', v_job.actor_user_id::text,
        'sourceId', CASE WHEN v_job.source_id IS NULL THEN NULL
                         ELSE v_job.source_id::text END,
        'transitionId', v_job.transition_id,
        'request', v_job.request,
        'progress', v_job.progress,
        'attemptCount', v_job.attempt_count,
        'failureCount', v_job.failure_count
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_claim(uuid)'::regprocedure
);
