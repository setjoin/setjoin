CREATE OR REPLACE FUNCTION identity_job_results(
    p_actor_user_id BIGINT,
    p_job_id UUID,
    p_after_sequence BIGINT,
    p_limit INTEGER
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500
       OR COALESCE(p_after_sequence, 0) < 0 THEN
        RAISE EXCEPTION 'invalid identity job results page'
            USING ERRCODE = 'BZ228';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.identity_jobs
         WHERE id = p_job_id AND actor_user_id = p_actor_user_id
    ) THEN
        RETURN NULL;
    END IF;
    RETURN jsonb_build_object(
        'items', COALESCE((
            SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                'sequence', r.sequence::text,
                'userId', CASE WHEN r.user_id IS NULL THEN NULL
                               ELSE r.user_id::text END,
                'state', r.state,
                'result', r.result,
                'createdAt', r.created_at
            )) ORDER BY r.sequence)
              FROM (
                  SELECT *
                    FROM public.identity_job_results
                   WHERE job_id = p_job_id
                     AND sequence > COALESCE(p_after_sequence, 0)
                   ORDER BY sequence
                   LIMIT p_limit
              ) r
        ), '[]'::jsonb),
        'nextSequence', (
            SELECT max(sequence)::text
              FROM (
                  SELECT sequence
                    FROM public.identity_job_results
                   WHERE job_id = p_job_id
                     AND sequence > COALESCE(p_after_sequence, 0)
                   ORDER BY sequence
                   LIMIT p_limit
              ) page
        )
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_results(bigint,uuid,bigint,integer)'::regprocedure
);
