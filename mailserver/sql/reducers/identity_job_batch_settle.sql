CREATE OR REPLACE FUNCTION identity_job_batch_settle(
    p_job_id UUID,
    p_worker_id UUID,
    p_items JSONB,
    p_progress JSONB,
    p_complete BOOLEAN,
    p_with_failures BOOLEAN
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_item JSONB;
    v_sequence BIGINT;
    v_user_id BIGINT;
BEGIN
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array'
       OR jsonb_array_length(p_items) > 500
       OR p_progress IS NULL OR jsonb_typeof(p_progress) <> 'object'
       OR octet_length(p_progress::text) > 65536
       OR p_complete IS NULL OR p_with_failures IS NULL THEN
        RAISE EXCEPTION 'invalid identity job batch'
            USING ERRCODE = 'BZ228';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.identity_jobs
         WHERE id = p_job_id
           AND kind = 'upgrade_backfill'
           AND state = 'running'
           AND worker_id = p_worker_id
    ) THEN
        RAISE EXCEPTION 'identity job lease is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;

    SELECT COALESCE(max(sequence), 0)
      INTO v_sequence
      FROM public.identity_job_results
     WHERE job_id = p_job_id;
    FOR v_item IN SELECT value FROM jsonb_array_elements(p_items)
    LOOP
        IF jsonb_typeof(v_item) <> 'object'
           OR COALESCE(v_item->>'userId','') !~ '^[1-9][0-9]*$'
           OR COALESCE(v_item->>'state','') NOT IN (
               'completed','failed','skipped','blocked'
           )
           OR jsonb_typeof(v_item->'result') <> 'object'
           OR octet_length((v_item->'result')::text) > 65536 THEN
            RAISE EXCEPTION 'invalid identity job batch result'
                USING ERRCODE = 'BZ228';
        END IF;
        v_user_id := (v_item->>'userId')::bigint;
        v_sequence := v_sequence + 1;
        INSERT INTO public.identity_job_results(
            job_id,sequence,user_id,state,result
        ) VALUES(
            p_job_id,v_sequence,v_user_id,v_item->>'state',v_item->'result'
        )
        ON CONFLICT (job_id,user_id) WHERE user_id IS NOT NULL
        DO NOTHING;
    END LOOP;

    UPDATE public.identity_jobs
       SET state = CASE
               WHEN NOT p_complete THEN 'queued'
               WHEN p_with_failures THEN 'completed_with_failures'
               ELSE 'completed'
           END,
           progress = p_progress,
           next_action = CASE
               WHEN NOT p_complete THEN 'wait'
               WHEN p_with_failures THEN 'inspect results'
               ELSE 'none'
           END,
           worker_id = NULL,
           lease_expires_at = NULL,
           completed_at = CASE WHEN p_complete
                               THEN statement_timestamp() ELSE NULL END,
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
    'identity_job_batch_settle(uuid,uuid,jsonb,jsonb,boolean,boolean)'::regprocedure
);
