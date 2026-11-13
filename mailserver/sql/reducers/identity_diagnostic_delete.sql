CREATE OR REPLACE FUNCTION identity_diagnostic_delete(
    p_actor_user_id BIGINT,
    p_job_id UUID,
    p_reason TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_found BOOLEAN;
BEGIN
    IF p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid diagnostic deletion reason'
            USING ERRCODE = 'BZ228';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM public.identity_jobs
         WHERE id = p_job_id
           AND actor_user_id = p_actor_user_id
           AND kind = 'diagnostics'
    ) INTO v_found;
    IF NOT v_found THEN
        RETURN FALSE;
    END IF;
    UPDATE public.identity_jobs
       SET artifact = NULL,
           artifact_sha256 = NULL,
           artifact_manifest = NULL,
           redaction_counts = NULL,
           state = 'expired',
           worker_id = NULL,
           lease_expires_at = NULL,
           completed_at = COALESCE(completed_at, statement_timestamp()),
           updated_at = statement_timestamp(),
           next_action = 'create a new job'
     WHERE id = p_job_id
       AND actor_user_id = p_actor_user_id
       AND kind = 'diagnostics'
       AND artifact IS NOT NULL;
    IF FOUND THEN
        PERFORM audit_write(
            p_actor_user_id, 'identity.diagnostics.delete', 'identity_job',
            NULL, NULL, jsonb_build_object('jobId', p_job_id),
            NULL, p_reason, 'core'
        );
    END IF;
    RETURN TRUE;
END;
$$;

SELECT apply_worker_ownership(
    'identity_diagnostic_delete(bigint,uuid,text)'::regprocedure
);
