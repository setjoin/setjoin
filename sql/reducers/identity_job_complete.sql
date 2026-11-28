CREATE OR REPLACE FUNCTION identity_job_complete(
    p_job_id UUID,
    p_worker_id UUID,
    p_state TEXT,
    p_progress JSONB,
    p_artifact BYTEA,
    p_manifest JSONB,
    p_redaction_counts JSONB
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_job public.identity_jobs%ROWTYPE;
BEGIN
    IF p_state NOT IN ('completed','completed_with_failures')
       OR p_progress IS NULL OR jsonb_typeof(p_progress) <> 'object'
       OR octet_length(p_progress::text) > 65536
       OR (p_artifact IS NOT NULL AND octet_length(p_artifact) > 26214400)
       OR ((p_artifact IS NULL) <> (p_manifest IS NULL))
       OR ((p_artifact IS NULL) <> (p_redaction_counts IS NULL))
       OR (p_manifest IS NOT NULL AND jsonb_typeof(p_manifest) <> 'object')
       OR (p_redaction_counts IS NOT NULL
           AND jsonb_typeof(p_redaction_counts) <> 'object') THEN
        RAISE EXCEPTION 'invalid identity job completion'
            USING ERRCODE = 'BZ228';
    END IF;
    UPDATE public.identity_jobs
       SET state = p_state,
           progress = p_progress,
           next_action = CASE WHEN p_state = 'completed'
                              THEN 'none' ELSE 'inspect results' END,
           artifact = p_artifact,
           artifact_sha256 = CASE WHEN p_artifact IS NULL THEN NULL
                                  ELSE digest(p_artifact, 'sha256') END,
           artifact_manifest = p_manifest,
           redaction_counts = p_redaction_counts,
           worker_id = NULL,
           lease_expires_at = NULL,
           completed_at = statement_timestamp(),
           updated_at = statement_timestamp()
     WHERE id = p_job_id
       AND state = 'running'
       AND worker_id = p_worker_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity job lease is stale'
            USING ERRCODE = 'BZ229',
                      HINT = '{"type":"identity_generation_stale"}';
    END IF;
    IF p_artifact IS NOT NULL THEN
        SELECT * INTO v_job FROM public.identity_jobs WHERE id = p_job_id;
        PERFORM audit_write(
            v_job.actor_user_id, 'identity.diagnostics.ready', 'identity_job',
            NULL, NULL,
            jsonb_build_object(
                'jobId', p_job_id,
                'byteCount', octet_length(p_artifact),
                'sha256', encode(digest(p_artifact, 'sha256'), 'hex'),
                'expiresAt', v_job.expires_at
            ),
            NULL, 'sanitized diagnostic bundle ready', 'core'
        );
    END IF;
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_complete(uuid,uuid,text,jsonb,bytea,jsonb,jsonb)'::regprocedure
);
