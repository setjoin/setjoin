CREATE OR REPLACE FUNCTION identity_diagnostic_download(
    p_actor_user_id BIGINT,
    p_job_id UUID
) RETURNS TABLE(
    artifact BYTEA,
    artifact_sha256 BYTEA,
    manifest_version TEXT,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_job public.identity_jobs%ROWTYPE;
BEGIN
    SELECT * INTO v_job
      FROM public.identity_jobs
     WHERE id = p_job_id
       AND actor_user_id = p_actor_user_id
       AND kind = 'diagnostics';
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF v_job.expires_at <= statement_timestamp()
       OR v_job.state = 'expired' THEN
        RAISE EXCEPTION 'identity diagnostic bundle has expired'
            USING ERRCODE = 'BZ238',
                  HINT = '{"type":"identity_transition_illegal","remediation":"create a new diagnostic bundle"}';
    END IF;
    IF v_job.state <> 'completed' OR v_job.artifact IS NULL THEN
        RAISE EXCEPTION 'identity diagnostic bundle is not ready'
            USING ERRCODE = 'BZ238',
                  HINT = '{"type":"identity_transition_illegal","remediation":"watch the diagnostic job"}';
    END IF;
    PERFORM audit_write(
        p_actor_user_id, 'identity.diagnostics.download', 'identity_job',
        NULL, NULL,
        jsonb_build_object(
            'jobId', p_job_id,
            'byteCount', octet_length(v_job.artifact),
            'sha256', encode(v_job.artifact_sha256, 'hex')
        ),
        NULL, 'sanitized diagnostic bundle downloaded', 'core'
    );
    RETURN QUERY SELECT
        v_job.artifact,
        v_job.artifact_sha256,
        COALESCE(v_job.artifact_manifest->>'manifestVersion', '1'),
        v_job.expires_at;
END;
$$;

SELECT apply_worker_ownership(
    'identity_diagnostic_download(bigint,uuid)'::regprocedure
);
