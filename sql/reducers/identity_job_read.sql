CREATE OR REPLACE FUNCTION identity_job_read(
    p_actor_user_id BIGINT,
    p_job_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_job public.identity_jobs%ROWTYPE;
BEGIN
    SELECT * INTO v_job
      FROM public.identity_jobs
     WHERE id = p_job_id
       AND actor_user_id = p_actor_user_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN jsonb_strip_nulls(jsonb_build_object(
        'jobId', v_job.id,
        'kind', v_job.kind,
        'state', v_job.state,
        'snapshotId', v_job.snapshot_id,
        'sourceKey', (
            SELECT source_key FROM public.identity_sources
             WHERE id = v_job.source_id
        ),
        'transitionId', v_job.transition_id,
        'createdAt', v_job.created_at,
        'expiresAt', v_job.expires_at,
        'progress', v_job.progress,
        'nextAction', v_job.next_action,
        'terminal', v_job.state IN (
            'completed','completed_with_failures','failed',
            'cancelled','expired'
        ),
        'cancelRequested', v_job.cancel_requested,
        'manifestVersion', v_job.artifact_manifest->>'manifestVersion',
        'byteCount', CASE WHEN v_job.artifact IS NULL THEN NULL
                          ELSE octet_length(v_job.artifact) END,
        'sha256', CASE WHEN v_job.artifact_sha256 IS NULL THEN NULL
                       ELSE encode(v_job.artifact_sha256, 'hex') END,
        'redactionCounts', v_job.redaction_counts
    ));
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_read(bigint,uuid)'::regprocedure
);
