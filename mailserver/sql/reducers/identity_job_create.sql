CREATE OR REPLACE FUNCTION identity_job_create(
    p_actor_user_id BIGINT,
    p_kind TEXT,
    p_idempotency_key UUID,
    p_source_key TEXT,
    p_transition_id UUID,
    p_request JSONB,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_id BIGINT;
    v_request_digest BYTEA;
    v_existing public.identity_jobs%ROWTYPE;
    v_job public.identity_jobs%ROWTYPE;
BEGIN
    IF p_actor_user_id IS NULL OR p_idempotency_key IS NULL
       OR p_kind NOT IN ('upgrade_backfill','diagnostics','cohort_preview')
       OR p_request IS NULL OR jsonb_typeof(p_request) <> 'object'
       OR octet_length(p_request::text) > 65536
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity job request'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"job"}';
    END IF;

    IF p_source_key IS NOT NULL THEN
        SELECT id INTO v_source_id
          FROM public.identity_sources
         WHERE source_key = p_source_key;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'identity source not found'
                USING ERRCODE = 'BZ228',
                      HINT = '{"type":"identity_source_invalid","field":"sourceKey"}';
        END IF;
    END IF;

    IF p_kind = 'diagnostics'
       AND ((v_source_id IS NULL) = (p_transition_id IS NULL)) THEN
        RAISE EXCEPTION 'diagnostics requires exactly one scope'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"scope"}';
    END IF;
    IF p_kind <> 'diagnostics' AND p_transition_id IS NOT NULL THEN
        RAISE EXCEPTION 'transition scope is invalid for this job kind'
            USING ERRCODE = 'BZ228';
    END IF;
    IF p_transition_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.identity_transitions
         WHERE id = p_transition_id
    ) THEN
        RAISE EXCEPTION 'identity transition not found'
            USING ERRCODE = 'BZ238',
                  HINT = '{"type":"identity_transition_illegal"}';
    END IF;

    v_request_digest := digest(
        convert_to(
            jsonb_build_object(
                'kind', p_kind,
                'sourceId', v_source_id,
                'transitionId', p_transition_id,
                'request', p_request,
                'reason', p_reason
            )::text,
            'UTF8'
        ),
        'sha256'
    );

    SELECT * INTO v_existing
      FROM public.identity_jobs
     WHERE actor_user_id = p_actor_user_id
       AND kind = p_kind
       AND idempotency_key = p_idempotency_key;
    IF FOUND THEN
        IF v_existing.request_digest <> v_request_digest THEN
            RAISE EXCEPTION 'identity idempotency key was reused'
                USING ERRCODE = 'BZ240',
                      HINT = '{"type":"identity_idempotency_conflict"}';
        END IF;
        RETURN identity_job_read(p_actor_user_id, v_existing.id);
    END IF;

    INSERT INTO public.identity_jobs (
        kind, actor_user_id, source_id, transition_id, idempotency_key,
        request_digest, request, reason
    ) VALUES (
        p_kind, p_actor_user_id, v_source_id, p_transition_id,
        p_idempotency_key, v_request_digest, p_request, p_reason
    ) RETURNING * INTO v_job;

    IF p_kind = 'diagnostics' THEN
        PERFORM audit_write(
            p_actor_user_id, 'identity.diagnostics.create', 'identity_job',
            NULL, NULL,
            jsonb_build_object(
                'jobId', v_job.id,
                'sourceId', v_source_id,
                'transitionId', p_transition_id,
                'expiresAt', v_job.expires_at
            ),
            NULL, p_reason, 'core'
        );
    END IF;

    RETURN identity_job_read(p_actor_user_id, v_job.id);
END;
$$;

SELECT apply_worker_ownership(
    'identity_job_create(bigint,text,uuid,text,uuid,jsonb,text)'::regprocedure
);
