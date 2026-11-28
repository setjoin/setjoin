CREATE OR REPLACE FUNCTION upgrade_challenge_issue(
    p_actor BIGINT,
    p_release_id TEXT,
    p_reason TEXT,
    p_schedule_at TIMESTAMPTZ,
    p_preview_digest TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_preview JSONB;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_existing upgrade_challenges%ROWTYPE;
    v_id UUID;
BEGIN
    IF p_preview_digest IS NULL OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid upgrade challenge input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    v_preview := upgrade_preview_payload(
        p_actor,p_release_id,p_reason,p_schedule_at
    );
    v_digest := digest(v_preview::text,'sha256');
    IF v_digest<>decode(lower(p_preview_digest),'hex') THEN
        RAISE EXCEPTION 'upgrade preview is stale'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale","reason":"preview_digest"}';
    END IF;
    v_request_digest := digest(jsonb_build_object(
        'operation','upgrade_challenge_issue',
        'actorId',p_actor::text,
        'releaseId',p_release_id,
        'previewDigest',lower(p_preview_digest),
        'idempotencyKey',p_idempotency_key::text
    )::text,'sha256');

    SELECT * INTO v_existing
      FROM upgrade_challenges
     WHERE actor_user_id=p_actor AND idempotency_key=p_idempotency_key
     FOR UPDATE;
    IF FOUND THEN
        IF v_existing.request_digest<>v_request_digest THEN
            RAISE EXCEPTION 'upgrade challenge idempotency key was reused'
                USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"challenge"}';
        END IF;
        RETURN jsonb_build_object(
            'challengeId',v_existing.id,
            'expiresAt',v_existing.expires_at,
            'completed',v_existing.completed_at IS NOT NULL,
            'replayed',true
        );
    END IF;

    INSERT INTO upgrade_challenges(
        actor_user_id,release_id,preview_digest,readiness_generation,
        policy_generation,expires_at,idempotency_key,request_digest
    ) VALUES(
        p_actor,p_release_id,v_digest,
        (v_preview->>'readinessGeneration')::bigint,
        (v_preview->>'policyGeneration')::bigint,
        statement_timestamp()+interval '5 minutes',
        p_idempotency_key,v_request_digest
    ) RETURNING id INTO v_id;
    PERFORM audit_write(
        p_actor,'upgrade_step_up_challenge_issued','upgrade_release',NULL,NULL,
        jsonb_build_object(
            'releaseId',p_release_id,'previewDigest',lower(p_preview_digest),
            'challengeId',v_id::text
        ),NULL,NULL,'core'
    );
    RETURN jsonb_build_object(
        'challengeId',v_id,
        'expiresAt',statement_timestamp()+interval '5 minutes',
        'completed',false,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_challenge_issue(bigint,text,text,timestamptz,text,uuid)'::regprocedure,
    true,false
);
