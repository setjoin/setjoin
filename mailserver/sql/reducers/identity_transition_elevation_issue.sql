-- Internal completion seam: a durable challenge is mandatory. The HTTP
-- challenge-complete reducer delegates here after factor verification.
CREATE OR REPLACE FUNCTION identity_transition_elevation_issue(
    p_actor BIGINT,
    p_transition_id UUID,
    p_challenge_id UUID,
    p_preview_digest TEXT,
    p_session_digest BYTEA,
    p_factor_digest BYTEA,
    p_amr TEXT[],
    p_acr TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_challenge identity_transition_challenges%ROWTYPE;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_id UUID;
    v_amr TEXT[];
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL OR p_challenge_id IS NULL
       OR p_preview_digest IS NULL
       OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_session_digest IS NULL OR octet_length(p_session_digest)<>32
       OR p_factor_digest IS NULL OR octet_length(p_factor_digest)<>32
       OR p_amr IS NULL OR cardinality(p_amr) NOT BETWEEN 2 AND 16
       OR p_acr IS NULL OR p_acr<>'aal2'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'fresh AAL2 transition step-up is required'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid","remediation":"complete the transition challenge with two verified factors"}';
    END IF;
    SELECT array_agg(DISTINCT factor ORDER BY factor) INTO v_amr
      FROM unnest(p_amr) factor;
    IF EXISTS (
        SELECT 1 FROM unnest(v_amr) factor
         WHERE factor NOT IN ('pwd','otp','hwk','swk','user','mfa')
    )
       OR NOT ('mfa'=ANY(v_amr))
       OR (
           SELECT count(*)<2
             FROM unnest(v_amr) factor
            WHERE factor IN ('pwd','otp','hwk','swk')
       ) THEN
        RAISE EXCEPTION 'fresh AAL2 transition step-up is required'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid","remediation":"complete the transition challenge with two verified factors"}';
    END IF;

    SELECT * INTO v_challenge
      FROM identity_transition_challenges
     WHERE id=p_challenge_id
       AND actor_user_id=p_actor
       AND transition_id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity transition challenge is not authorized'
            USING ERRCODE='BZ236';
    END IF;
    v_digest := decode(lower(p_preview_digest),'hex');
    IF v_challenge.preview_digest<>v_digest THEN
        RAISE EXCEPTION 'identity transition challenge digest is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;

    v_request_digest := digest(jsonb_build_object(
        'operation','challenge_complete',
        'actor',p_actor::text,
        'transitionId',p_transition_id::text,
        'challengeId',p_challenge_id::text,
        'transitionGeneration',v_challenge.transition_generation::text,
        'previewDigest',lower(p_preview_digest),
        'sessionDigest',encode(p_session_digest,'hex'),
        'factorDigest',encode(p_factor_digest,'hex'),
        'amr',to_jsonb(v_amr),
        'acr',p_acr
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,'challenge_complete:'||p_challenge_id::text,
        p_idempotency_key,p_transition_id,v_request_digest
    ) THEN
        IF v_challenge.elevation_id IS NULL THEN
            RAISE EXCEPTION 'identity transition challenge replay is incomplete'
                USING ERRCODE='BZ236';
        END IF;
        v_id := v_challenge.elevation_id;
        RETURN (
            SELECT jsonb_build_object(
                'challengeId',p_challenge_id,
                'elevationId',e.id,
                'transitionId',e.transition_id,
                'transitionGeneration',e.transition_generation::text,
                'expiresAt',e.expires_at,
                'consumed',e.consumed_at IS NOT NULL,
                'invalidated',e.invalidated_at IS NOT NULL,
                'replayed',true
            )
              FROM identity_transition_elevations e
             WHERE e.id=v_id
        );
    END IF;
    IF v_challenge.completed_at IS NOT NULL
       OR v_challenge.elevation_id IS NOT NULL
       OR v_challenge.invalidated_at IS NOT NULL
       OR v_challenge.expires_at<=statement_timestamp() THEN
        RAISE EXCEPTION 'identity transition challenge is expired, invalidated, or already completed'
            USING ERRCODE='BZ236';
    END IF;

    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND
       OR NOT EXISTS (
           SELECT 1 FROM users WHERE id=p_actor AND enabled
       )
       OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition challenge is not authorized'
            USING ERRCODE='BZ236';
    END IF;
    IF v_t.transition_generation<>v_challenge.transition_generation
       OR (v_t.state='rollback_previewed'
           AND v_t.rollback_preview_digest<>v_digest)
       OR (v_t.state<>'rollback_previewed'
           AND (v_t.state NOT IN (
                    'previewed','awaiting_approval','authorized'
                )
                OR v_t.preview_digest<>v_digest
                OR v_t.preview_expires_at<=statement_timestamp()))
       OR (v_t.state='rollback_previewed'
           AND v_t.rollback_preview_expires_at<=statement_timestamp()) THEN
        RAISE EXCEPTION 'identity transition challenge is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;

    INSERT INTO identity_transition_elevations(
        actor_user_id,transition_id,transition_generation,preview_digest,
        session_digest,factor_digest,amr,acr,expires_at,
        idempotency_key,request_digest,challenge_id
    ) VALUES(
        p_actor,p_transition_id,v_t.transition_generation,v_digest,
        p_session_digest,p_factor_digest,v_amr,p_acr,
        statement_timestamp()+interval '5 minutes',
        p_idempotency_key,v_request_digest,p_challenge_id
    )
    RETURNING id INTO v_id;
    UPDATE identity_transition_challenges
       SET completed_at=statement_timestamp(),
           elevation_id=v_id
     WHERE id=p_challenge_id
       AND completed_at IS NULL
       AND elevation_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity transition challenge was completed concurrently'
            USING ERRCODE='BZ236';
    END IF;

    RETURN (
        SELECT jsonb_build_object(
            'challengeId',p_challenge_id,
            'elevationId',e.id,
            'transitionId',e.transition_id,
            'transitionGeneration',e.transition_generation::text,
            'expiresAt',e.expires_at,
            'consumed',false,
            'invalidated',false,
            'replayed',false
        )
          FROM identity_transition_elevations e
         WHERE e.id=v_id
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_elevation_issue(bigint,uuid,uuid,text,bytea,bytea,text[],text,uuid)'::regprocedure
);
