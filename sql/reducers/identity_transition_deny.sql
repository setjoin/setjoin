CREATE OR REPLACE FUNCTION identity_transition_deny(
    p_actor BIGINT,
    p_transition_id UUID,
    p_preview_digest TEXT,
    p_elevation_id UUID,
    p_reason TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_request approval_requests%ROWTYPE;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_is_rollback BOOLEAN;
    v_approval_id BIGINT;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_preview_digest IS NULL
       OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_elevation_id IS NULL
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition denial'
            USING ERRCODE='BZ236';
    END IF;

    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND OR p_actor=v_t.actor_user_id
       OR NOT admin_can_reach(p_actor,v_t.user_id)
       OR NOT EXISTS (
           SELECT 1
             FROM users u,
                  system_config c,
                  LATERAL jsonb_array_elements_text(c.value) x(raw)
            WHERE u.id=p_actor AND u.enabled
              AND c.key='ca_break_glass_user_ids'
              AND x.raw::bigint=p_actor
       ) THEN
        RAISE EXCEPTION 'independent denial is invalid'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid"}';
    END IF;

    v_is_rollback := v_t.state='rollback_previewed'
                     AND v_t.rollback_approval_request_id IS NOT NULL;
    IF NOT v_is_rollback AND v_t.state<>'awaiting_approval' THEN
        RAISE EXCEPTION 'identity transition is not awaiting approval'
            USING ERRCODE='BZ236';
    END IF;
    v_approval_id := CASE WHEN v_is_rollback
                          THEN v_t.rollback_approval_request_id
                          ELSE v_t.approval_request_id END;
    SELECT * INTO v_request
      FROM approval_requests
     WHERE id=v_approval_id
       AND consumer_type='identity.transition'
       AND status='pending'
     FOR UPDATE;
    IF NOT FOUND
       OR v_request.expires_at<=statement_timestamp()
       OR v_request.payload->>'transitionId'<>v_t.id::text
       OR v_request.payload->>'previewDigest'<>lower(p_preview_digest) THEN
        RAISE EXCEPTION 'identity transition approval is stale or unavailable'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid"}';
    END IF;

    v_digest := decode(lower(p_preview_digest),'hex');
    IF (v_is_rollback AND v_t.rollback_preview_digest<>v_digest)
       OR (NOT v_is_rollback AND v_t.preview_digest<>v_digest) THEN
        RAISE EXCEPTION 'identity transition preview is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    v_request_digest := digest(jsonb_build_object(
        'operation',CASE WHEN v_is_rollback
                         THEN 'rollback_deny' ELSE 'deny' END,
        'transitionId',p_transition_id::text,
        'transitionGeneration',v_t.transition_generation::text,
        'previewDigest',lower(p_preview_digest),
        'elevationId',p_elevation_id::text,
        'reason',p_reason
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,
        CASE WHEN v_is_rollback THEN 'rollback_deny' ELSE 'deny' END,
        p_idempotency_key,p_transition_id,v_request_digest
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;

    PERFORM identity_transition_elevation_consume(
        p_elevation_id,p_actor,p_transition_id,v_digest,
        v_t.transition_generation
    );
    PERFORM approval_decide(v_approval_id,p_actor,'deny',p_reason);
    IF v_is_rollback THEN
        UPDATE identity_transitions
           SET rollback_approver_elevation_id=p_elevation_id,
               updated_at=statement_timestamp()
         WHERE id=p_transition_id;
        PERFORM identity_transition_set_state(
            p_transition_id,'rollback_previewed','failed_recoverable',
            'rollback_denied'
        );
    ELSE
        UPDATE identity_transitions
           SET approver_elevation_id=p_elevation_id,
               updated_at=statement_timestamp()
         WHERE id=p_transition_id;
        PERFORM identity_transition_set_state(
            p_transition_id,'awaiting_approval','cancelled',NULL
        );
    END IF;
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,after_digest,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_denied',p_reason,v_digest,
        jsonb_build_object(
            'approvalRequestId',v_approval_id,
            'operation',CASE WHEN v_is_rollback
                             THEN 'rollback' ELSE 'execute' END
        )
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_deny(bigint,uuid,text,uuid,text,uuid)'::regprocedure
);
