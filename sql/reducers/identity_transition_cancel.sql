CREATE OR REPLACE FUNCTION identity_transition_cancel(
    p_actor BIGINT,
    p_transition_id UUID,
    p_expected_generation BIGINT,
    p_reason TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_request_digest BYTEA;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition cancellation'
            USING ERRCODE='BZ241';
    END IF;
    SELECT * INTO v_t
     FROM identity_transitions
     WHERE id=p_transition_id
       AND actor_user_id=p_actor
     FOR UPDATE;
    IF NOT FOUND
       OR v_t.state NOT IN (
           'previewed','awaiting_approval','authorized','failed_precommit'
       )
       OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition cannot be cancelled'
            USING ERRCODE='BZ234';
    END IF;
    IF v_t.transition_generation<>p_expected_generation THEN
        RAISE EXCEPTION 'identity transition generation is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    v_request_digest := digest(jsonb_build_object(
        'operation','cancel',
        'transitionId',p_transition_id::text,
        'transitionGeneration',p_expected_generation::text,
        'reason',p_reason
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,'cancel',p_idempotency_key,p_transition_id,
        v_request_digest
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;
    IF v_t.approval_request_id IS NOT NULL THEN
        UPDATE approval_requests
           SET status='cancelled',
               decided_at=statement_timestamp(),
               decided_by_user_id=p_actor,
               decision_comment=p_reason
         WHERE id=v_t.approval_request_id
           AND requester_user_id=p_actor
           AND status='pending';
    END IF;
    UPDATE identity_transition_elevations
       SET invalidated_at=statement_timestamp()
     WHERE transition_id=p_transition_id
       AND consumed_at IS NULL
       AND invalidated_at IS NULL;
    UPDATE identity_transition_challenges
       SET invalidated_at=statement_timestamp()
     WHERE transition_id=p_transition_id
       AND completed_at IS NULL
       AND invalidated_at IS NULL;
    PERFORM identity_transition_set_state(
        p_transition_id,v_t.state,'cancelled',NULL
    );
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_cancelled',p_reason,
        jsonb_build_object('fromState',v_t.state)
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_cancel(bigint,uuid,bigint,text,uuid)'::regprocedure
);
