CREATE OR REPLACE FUNCTION upgrade_intent_cancel(
    p_actor BIGINT,
    p_intent_id BIGINT,
    p_expected_generation BIGINT,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
    v_state TEXT;
    v_generation BIGINT;
BEGIN
    IF p_intent_id IS NULL OR p_intent_id<=0
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 8 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid upgrade cancellation input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    SELECT * INTO v_intent
      FROM upgrade_intents WHERE id=p_intent_id FOR UPDATE;
    IF NOT FOUND OR v_intent.state_generation<>p_expected_generation THEN
        RAISE EXCEPTION 'upgrade cancellation target is stale'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"cancel"}';
    END IF;
    IF v_intent.state='cancel_requested' THEN
        RETURN jsonb_build_object(
            'intentId',v_intent.id::text,'state',v_intent.state,
            'stateGeneration',v_intent.state_generation::text,'replayed',true
        );
    ELSIF v_intent.state IN ('awaiting_approval','approved','scheduled') THEN
        v_state := 'cancelled';
    ELSIF v_intent.state IN ('claimed','preflight','recovery_point','staged') THEN
        v_state := 'cancel_requested';
    ELSE
        RAISE EXCEPTION 'upgrade cannot be cancelled at the current boundary'
            USING ERRCODE='BZ242',
                  HINT='{"type":"upgrade_intent_state_conflict","operation":"cancel","remediation":"wait for the next manifest-declared safe boundary"}';
    END IF;
    IF v_intent.approval_request_id IS NOT NULL
       AND v_intent.state='awaiting_approval' THEN
        PERFORM approval_request_cancel(v_intent.approval_request_id,v_intent.requested_by_user_id);
    END IF;
    UPDATE upgrade_intents
       SET state=v_state,state_generation=state_generation+1,
           cancel_requested_at=statement_timestamp(),
           completed_at=CASE WHEN v_state='cancelled' THEN statement_timestamp() ELSE NULL END,
           updated_at=statement_timestamp()
     WHERE id=p_intent_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,actor_user_id,evidence
    ) VALUES(
        p_intent_id,v_generation,v_intent.state,v_state,p_actor,
        jsonb_build_object('reason',p_reason)
    );
    PERFORM audit_write(
        p_actor,'upgrade_intent_cancel_requested','upgrade_intent',p_intent_id,
        jsonb_build_object('state',v_intent.state),
        jsonb_build_object('state',v_state),NULL,p_reason,'core'
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',p_intent_id,'state',v_state,'generation',v_generation
    )::text);
    RETURN jsonb_build_object(
        'intentId',p_intent_id::text,'state',v_state,
        'stateGeneration',v_generation::text,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_cancel(bigint,bigint,bigint,text)'::regprocedure,true,false
);
