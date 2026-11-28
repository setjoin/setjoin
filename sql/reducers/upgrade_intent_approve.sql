CREATE OR REPLACE FUNCTION upgrade_intent_approve(
    p_actor BIGINT,
    p_intent_id BIGINT,
    p_expected_generation BIGINT,
    p_decision TEXT,
    p_comment TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
    v_status TEXT;
    v_state TEXT;
    v_generation BIGINT;
BEGIN
    IF p_intent_id IS NULL OR p_intent_id<=0 OR p_expected_generation IS NULL
       OR p_expected_generation<=0 OR p_decision NOT IN ('approve','deny')
       OR (p_comment IS NOT NULL AND (
            octet_length(p_comment)>1024 OR p_comment ~ '[[:cntrl:]]'
       )) THEN
        RAISE EXCEPTION 'invalid upgrade approval input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    SELECT * INTO v_intent
      FROM upgrade_intents
     WHERE id=p_intent_id FOR UPDATE;
    IF NOT FOUND OR v_intent.state<>'awaiting_approval'
       OR v_intent.state_generation<>p_expected_generation
       OR v_intent.approval_request_id IS NULL
       OR v_intent.expires_at<=statement_timestamp()
       OR v_intent.requested_by_user_id=p_actor THEN
        RAISE EXCEPTION 'upgrade approval target is stale or not independently approvable'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"approval"}';
    END IF;
    v_status := approval_decide(
        v_intent.approval_request_id,p_actor,p_decision,p_comment
    );
    IF v_status='approved' THEN
        v_state := CASE WHEN v_intent.schedule_at IS NOT NULL
                            AND v_intent.schedule_at>statement_timestamp()
                        THEN 'scheduled' ELSE 'approved' END;
    ELSE
        v_state := 'cancelled';
    END IF;
    UPDATE upgrade_intents
       SET state=v_state,state_generation=state_generation+1,
           approved_by_user_id=CASE WHEN v_status='approved' THEN p_actor ELSE NULL END,
           completed_at=CASE WHEN v_state='cancelled' THEN statement_timestamp() ELSE NULL END,
           updated_at=statement_timestamp()
     WHERE id=p_intent_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,actor_user_id,evidence
    ) VALUES(
        p_intent_id,v_generation,'awaiting_approval',v_state,p_actor,
        jsonb_build_object('decision',p_decision,'approvalRequestId',v_intent.approval_request_id::text)
    );
    PERFORM audit_write(
        p_actor,'upgrade_intent_'||v_status,'upgrade_intent',p_intent_id,
        jsonb_build_object('state','awaiting_approval'),
        jsonb_build_object('state',v_state),NULL,p_comment,'core'
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',p_intent_id,'state',v_state,'generation',v_generation
    )::text);
    RETURN jsonb_build_object(
        'intentId',p_intent_id::text,'state',v_state,
        'stateGeneration',v_generation::text
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_approve(bigint,bigint,bigint,text,text)'::regprocedure,
    true,false
);
