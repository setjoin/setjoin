CREATE OR REPLACE FUNCTION upgrade_intent_complete(
    p_intent_id BIGINT,
    p_expected_generation BIGINT,
    p_executor_id TEXT,
    p_lease_id UUID,
    p_terminal_state TEXT,
    p_evidence_digest TEXT,
    p_result JSONB
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
    v_release upgrade_release_catalog%ROWTYPE;
    v_ready upgrade_readiness%ROWTYPE;
    v_generation BIGINT;
    v_status TEXT;
    v_downtime INTEGER := 0;
BEGIN
    IF p_intent_id IS NULL OR p_intent_id<=0
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_executor_id IS NULL OR octet_length(p_executor_id) NOT BETWEEN 1 AND 128
       OR p_executor_id !~ '^[A-Za-z0-9._:-]+$' OR p_lease_id IS NULL
       OR p_terminal_state NOT IN ('verified','rolled_back','failed','recovery_required','cancelled')
       OR p_evidence_digest IS NULL OR p_evidence_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_result IS NULL OR jsonb_typeof(p_result)<>'object'
       OR octet_length(p_result::text)>262144 THEN
        RAISE EXCEPTION 'invalid upgrade completion input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    SELECT * INTO v_intent
      FROM upgrade_intents WHERE id=p_intent_id FOR UPDATE;
    IF FOUND AND v_intent.state=p_terminal_state
       AND v_intent.executor_id=p_executor_id AND v_intent.lease_id=p_lease_id
       AND EXISTS (
            SELECT 1 FROM upgrade_intent_events e
             WHERE e.intent_id=p_intent_id
               AND e.state_generation=v_intent.state_generation
               AND e.to_state=p_terminal_state
               AND e.executor_id=p_executor_id
               AND e.evidence_digest=decode(lower(p_evidence_digest),'hex')
               AND e.evidence=p_result
       ) THEN
        RETURN jsonb_build_object(
            'intentId',v_intent.id::text,'state',v_intent.state,
            'stateGeneration',v_intent.state_generation::text,'replayed',true
        );
    END IF;
    IF NOT FOUND OR v_intent.state_generation<>p_expected_generation
       OR v_intent.executor_id<>p_executor_id OR v_intent.lease_id<>p_lease_id
       OR NOT (
            (p_terminal_state='verified' AND v_intent.state='committed')
            OR (p_terminal_state='rolled_back' AND v_intent.state='rolling_back')
            OR (p_terminal_state='cancelled' AND v_intent.state='cancel_requested')
            OR (p_terminal_state='failed' AND v_intent.state IN (
                'claimed','preflight','recovery_point','staged'
            ))
            OR (p_terminal_state='recovery_required' AND v_intent.state IN (
                'maintenance','migrations','switched','readiness','committed','rolling_back'
            ))
       ) THEN
        RAISE EXCEPTION 'illegal or stale upgrade completion'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"complete"}';
    END IF;
    IF p_result ? 'downtimeMs'
       AND jsonb_typeof(p_result->'downtimeMs')='number'
       AND (p_result->>'downtimeMs') ~ '^[0-9]{1,9}$' THEN
        v_downtime := LEAST((p_result->>'downtimeMs')::integer,999999999);
    END IF;
    UPDATE upgrade_intents
       SET state=p_terminal_state,state_generation=state_generation+1,
           completed_at=statement_timestamp(),result=p_result,
           updated_at=statement_timestamp()
     WHERE id=p_intent_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,executor_id,
        evidence_digest,evidence
    ) VALUES(
        p_intent_id,v_generation,v_intent.state,p_terminal_state,p_executor_id,
        decode(lower(p_evidence_digest),'hex'),p_result
    );
    SELECT * INTO v_release FROM upgrade_release_catalog
     WHERE release_id=v_intent.release_id;
    SELECT * INTO v_ready FROM upgrade_readiness
     WHERE release_id=v_intent.release_id;
    v_status := CASE p_terminal_state
        WHEN 'verified' THEN 'success'
        WHEN 'rolled_back' THEN 'rolled_back'
        ELSE 'failed' END;
    INSERT INTO upgrade_history(
        from_version,to_version,binary_sha256,mode,ddl_classification,
        status,started_at,completed_at,downtime_ms,error_message
    ) VALUES(
        v_ready.source_version,v_release.version,encode(v_intent.manifest_digest,'hex'),
        'full_restart','additive_only',v_status,v_intent.created_at,
        statement_timestamp(),v_downtime,
        CASE WHEN p_terminal_state IN ('failed','recovery_required')
             THEN COALESCE(p_result->>'summary',p_terminal_state) ELSE NULL END
    );
    PERFORM audit_write(
        NULL,'upgrade_intent_'||p_terminal_state,'upgrade_intent',p_intent_id,
        jsonb_build_object('state',v_intent.state),
        jsonb_build_object(
            'state',p_terminal_state,'evidenceDigest',lower(p_evidence_digest)
        ),NULL,NULL,'core'
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',p_intent_id,'state',p_terminal_state,'generation',v_generation
    )::text);
    RETURN jsonb_build_object(
        'intentId',p_intent_id::text,'state',p_terminal_state,
        'stateGeneration',v_generation::text,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_complete(bigint,bigint,text,uuid,text,text,jsonb)'::regprocedure,
    false,true
);
