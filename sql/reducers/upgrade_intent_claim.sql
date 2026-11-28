CREATE OR REPLACE FUNCTION upgrade_intent_claim(
    p_intent_id BIGINT,
    p_expected_generation BIGINT,
    p_executor_id TEXT,
    p_lease_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
    v_generation BIGINT;
BEGIN
    IF p_intent_id IS NULL OR p_intent_id<=0
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_executor_id IS NULL OR octet_length(p_executor_id) NOT BETWEEN 1 AND 128
       OR p_executor_id !~ '^[A-Za-z0-9._:-]+$' OR p_lease_id IS NULL THEN
        RAISE EXCEPTION 'invalid upgrade claim input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    SELECT * INTO v_intent
      FROM upgrade_intents WHERE id=p_intent_id FOR UPDATE;
    IF FOUND AND v_intent.state='claimed'
       AND v_intent.executor_id=p_executor_id AND v_intent.lease_id=p_lease_id THEN
        RETURN jsonb_build_object(
            'intentId',v_intent.id::text,'state',v_intent.state,
            'stateGeneration',v_intent.state_generation::text,
            'releaseId',v_intent.release_id,
            'manifestDigest',encode(v_intent.manifest_digest,'hex'),
            'recoverySetId',v_intent.recovery_set_id::text,
            'recoverySetDigest',encode(v_intent.recovery_set_digest,'hex'),
            'leaseId',v_intent.lease_id::text,'replayed',true
        );
    END IF;
    IF NOT FOUND OR v_intent.state_generation<>p_expected_generation
       OR v_intent.state NOT IN ('approved','scheduled')
       OR (v_intent.schedule_at IS NOT NULL AND v_intent.schedule_at>statement_timestamp())
       OR v_intent.expires_at<=statement_timestamp()
       OR NOT COALESCE((
            SELECT enabled FROM feature_toggles
             WHERE key='feature.transactional_upgrades_execution'
       ),false)
       OR NOT EXISTS (
            SELECT 1
              FROM upgrade_readiness r
              JOIN upgrade_release_catalog c USING(release_id)
              CROSS JOIN upgrade_control_state s
             WHERE r.release_id=v_intent.release_id
               AND r.readiness_generation=v_intent.readiness_generation
               AND r.manifest_digest=v_intent.manifest_digest
               AND r.status='ready' AND r.blocker_count=0
               AND r.expires_at>statement_timestamp()
               AND c.status='available'
               AND c.catalog_generation=v_intent.catalog_generation
               AND c.metadata_expires_at>statement_timestamp()
               AND (
                    c.channel='community'
                    OR c.entitlement_grace_until>statement_timestamp()
               )
               AND s.singleton AND s.policy_generation=v_intent.policy_generation
       ) THEN
        RAISE EXCEPTION 'upgrade intent is not claimable or its evidence is stale'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale","operation":"claim"}';
    END IF;
    IF v_intent.recovery_set_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM upgrade_recovery_sets recovery
         WHERE recovery.recovery_set_id=v_intent.recovery_set_id
           AND recovery.installation_id=v_intent.installation_id
           AND recovery.manifest_digest=v_intent.recovery_set_digest
           AND recovery.status='verified'
           AND recovery.expires_at>statement_timestamp()
           AND recovery.created_at>=statement_timestamp()-interval '24 hours'
    ) THEN
        RAISE EXCEPTION 'upgrade recovery set is missing, stale, or changed'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale","operation":"claim","reason":"recovery_set"}';
    END IF;
    UPDATE upgrade_intents
       SET state='claimed',state_generation=state_generation+1,
           executor_id=p_executor_id,lease_id=p_lease_id,
           claimed_at=statement_timestamp(),updated_at=statement_timestamp()
     WHERE id=p_intent_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
    IF v_generation IS NULL THEN
        RAISE EXCEPTION 'upgrade intent was claimed concurrently'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"claim"}';
    END IF;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,executor_id,evidence
    ) VALUES(
        p_intent_id,v_generation,v_intent.state,'claimed',p_executor_id,
        jsonb_build_object('leaseId',p_lease_id::text)
    );
    PERFORM audit_write(
        NULL,'upgrade_intent_claimed','upgrade_intent',p_intent_id,
        jsonb_build_object('state',v_intent.state),
        jsonb_build_object('state','claimed','executorId',p_executor_id),
        NULL,NULL,'core'
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',p_intent_id,'state','claimed','generation',v_generation
    )::text);
    RETURN jsonb_build_object(
        'intentId',p_intent_id::text,'state','claimed',
        'stateGeneration',v_generation::text,
        'releaseId',v_intent.release_id,
        'manifestDigest',encode(v_intent.manifest_digest,'hex'),
        'recoverySetId',v_intent.recovery_set_id::text,
        'recoverySetDigest',encode(v_intent.recovery_set_digest,'hex'),
        'leaseId',p_lease_id::text,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_claim(bigint,bigint,text,uuid)'::regprocedure,false,true
);
