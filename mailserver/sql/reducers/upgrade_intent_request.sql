CREATE OR REPLACE FUNCTION upgrade_intent_request(
    p_actor BIGINT,
    p_release_id TEXT,
    p_reason TEXT,
    p_schedule_at TIMESTAMPTZ,
    p_preview_digest TEXT,
    p_elevation_id UUID,
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
    v_control upgrade_control_state%ROWTYPE;
    v_existing upgrade_intents%ROWTYPE;
    v_elevation UUID;
    v_approval RECORD;
    v_approver RECORD;
    v_approval_id BIGINT;
    v_state TEXT;
    v_id BIGINT;
    v_expired RECORD;
BEGIN
    IF p_preview_digest IS NULL OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_elevation_id IS NULL OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid upgrade intent request'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    IF NOT COALESCE((
        SELECT enabled FROM feature_toggles
         WHERE key='feature.transactional_upgrades_execution'
    ),false) THEN
        RAISE EXCEPTION 'transactional upgrade execution is disabled'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","reason":"execution_disabled"}';
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
        'operation','upgrade_intent_request',
        'actorId',p_actor::text,'releaseId',p_release_id,
        'reason',p_reason,'scheduleAt',p_schedule_at,
        'previewDigest',lower(p_preview_digest),
        'elevationId',p_elevation_id::text
    )::text,'sha256');

    SELECT * INTO STRICT v_control
      FROM upgrade_control_state WHERE singleton FOR UPDATE;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(v_control.installation_id::text,178)
    );

    SELECT * INTO v_existing
      FROM upgrade_intents
     WHERE requested_by_user_id=p_actor
       AND idempotency_key=p_idempotency_key
     FOR UPDATE;
    IF FOUND THEN
        IF v_existing.request_digest<>v_request_digest THEN
            RAISE EXCEPTION 'upgrade intent idempotency key was reused'
                USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"request"}';
        END IF;
        RETURN jsonb_build_object(
            'intentId',v_existing.id::text,'state',v_existing.state,
            'stateGeneration',v_existing.state_generation::text,
            'approvalRequestId',CASE WHEN v_existing.approval_request_id IS NULL
                THEN NULL ELSE v_existing.approval_request_id::text END,
            'replayed',true,'existing',true
        );
    END IF;

    FOR v_expired IN
        UPDATE upgrade_intents
           SET state='expired',state_generation=state_generation+1,
               completed_at=statement_timestamp(),updated_at=statement_timestamp()
         WHERE installation_id=v_control.installation_id
           AND state IN ('awaiting_approval','approved','scheduled')
           AND expires_at<=statement_timestamp()
        RETURNING id,state_generation
    LOOP
        INSERT INTO upgrade_intent_events(
            intent_id,state_generation,from_state,to_state,evidence
        ) VALUES(
            v_expired.id,v_expired.state_generation,NULL,'expired',
            '{"reason":"lease_expired"}'::jsonb
        );
    END LOOP;

    SELECT * INTO v_existing
      FROM upgrade_intents
     WHERE installation_id=v_control.installation_id
       AND state NOT IN ('verified','rolled_back','failed','cancelled','expired')
     FOR UPDATE;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'intentId',v_existing.id::text,'state',v_existing.state,
            'stateGeneration',v_existing.state_generation::text,
            'approvalRequestId',CASE WHEN v_existing.approval_request_id IS NULL
                THEN NULL ELSE v_existing.approval_request_id::text END,
            'replayed',false,'existing',true
        );
    END IF;

    UPDATE upgrade_elevations e
       SET consumed_at=statement_timestamp()
      FROM users u
     WHERE e.id=p_elevation_id
       AND e.actor_user_id=p_actor
       AND e.release_id=p_release_id
       AND e.preview_digest=v_digest
       AND e.readiness_generation=(v_preview->>'readinessGeneration')::bigint
       AND e.policy_generation=(v_preview->>'policyGeneration')::bigint
       AND e.consumed_at IS NULL AND e.invalidated_at IS NULL
       AND e.expires_at>statement_timestamp()
       AND u.id=e.actor_user_id AND u.enabled
    RETURNING e.id INTO v_elevation;
    IF v_elevation IS NULL THEN
        RAISE EXCEPTION 'upgrade elevation is missing, expired, stale, disabled, or consumed'
            USING ERRCODE='BZ250',
                  HINT='{"type":"upgrade_authorization_invalid","remediation":"complete a fresh upgrade-scoped step-up"}';
    END IF;

    SELECT * INTO v_approval
      FROM approval_match_policies(
          'system_upgrade',jsonb_build_object(
              'channel',v_preview->>'channel',
              'target_version',v_preview->>'targetVersion',
              'scheduled',p_schedule_at IS NOT NULL
          )
      );
    IF COALESCE(v_approval.required,false) THEN
        SELECT * INTO v_approver
          FROM approval_resolve_approver(p_actor,v_approval.approver_spec);
        IF COALESCE(v_approver.skip,false)
           OR v_approver.kind IS NULL OR v_approver.ref IS NULL
           OR v_approver.ref<=0
           OR (v_approver.kind='user' AND v_approver.ref=p_actor)
           OR (v_approver.kind='user' AND NOT EXISTS (
                SELECT 1 FROM users WHERE id=v_approver.ref AND enabled
           )) THEN
            RAISE EXCEPTION 'independent upgrade approver is unavailable'
                USING ERRCODE='BZ250',
                      HINT='{"type":"upgrade_authorization_invalid","remediation":"configure a different active approver"}';
        END IF;
        v_approval_id := approval_request_create(
            'system_upgrade',p_actor,
            'System upgrade to '||(v_preview->>'targetVersion'),
            jsonb_build_object(
                'releaseId',p_release_id,
                'manifestDigest',lower(p_preview_digest),
                'policyGeneration',v_preview->>'policyGeneration'
            ),
            v_approval.winner_policy_id,v_approver.kind,v_approver.ref,240,NULL
        );
        v_state := 'awaiting_approval';
    ELSIF p_schedule_at IS NOT NULL AND p_schedule_at>statement_timestamp() THEN
        v_state := 'scheduled';
    ELSE
        v_state := 'approved';
    END IF;

    INSERT INTO upgrade_intents(
        installation_id,release_id,manifest_digest,catalog_generation,
        readiness_generation,policy_generation,preview_digest,state,
        recovery_set_id,recovery_set_digest,
        requested_by_user_id,requester_elevation_id,approval_request_id,
        reason,schedule_at,expires_at,idempotency_key,request_digest
    ) VALUES(
        v_control.installation_id,p_release_id,
        decode(v_preview->>'manifestDigest','hex'),
        (v_preview->>'catalogGeneration')::bigint,
        (v_preview->>'readinessGeneration')::bigint,
        (v_preview->>'policyGeneration')::bigint,v_digest,v_state,
        (v_preview->>'recoverySetId')::uuid,
        decode(v_preview->>'recoverySetDigest','hex'),
        p_actor,p_elevation_id,v_approval_id,p_reason,p_schedule_at,
        COALESCE(p_schedule_at,statement_timestamp())+interval '4 hours',
        p_idempotency_key,v_request_digest
    ) RETURNING id INTO v_id;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,actor_user_id,evidence_digest,evidence
    ) VALUES(
        v_id,1,NULL,v_state,p_actor,v_digest,
        jsonb_build_object(
            'releaseId',p_release_id,'approvalRequestId',
            CASE WHEN v_approval_id IS NULL THEN NULL ELSE v_approval_id::text END
        )
    );
    PERFORM audit_write(
        p_actor,'upgrade_intent_requested','upgrade_intent',v_id,NULL,
        jsonb_build_object(
            'releaseId',p_release_id,'state',v_state,
            'previewDigest',lower(p_preview_digest),
            'reason',p_reason,'scheduleAt',p_schedule_at
        ),NULL,p_reason,'core'
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',v_id,'state',v_state,'generation',1
    )::text);
    RETURN jsonb_build_object(
        'intentId',v_id::text,'state',v_state,'stateGeneration','1',
        'approvalRequestId',CASE WHEN v_approval_id IS NULL
            THEN NULL ELSE v_approval_id::text END,
        'replayed',false,'existing',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_request(bigint,text,text,timestamptz,text,uuid,uuid)'::regprocedure,
    true,false
);
