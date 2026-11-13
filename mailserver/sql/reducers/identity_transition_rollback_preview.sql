CREATE OR REPLACE FUNCTION identity_transition_rollback_preview(
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
    v_a user_lifecycle_authorities%ROWTYPE;
    v_l user_identity_links%ROWTYPE;
    v_s identity_sources%ROWTYPE;
    v_target_l user_identity_links%ROWTYPE;
    v_boundary TEXT := 'reversible';
    v_snapshot JSONB;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_expires TIMESTAMPTZ;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity rollback preview'
            USING ERRCODE='BZ241';
    END IF;
    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND
       OR v_t.state<>'failed_recoverable'
       OR v_t.authority_before IS NULL
       OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition is not rollback-previewable'
            USING ERRCODE='BZ234';
    END IF;
    IF v_t.transition_generation<>p_expected_generation THEN
        RAISE EXCEPTION 'identity transition generation is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||v_t.user_id::text,0
    ));
    SELECT * INTO v_a FROM user_lifecycle_authorities
     WHERE user_id=v_t.user_id FOR UPDATE;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-source:'||v_t.source_id::text,0
    ));
    SELECT * INTO v_s FROM identity_sources
     WHERE id=v_t.source_id FOR UPDATE;
    IF v_s.id IS NULL THEN
        RAISE EXCEPTION 'identity rollback source is missing'
            USING ERRCODE='BZ235';
    END IF;
    SELECT * INTO v_l FROM user_identity_links
     WHERE id=v_t.link_id FOR UPDATE;
    IF v_t.kind='source_to_source' THEN
        SELECT * INTO v_target_l FROM user_identity_links WHERE id=v_t.target_link_id FOR UPDATE;
    END IF;
    IF v_l.id IS NULL
       OR (v_t.kind='source_to_source' AND v_target_l.id IS NULL) THEN
        RAISE EXCEPTION 'identity rollback link is missing'
            USING ERRCODE='BZ235';
    END IF;
    IF v_t.committed_at+interval '4 hours'<=statement_timestamp() THEN
        v_boundary := 'window_expired';
    ELSIF EXISTS (
        SELECT 1 FROM login_events le
         WHERE le.user_id=v_t.user_id
           AND le.success
           AND le.occurred_at>v_t.committed_at
    ) THEN
        v_boundary := 'new_login_observed';
    ELSIF EXISTS (
        SELECT 1 FROM identity_transition_effects e
         WHERE e.transition_id=v_t.id
           AND e.effect_kind='subscriber_notice'
           AND e.state='completed'
    ) THEN
        v_boundary := 'irreversible_effect';
    ELSIF v_a.generation<>v_t.committed_lifecycle_generation
       OR v_l.state<>'detached' OR v_l.generation<>v_t.committed_link_generation
       OR (v_t.kind='directory_to_local' AND v_a.authority_kind<>'local')
       OR (v_t.kind='source_to_source' AND (v_a.authority_kind<>'source'
         OR v_a.link_id<>v_t.target_link_id OR v_target_l.state<>'active'
         OR v_target_l.generation<>v_t.committed_target_link_generation)) THEN
        v_boundary := 'irreversible_effect';
    END IF;

    UPDATE identity_transitions
       SET rollback_boundary=v_boundary,
           updated_at=statement_timestamp()
     WHERE id=v_t.id;
    IF v_boundary<>'reversible' THEN
        RETURN identity_transition_read(p_actor,p_transition_id)
            || jsonb_build_object(
            'eligible',false,
            'boundary',v_boundary
        );
    END IF;

    v_expires := statement_timestamp()+interval '15 minutes';
    v_snapshot := jsonb_build_object(
        'version',1,
        'operation','rollback',
        'transitionId',v_t.id,
        'personId',v_t.user_id::text,
        'transitionGeneration',v_t.transition_generation::text,
        'currentLifecycleGeneration',v_a.generation::text,
        'currentLinkGeneration',v_l.generation::text,
        'currentTargetLinkGeneration',CASE WHEN v_t.kind='source_to_source' THEN v_target_l.generation::text ELSE NULL END,
        'sourceId',v_s.id::text,
        'currentSourceGeneration',v_s.generation::text,
        'currentSourceState',v_s.state,
        'sourcePostureDigest',encode(digest(jsonb_build_object(
            'kind',v_s.kind,
            'capabilities',v_s.capabilities,
            'state',v_s.state,
            'mappingVersion',v_s.mapping_version::text,
            'configKeyVersion',v_s.config_key_version::text,
            'configEnvelopeDigest',encode(
                digest(COALESCE(v_s.config_envelope,''::bytea),'sha256'),'hex'
            )
        )::text,'sha256'),'hex'),
        'restoreAuthority',v_t.authority_before,
        'effects',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'effectId',e.effect_id,
                'kind',e.effect_kind,
                'state',e.state,
                'attemptCount',e.attempt_count
            ) ORDER BY e.effect_kind)
              FROM identity_transition_effects e
             WHERE e.transition_id=v_t.id
        ),'[]'::jsonb),
        'expiresAt',v_expires
    );
    v_digest := digest(v_snapshot::text,'sha256');
    v_request_digest := digest(jsonb_build_object(
        'operation','rollback_preview',
        'transitionId',v_t.id,
        'transitionGeneration',p_expected_generation::text,
        'reason',p_reason,
        'snapshotDigest',encode(v_digest,'hex')
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,'rollback_preview',p_idempotency_key,p_transition_id,
        v_request_digest
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;
    UPDATE identity_transitions
       SET rollback_preview_digest=v_digest,
           rollback_preview_snapshot=v_snapshot,
           rollback_preview_expires_at=v_expires,
           rollback_reason=p_reason,
           rollback_approval_request_id=NULL,
           rollback_requester_elevation_id=NULL,
           rollback_approver_elevation_id=NULL,
           rollback_execution_elevation_id=NULL,
           rollback_requested_at=NULL,
           rollback_requested_generation=NULL,
           rollback_approved_by_user_id=NULL,
           rollback_approved_at=NULL,
           rollback_authorized_generation=NULL,
           updated_at=statement_timestamp()
     WHERE id=v_t.id AND state='failed_recoverable';
    PERFORM identity_transition_set_state(
        v_t.id,'failed_recoverable','rollback_previewed',NULL
    );
    INSERT INTO identity_transition_steps(
        transition_id,ordinal,stage,state,attempt_count,
        input_digest,output_digest,started_at,finished_at
    ) VALUES(
        v_t.id,8,'rollback_preview','completed',1,
        v_request_digest,v_digest,
        statement_timestamp(),statement_timestamp()
    )
    ON CONFLICT(transition_id,stage) DO UPDATE
        SET state='completed',
            attempt_count=identity_transition_steps.attempt_count+1,
            input_digest=EXCLUDED.input_digest,
            output_digest=EXCLUDED.output_digest,
            started_at=EXCLUDED.started_at,
            finished_at=EXCLUDED.finished_at,
            error_code=NULL,error_detail=NULL;
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,after_digest,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_rollback_previewed',p_reason,v_digest,
        jsonb_build_object('expiresAt',v_expires)
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_rollback_preview(bigint,uuid,bigint,text,uuid)'::regprocedure
);
