CREATE OR REPLACE FUNCTION identity_transition_execute(
    p_actor BIGINT,
    p_transition_id UUID,
    p_preview_digest TEXT,
    p_elevation_id UUID,
    p_approval_request_id BIGINT,
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
    v_target_s identity_sources%ROWTYPE;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_recovery BOOLEAN;
    v_protected BOOLEAN;
    v_before JSONB;
    v_rows INTEGER;
    v_generation BIGINT;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_preview_digest IS NULL
       OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_elevation_id IS NULL
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition execution'
            USING ERRCODE='BZ241';
    END IF;

    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
       AND actor_user_id=p_actor
     FOR UPDATE;
    IF NOT FOUND OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition not found'
            USING ERRCODE='BZ234';
    END IF;
    v_digest := decode(lower(p_preview_digest),'hex');
    IF v_t.preview_digest<>v_digest THEN
        RAISE EXCEPTION 'identity transition preview is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    IF v_t.reason<>p_reason THEN
        RAISE EXCEPTION 'identity transition reason differs from the preview'
            USING ERRCODE='BZ240',
                  HINT='{"type":"identity_idempotency_conflict","operation":"transition_execute"}';
    END IF;
    IF v_t.authorized_generation IS NULL THEN
        RAISE EXCEPTION 'identity transition is not authorized'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid"}';
    END IF;

    v_request_digest := digest(jsonb_build_object(
        'operation','execute',
        'transitionId',p_transition_id::text,
        'authorizedGeneration',v_t.authorized_generation::text,
        'previewDigest',lower(p_preview_digest),
        'elevationId',p_elevation_id::text,
        'approvalRequestId',p_approval_request_id::text,
        'reason',p_reason
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,'execute',p_idempotency_key,p_transition_id,
        v_request_digest
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id)
               || '{"replayed":true}'::jsonb;
    END IF;

    IF NOT COALESCE((
        SELECT enabled FROM feature_toggles
         WHERE key='feature.identity_model_v2'
    ),false)
       OR NOT COALESCE((
           SELECT enabled FROM feature_toggles
            WHERE key='feature.identity_transitions'
       ),false)
       OR NOT COALESCE((
           SELECT enabled FROM feature_toggles
            WHERE key='feature.cae_runtime'
       ),false) THEN
        RAISE EXCEPTION 'identity transition admission prerequisites are disabled'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_transition_preflight"}';
    END IF;
    IF v_t.state<>'authorized'
       OR v_t.transition_generation<>v_t.authorized_generation
       OR v_t.preview_expires_at<=statement_timestamp() THEN
        RAISE EXCEPTION 'identity transition authorization is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM users WHERE id=p_actor AND enabled
    ) THEN
        RAISE EXCEPTION 'identity transition requester is disabled'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid"}';
    END IF;
    IF v_t.protected AND (
        p_approval_request_id IS DISTINCT FROM v_t.approval_request_id
        OR NOT EXISTS (
            SELECT 1
              FROM approval_requests ar
              JOIN users requester
                ON requester.id=ar.requester_user_id AND requester.enabled
              JOIN users approver
                ON approver.id=ar.decided_by_user_id AND approver.enabled
             WHERE ar.id=v_t.approval_request_id
               AND ar.consumer_type='identity.transition'
               AND ar.status='approved'
               AND ar.requester_user_id=p_actor
               AND ar.decided_by_user_id IS DISTINCT FROM p_actor
               AND ar.payload->>'transitionId'=v_t.id::text
               AND ar.payload->>'previewDigest'=lower(p_preview_digest)
               AND ar.payload->>'transitionGeneration'=
                   v_t.requested_generation::text
               AND ar.expires_at>ar.decided_at
        )
    ) THEN
        RAISE EXCEPTION 'independent approval is missing, stale, or disabled'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid"}';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||v_t.user_id::text,0
    ));
    PERFORM 1 FROM users WHERE id=v_t.user_id FOR UPDATE;
    SELECT * INTO v_a
      FROM user_lifecycle_authorities
     WHERE user_id=v_t.user_id
     FOR UPDATE;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-source:'||v_t.source_id::text,0
    ));
    SELECT * INTO v_s
      FROM identity_sources
     WHERE id=v_t.source_id
     FOR UPDATE;
    SELECT * INTO v_l
      FROM user_identity_links
     WHERE id=v_t.link_id;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-subject:'||v_t.source_id::text||':'||
        encode(digest(v_l.external_subject,'sha256'),'hex'),0
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-link:'||v_t.link_id::text,0
    ));
    SELECT * INTO v_l
      FROM user_identity_links
     WHERE id=v_t.link_id
     FOR UPDATE;

    IF v_t.kind='source_to_source' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('identity-source:'||v_t.target_source_id::text,0));
        SELECT * INTO v_target_s FROM identity_sources WHERE id=v_t.target_source_id FOR UPDATE;
        PERFORM pg_advisory_xact_lock(hashtextextended('identity-link:'||v_t.target_link_id::text,0));
        SELECT * INTO v_target_l FROM user_identity_links WHERE id=v_t.target_link_id FOR UPDATE;
    END IF;

    IF v_a.generation<>v_t.lifecycle_generation
       OR v_a.authority_kind<>'source'
       OR v_a.link_id<>v_t.link_id
       OR v_s.generation<>v_t.source_generation
       OR v_l.generation<>v_t.link_generation
       OR v_l.user_id<>v_t.user_id
       OR v_l.source_id<>v_t.source_id
       OR v_l.state<>'active'
       OR NOT ('provision'=ANY(v_l.purposes))
       OR (v_t.kind='source_to_source' AND (
           v_target_s.id IS NULL OR v_target_s.state<>'active'
           OR v_target_s.generation<>v_t.target_source_generation
           OR v_target_l.id IS NULL OR v_target_l.user_id<>v_t.user_id
           OR v_target_l.source_id<>v_t.target_source_id
           OR v_target_l.state<>'active' OR v_target_l.generation<>v_t.target_link_generation
           OR NOT ('provision'=ANY(v_target_l.purposes)))) THEN
        RAISE EXCEPTION 'identity transition state changed after preview'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;

    v_recovery := identity_recovery_available(v_t.user_id,v_l.id);
    IF NOT v_recovery THEN
        RAISE EXCEPTION 'alternate authentication and recovery are required'
            USING ERRCODE='BZ237',
                  HINT='{"type":"identity_recovery_missing"}';
    END IF;

    v_protected := EXISTS (
        SELECT 1
          FROM admin_role_assignments a
          JOIN admin_role_groups g ON g.id=a.role_group_id
         WHERE a.user_id=v_t.user_id
           AND (a.expires_at IS NULL
                OR a.expires_at>statement_timestamp())
           AND admin_assignment_active(a.eligible,a.activated_until)
           AND EXISTS (
               SELECT 1 FROM admin_permissions p
                WHERE p.permission_key=ANY(g.permissions)
                  AND p.is_sensitive
           )
    ) OR EXISTS (
        SELECT 1
          FROM system_config c,
               LATERAL jsonb_array_elements_text(c.value) x(raw)
         WHERE c.key='ca_break_glass_user_ids'
           AND x.raw::bigint=v_t.user_id
    );
    IF v_protected AND NOT v_t.protected THEN
        RAISE EXCEPTION 'identity transition protection posture changed'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_required","remediation":"re-preview and obtain independent approval"}';
    END IF;

    PERFORM identity_transition_elevation_consume(
        p_elevation_id,p_actor,p_transition_id,v_digest,
        v_t.authorized_generation
    );
    UPDATE identity_transitions
       SET execution_elevation_id=p_elevation_id
     WHERE id=p_transition_id
       AND state='authorized'
       AND transition_generation=v_t.authorized_generation;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows<>1 THEN
        RAISE EXCEPTION 'identity transition authorization was consumed concurrently'
            USING ERRCODE='BZ235';
    END IF;
    PERFORM identity_transition_set_state(
        p_transition_id,'authorized','executing',NULL
    );

    SELECT jsonb_build_object(
        'authorityKind',v_a.authority_kind,
        'authorityLinkId',v_a.link_id::text,
        'authorityGeneration',v_a.generation::text,
        'linkState',v_l.state,
        'linkPurposes',to_jsonb(v_l.purposes),
        'linkGeneration',v_l.generation::text,
        'syncSource',(SELECT sync_source FROM users WHERE id=v_t.user_id),
        'mailboxInvariant',identity_mailbox_invariant_snapshot(v_t.user_id),
        'targetLinkState',CASE WHEN v_t.kind='source_to_source' THEN v_target_l.state ELSE NULL END,
        'targetLinkGeneration',CASE WHEN v_t.kind='source_to_source' THEN v_target_l.generation::text ELSE NULL END,
        'attributeFields',COALESCE((
            SELECT jsonb_agg(a.field ORDER BY a.field)
              FROM identity_attribute_authority a
             WHERE a.user_id=v_t.user_id
               AND a.source_id=v_t.source_id
               AND a.link_id=v_t.link_id
        ),'[]'::jsonb),
        'grantIds',COALESCE((
            SELECT jsonb_agg(g.id::text ORDER BY g.id)
              FROM identity_entitlement_grants g
             WHERE g.user_id=v_t.user_id
               AND g.source_id=v_t.source_id
               AND g.link_id=v_t.link_id
               AND g.revoked_at IS NULL
        ),'[]'::jsonb)
    ) INTO v_before;

    UPDATE user_lifecycle_authorities
       SET authority_kind=CASE WHEN v_t.kind='source_to_source' THEN 'source' ELSE 'local' END,
           link_id=CASE WHEN v_t.kind='source_to_source' THEN v_t.target_link_id ELSE NULL END,
           generation=generation+1,
           established_by=p_actor,
           established_at=statement_timestamp(),
           updated_at=statement_timestamp()
     WHERE user_id=v_t.user_id
       AND generation=v_t.lifecycle_generation
       AND authority_kind='source'
       AND link_id=v_t.link_id;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows<>1 THEN
        RAISE EXCEPTION 'identity lifecycle generation changed'
            USING ERRCODE='BZ235';
    END IF;
    UPDATE user_identity_links
       SET state='detached',
           generation=generation+1,
           detached_by=p_actor,
           detached_at=statement_timestamp(),
           detached_reason=CASE WHEN v_t.kind='source_to_source' THEN 'source_to_source transition' ELSE 'directory_to_local transition' END,
           updated_at=statement_timestamp()
     WHERE id=v_t.link_id
       AND user_id=v_t.user_id
       AND source_id=v_t.source_id
       AND generation=v_t.link_generation
       AND state='active';
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows<>1 THEN
        RAISE EXCEPTION 'identity link generation changed'
            USING ERRCODE='BZ235';
    END IF;
    UPDATE identity_attribute_authority
       SET authority_kind=CASE WHEN v_t.kind='source_to_source' THEN 'source' ELSE 'local' END,
           source_id=CASE WHEN v_t.kind='source_to_source' THEN v_t.target_source_id ELSE NULL END,
           link_id=CASE WHEN v_t.kind='source_to_source' THEN v_t.target_link_id ELSE NULL END,
           local_override_state='none',
           generation=generation+1,
           updated_at=statement_timestamp()
     WHERE user_id=v_t.user_id
       AND source_id=v_t.source_id
       AND link_id=v_t.link_id;
    UPDATE identity_entitlement_grants
       SET revoked_at=statement_timestamp(),
           updated_at=statement_timestamp()
     WHERE user_id=v_t.user_id
       AND source_id=v_t.source_id
       AND link_id=v_t.link_id
       AND revoked_at IS NULL;
    UPDATE users
       SET sync_source=CASE WHEN v_t.kind='source_to_source' THEN v_target_s.kind ELSE 'local' END,
           updated_at=statement_timestamp()
     WHERE id=v_t.user_id;

    IF identity_mailbox_invariant_snapshot(v_t.user_id)<>v_before->'mailboxInvariant' THEN
        RAISE EXCEPTION 'identity transition changed mailbox ownership or address claims' USING ERRCODE='BZ235';
    END IF;

    UPDATE oauth_tokens
       SET revoked_at=statement_timestamp(),revoked_by=p_actor
     WHERE user_id=v_t.user_id AND revoked_at IS NULL;
    PERFORM revoke_user_sessions(
        v_t.user_id,'all','identity_directory_to_local',
        p_actor,NULL,NULL
    );
    DELETE FROM sessions WHERE user_id=v_t.user_id;
    DELETE FROM ws_subscriptions WHERE user_id=v_t.user_id;

    INSERT INTO identity_transition_steps(
        transition_id,ordinal,stage,state,attempt_count,
        input_digest,output_digest,started_at,finished_at
    ) VALUES(
        v_t.id,4,'authority_commit','completed',1,
        v_digest,digest(v_before::text,'sha256'),
        statement_timestamp(),statement_timestamp()
    );
    v_generation := identity_transition_set_state(
        p_transition_id,'executing','authority_committed',NULL
    );
    UPDATE identity_transitions
       SET authority_before=v_before,
           committed_lifecycle_generation=(
               SELECT generation FROM user_lifecycle_authorities
                WHERE user_id=v_t.user_id
           ),
           committed_link_generation=(
               SELECT generation FROM user_identity_links
                WHERE id=v_t.link_id
           ),
           committed_target_link_generation=CASE WHEN v_t.kind='source_to_source' THEN (
               SELECT generation FROM user_identity_links WHERE id=v_t.target_link_id
           ) ELSE NULL END,
           rollback_boundary='reversible',
           committed_at=statement_timestamp(),
           updated_at=statement_timestamp()
     WHERE id=v_t.id
       AND state='authority_committed'
       AND transition_generation=v_generation;

    INSERT INTO identity_transition_effects(
        transition_id,effect_kind
    ) VALUES
        (v_t.id,'auth_sessions'),
        (v_t.id,'livekit_sessions'),
        (v_t.id,'subscriber_notice');
    INSERT INTO identity_transition_effect_targets(
        transition_id,effect_kind,target_key
    )
    SELECT v_t.id,'livekit_sessions',
           m.room_name::text||'|u:'||v_t.user_id::text
      FROM meeting_participants p
      JOIN meetings m ON m.id=p.meeting_id
     WHERE p.identity='u:'||v_t.user_id::text
       AND p.left_at IS NULL
    ON CONFLICT DO NOTHING;
    INSERT INTO identity_transition_effect_targets(
        transition_id,effect_kind,target_key,evict_until
    )
    SELECT v_t.id,'livekit_sessions',
           a.room_name||'|'||a.identity,
           a.expires_at
      FROM identity_media_admissions a
     WHERE a.user_id=v_t.user_id
       AND a.expires_at>statement_timestamp()
    ON CONFLICT(transition_id,effect_kind,target_key) DO UPDATE
      SET evict_until=GREATEST(
          identity_transition_effect_targets.evict_until,
          EXCLUDED.evict_until
      );
    UPDATE identity_transition_effects
       SET state='completed',
           attempt_count=1,
           completed_at=statement_timestamp(),
           updated_at=statement_timestamp()
     WHERE transition_id=v_t.id
       AND effect_kind='auth_sessions';
    INSERT INTO identity_transition_steps(
        transition_id,ordinal,stage,state,attempt_count,
        input_digest,output_digest,started_at,finished_at
    ) VALUES
        (v_t.id,5,'auth_sessions','completed',1,v_digest,v_digest,
         statement_timestamp(),statement_timestamp()),
        (v_t.id,6,'livekit_sessions','pending',0,v_digest,NULL,NULL,NULL),
        (v_t.id,7,'subscriber_notice','pending',0,v_digest,NULL,NULL,NULL);
    PERFORM identity_transition_set_state(
        p_transition_id,'authority_committed','effects_pending',NULL
    );

    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,before_digest,after_digest,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_committed',p_reason,
        digest(v_before::text,'sha256'),
        digest(v_t.id::text||':effects_pending','sha256'),
        jsonb_build_object(
            'kind',v_t.kind,
            'targetSourceId',v_t.target_source_id,
            'targetLinkId',v_t.target_link_id,
            'personPreserved',true,
            'sourceGeneration',v_t.source_generation,
            'linkGeneration',v_t.link_generation,
            'lifecycleGeneration',v_t.lifecycle_generation
        )
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_execute(bigint,uuid,text,uuid,bigint,text,uuid)'::regprocedure
);
