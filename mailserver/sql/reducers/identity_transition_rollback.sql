CREATE OR REPLACE FUNCTION identity_transition_rollback(
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
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_rows INTEGER;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_preview_digest IS NULL
       OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_elevation_id IS NULL
       OR p_approval_request_id IS NULL
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition rollback'
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
    IF v_t.rollback_preview_digest<>v_digest
       OR v_t.rollback_reason<>p_reason
       OR v_t.rollback_authorized_generation IS NULL THEN
        RAISE EXCEPTION 'identity rollback preview or authorization is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale","operation":"rollback"}';
    END IF;
    v_request_digest := digest(jsonb_build_object(
        'operation','rollback',
        'transitionId',p_transition_id::text,
        'authorizedGeneration',v_t.rollback_authorized_generation::text,
        'previewDigest',lower(p_preview_digest),
        'elevationId',p_elevation_id::text,
        'approvalRequestId',p_approval_request_id::text,
        'reason',p_reason
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,'rollback',p_idempotency_key,p_transition_id,
        v_request_digest
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;
    IF v_t.state<>'rollback_previewed'
       OR v_t.transition_generation<>v_t.rollback_authorized_generation
       OR v_t.rollback_preview_expires_at<=statement_timestamp()
       OR v_t.rollback_boundary<>'reversible'
       OR p_approval_request_id<>v_t.rollback_approval_request_id THEN
        RAISE EXCEPTION 'identity transition rollback is stale or unavailable'
            USING ERRCODE='BZ235';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM approval_requests ar
          JOIN users requester
            ON requester.id=ar.requester_user_id AND requester.enabled
          JOIN users approver
            ON approver.id=ar.decided_by_user_id AND approver.enabled
         WHERE ar.id=p_approval_request_id
           AND ar.consumer_type='identity.transition'
           AND ar.status='approved'
           AND ar.requester_user_id=p_actor
           AND ar.decided_by_user_id IS DISTINCT FROM p_actor
           AND ar.payload->>'transitionId'=v_t.id::text
           AND ar.payload->>'operation'='rollback'
           AND ar.payload->>'previewDigest'=lower(p_preview_digest)
           AND ar.payload->>'transitionGeneration'=
               v_t.rollback_requested_generation::text
    ) THEN
        RAISE EXCEPTION 'independent rollback approval is invalid'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid"}';
    END IF;
    IF EXISTS (
        SELECT 1 FROM login_events le
         WHERE le.user_id=v_t.user_id
           AND le.success
           AND le.occurred_at>v_t.committed_at
    ) OR EXISTS (
        SELECT 1 FROM identity_transition_effects e
         WHERE e.transition_id=v_t.id
           AND e.effect_kind='subscriber_notice'
           AND e.state='completed'
    ) THEN
        UPDATE identity_transitions
           SET rollback_boundary=CASE
               WHEN EXISTS (
                   SELECT 1 FROM login_events le
                    WHERE le.user_id=v_t.user_id
                      AND le.success
                      AND le.occurred_at>v_t.committed_at
               ) THEN 'new_login_observed'
               ELSE 'irreversible_effect'
           END,
           updated_at=statement_timestamp()
         WHERE id=v_t.id;
        RAISE EXCEPTION 'identity rollback boundary has closed'
            USING ERRCODE='BZ238',
                  HINT='{"type":"identity_effect_terminal","remediation":"continue exact forward recovery"}';
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
    SELECT * INTO v_s FROM identity_sources
     WHERE id=v_t.source_id FOR UPDATE;
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
        SELECT * INTO v_target_l FROM user_identity_links WHERE id=v_t.target_link_id FOR UPDATE;
    END IF;
    IF v_s.id IS NULL OR v_l.id IS NULL
       OR (v_t.kind='source_to_source' AND v_target_l.id IS NULL)
       OR v_s.id::text IS DISTINCT FROM
          v_t.rollback_preview_snapshot->>'sourceId'
       OR v_s.generation::text IS DISTINCT FROM
          v_t.rollback_preview_snapshot->>'currentSourceGeneration'
       OR v_s.state IS DISTINCT FROM
          v_t.rollback_preview_snapshot->>'currentSourceState'
       OR encode(digest(jsonb_build_object(
            'kind',v_s.kind,
            'capabilities',v_s.capabilities,
            'state',v_s.state,
            'mappingVersion',v_s.mapping_version::text,
            'configKeyVersion',v_s.config_key_version::text,
            'configEnvelopeDigest',encode(
                digest(COALESCE(v_s.config_envelope,''::bytea),'sha256'),'hex'
            )
          )::text,'sha256'),'hex') IS DISTINCT FROM
          v_t.rollback_preview_snapshot->>'sourcePostureDigest' THEN
        RAISE EXCEPTION 'identity rollback source changed after preview'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale","operation":"rollback"}';
    END IF;
    IF v_a.generation<>v_t.committed_lifecycle_generation
       OR v_l.state<>'detached'
       OR v_l.generation<>v_t.committed_link_generation
       OR (v_t.kind='directory_to_local' AND v_a.authority_kind<>'local')
       OR (v_t.kind='source_to_source' AND (v_a.authority_kind<>'source'
         OR v_a.link_id<>v_t.target_link_id OR v_target_l.state<>'active'
         OR v_target_l.generation<>v_t.committed_target_link_generation)) THEN
        RAISE EXCEPTION 'identity rollback authority changed after preview'
            USING ERRCODE='BZ235';
    END IF;

    PERFORM identity_transition_elevation_consume(
        p_elevation_id,p_actor,p_transition_id,v_digest,
        v_t.rollback_authorized_generation
    );
    UPDATE identity_transitions
       SET rollback_execution_elevation_id=p_elevation_id
     WHERE id=p_transition_id
       AND state='rollback_previewed'
       AND transition_generation=v_t.rollback_authorized_generation;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows<>1 THEN
        RAISE EXCEPTION 'identity rollback authorization was consumed concurrently'
            USING ERRCODE='BZ235';
    END IF;
    PERFORM identity_transition_set_state(
        p_transition_id,'rollback_previewed','rolling_back',NULL
    );

    UPDATE user_lifecycle_authorities
       SET authority_kind='source',
           link_id=v_t.link_id,
           generation=generation+1,
           established_by=p_actor,
           established_at=statement_timestamp(),
           updated_at=statement_timestamp()
     WHERE user_id=v_t.user_id
       AND ((v_t.kind='directory_to_local' AND authority_kind='local') OR
         (v_t.kind='source_to_source' AND authority_kind='source' AND link_id=v_t.target_link_id))
       AND generation=v_t.committed_lifecycle_generation;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows<>1 THEN
        RAISE EXCEPTION 'identity rollback lifecycle generation changed'
            USING ERRCODE='BZ235';
    END IF;
    IF v_t.kind='source_to_source' THEN
      UPDATE user_identity_links SET state='detached',generation=generation+1,
        detached_by=p_actor,detached_at=statement_timestamp(),detached_reason='source_to_source rollback',
        updated_at=statement_timestamp()
      WHERE id=v_t.target_link_id AND user_id=v_t.user_id AND state='active'
        AND generation=v_t.committed_target_link_generation;
      GET DIAGNOSTICS v_rows=ROW_COUNT;
      IF v_rows<>1 THEN RAISE EXCEPTION 'identity rollback target link generation changed' USING ERRCODE='BZ235'; END IF;
    END IF;
    UPDATE user_identity_links
       SET state='active',
           generation=generation+1,
           detached_by=NULL,
           detached_at=NULL,
           detached_reason=NULL,
           updated_at=statement_timestamp()
     WHERE id=v_t.link_id
       AND user_id=v_t.user_id
       AND source_id=v_t.source_id
       AND state='detached'
       AND generation=v_t.committed_link_generation;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows<>1 THEN
        RAISE EXCEPTION 'identity rollback link generation changed'
            USING ERRCODE='BZ235';
    END IF;
    UPDATE identity_attribute_authority a
       SET authority_kind='source',
           source_id=v_t.source_id,
           link_id=v_t.link_id,
           generation=a.generation+1,
           updated_at=statement_timestamp()
     WHERE a.user_id=v_t.user_id
       AND a.field IN (
           SELECT jsonb_array_elements_text(
               v_t.authority_before->'attributeFields'
           )
       )
       AND ((v_t.kind='directory_to_local' AND a.authority_kind='local' AND a.source_id IS NULL AND a.link_id IS NULL)
         OR (v_t.kind='source_to_source' AND a.authority_kind='source'
           AND a.source_id=v_t.target_source_id AND a.link_id=v_t.target_link_id));
    UPDATE identity_entitlement_grants g
       SET revoked_at=NULL,
           updated_at=statement_timestamp()
     WHERE g.user_id=v_t.user_id
       AND g.source_id=v_t.source_id
       AND g.link_id=v_t.link_id
       AND g.id IN (
           SELECT value::bigint
             FROM jsonb_array_elements_text(
                 v_t.authority_before->'grantIds'
             )
       )
       AND g.revoked_at IS NOT NULL;
    UPDATE users
       SET sync_source=COALESCE(
               v_t.authority_before->>'syncSource',
               (SELECT kind FROM identity_sources
                 WHERE id=v_t.source_id)
           ),
           updated_at=statement_timestamp()
     WHERE id=v_t.user_id;

    IF identity_mailbox_invariant_snapshot(v_t.user_id)<>v_t.authority_before->'mailboxInvariant' THEN
        RAISE EXCEPTION 'identity rollback changed mailbox ownership or address claims' USING ERRCODE='BZ235';
    END IF;

    UPDATE oauth_tokens
       SET revoked_at=statement_timestamp(),revoked_by=p_actor
     WHERE user_id=v_t.user_id AND revoked_at IS NULL;
    PERFORM revoke_user_sessions(
        v_t.user_id,'all','identity_transition_rollback',
        p_actor,NULL,NULL
    );
    DELETE FROM sessions WHERE user_id=v_t.user_id;
    DELETE FROM ws_subscriptions WHERE user_id=v_t.user_id;

    INSERT INTO identity_transition_effects(
        transition_id,effect_kind
    ) VALUES
        (v_t.id,'rollback_auth_sessions'),
        (v_t.id,'rollback_livekit_sessions'),
        (v_t.id,'rollback_subscriber_notice');
    INSERT INTO identity_transition_effect_targets(
        transition_id,effect_kind,target_key
    )
    SELECT v_t.id,'rollback_livekit_sessions',
           m.room_name::text||'|u:'||v_t.user_id::text
      FROM meeting_participants p
      JOIN meetings m ON m.id=p.meeting_id
     WHERE p.identity='u:'||v_t.user_id::text
       AND p.left_at IS NULL
    ON CONFLICT DO NOTHING;
    INSERT INTO identity_transition_effect_targets(
        transition_id,effect_kind,target_key,evict_until
    )
    SELECT v_t.id,'rollback_livekit_sessions',
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
       AND effect_kind='rollback_auth_sessions';
    INSERT INTO identity_transition_steps(
        transition_id,ordinal,stage,state,attempt_count,
        input_digest,output_digest,started_at,finished_at
    ) VALUES
        (v_t.id,11,'rollback_authority','completed',1,v_digest,
         digest(v_t.authority_before::text,'sha256'),
         statement_timestamp(),statement_timestamp()),
        (v_t.id,12,'rollback_auth_sessions','completed',1,v_digest,v_digest,
         statement_timestamp(),statement_timestamp()),
        (v_t.id,13,'rollback_livekit_sessions','pending',0,v_digest,NULL,NULL,NULL),
        (v_t.id,14,'rollback_subscriber_notice','pending',0,v_digest,NULL,NULL,NULL);
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,before_digest,after_digest,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_rollback_started',p_reason,
        v_t.rollback_preview_digest,
        digest(v_t.id::text||':rolling_back','sha256'),
        jsonb_build_object('personPreserved',true)
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_rollback(bigint,uuid,text,uuid,bigint,text,uuid)'::regprocedure
);
