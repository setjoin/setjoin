CREATE OR REPLACE FUNCTION identity_transition_preview(
    p_actor BIGINT,
    p_user_id BIGINT,
    p_reason TEXT,
    p_idempotency_key UUID,
    p_transition_id UUID DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_authority user_lifecycle_authorities%ROWTYPE;
    v_link user_identity_links%ROWTYPE;
    v_source identity_sources%ROWTYPE;
    v_existing identity_transitions%ROWTYPE;
    v_protected BOOLEAN;
    v_recovery BOOLEAN;
    v_expires TIMESTAMPTZ;
    v_snapshot JSONB;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_id UUID;
    v_replayed BOOLEAN := false;
    v_old_state TEXT;
BEGIN
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
                  HINT='{"type":"identity_transition_preflight","remediation":"enable and verify identity model, transition admission, and live revocation enforcement"}';
    END IF;
    IF p_actor IS NULL OR p_user_id IS NULL OR p_idempotency_key IS NULL
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity transition preview'
            USING ERRCODE='BZ241';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM users WHERE id=p_actor AND enabled
    ) OR NOT admin_can_reach(p_actor,p_user_id) THEN
        RAISE EXCEPTION 'identity transition target is not reachable'
            USING ERRCODE='BZ234';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text,0
    ));
    PERFORM 1 FROM users WHERE id=p_user_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity transition target is not reachable'
            USING ERRCODE='BZ234';
    END IF;
    SELECT * INTO v_authority
      FROM user_lifecycle_authorities
     WHERE user_id=p_user_id
     FOR UPDATE;
    IF NOT FOUND OR v_authority.authority_kind<>'source' THEN
        RAISE EXCEPTION 'person is not directory lifecycle-owned'
            USING ERRCODE='BZ234';
    END IF;

    SELECT * INTO v_link
      FROM user_identity_links
     WHERE id=v_authority.link_id AND user_id=p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'lifecycle link is missing'
            USING ERRCODE='BZ234';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-source:'||v_link.source_id::text,0
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-subject:'||v_link.source_id::text||':'||
        encode(digest(v_link.external_subject,'sha256'),'hex'),0
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-link:'||v_link.id::text,0
    ));
    SELECT * INTO v_source
      FROM identity_sources
     WHERE id=v_link.source_id
     FOR UPDATE;
    SELECT * INTO v_link
      FROM user_identity_links
     WHERE id=v_authority.link_id AND user_id=p_user_id
       AND state='active' AND 'provision'=ANY(purposes)
     FOR UPDATE;
    IF NOT FOUND
       OR v_source.kind NOT IN ('ad','ldap','scim')
       OR v_source.state<>'active' THEN
        RAISE EXCEPTION 'source pair is not supported for directory-to-local'
            USING ERRCODE='BZ234';
    END IF;

    v_recovery := identity_recovery_available(p_user_id,v_link.id);
    IF NOT v_recovery THEN
        RAISE EXCEPTION 'alternate authentication and recovery are required'
            USING ERRCODE='BZ237',
                  HINT='{"type":"identity_recovery_missing"}';
    END IF;

    v_protected := EXISTS (
        SELECT 1
          FROM admin_role_assignments a
          JOIN admin_role_groups g ON g.id=a.role_group_id
         WHERE a.user_id=p_user_id
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
           AND x.raw::bigint=p_user_id
    );

    v_expires := statement_timestamp()+interval '15 minutes';
    SELECT jsonb_build_object(
        'version',1,
        'type','directory_to_local',
        'personId',p_user_id::text,
        'oldSourceId',v_source.id::text,
        'oldLinkId',v_link.id::text,
        'generations',jsonb_build_object(
            'source',v_source.generation::text,
            'mapping',v_source.mapping_version::text,
            'link',v_link.generation::text,
            'lifecycle',v_authority.generation::text
        ),
        'attributeChanges',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'field',a.field,
                'generation',a.generation::text,
                'localOverride',a.local_override_state
            ) ORDER BY a.field)
              FROM identity_attribute_authority a
             WHERE a.user_id=p_user_id
               AND a.source_id=v_source.id
               AND a.link_id=v_link.id
        ),'[]'::jsonb),
        'sourceGrantIds',COALESCE((
            SELECT jsonb_agg(g.id::text ORDER BY g.id)
              FROM identity_entitlement_grants g
             WHERE g.user_id=p_user_id
               AND g.source_id=v_source.id
               AND g.link_id=v_link.id
               AND g.revoked_at IS NULL
        ),'[]'::jsonb),
        'recoveryReady',v_recovery,
        'protected',v_protected,
        'sessions',jsonb_build_object(
            'oauthFamilies',(SELECT count(*) FROM oauth_tokens o
                              WHERE o.user_id=p_user_id
                                AND o.revoked_at IS NULL),
            'webSessions',(SELECT count(*) FROM sessions s
                            WHERE s.user_id=p_user_id),
            'livekitTargets',(SELECT count(*)
                FROM meeting_participants mp
                JOIN meetings m ON m.id=mp.meeting_id
               WHERE mp.identity='u:'||p_user_id::text
                 AND mp.left_at IS NULL)
        ),
        'ownershipIdsPreserved',true,
        'expiresAt',v_expires
    ) INTO v_snapshot;
    v_digest := digest(v_snapshot::text,'sha256');
    v_request_digest := digest(jsonb_build_object(
        'type','directory_to_local',
        'actor',p_actor::text,
        'personId',p_user_id::text,
        'reason',p_reason,
        'sourceId',v_source.id::text,
        'sourceGeneration',v_source.generation::text,
        'mappingVersion',v_source.mapping_version::text,
        'linkId',v_link.id::text,
        'linkGeneration',v_link.generation::text,
        'lifecycleGeneration',v_authority.generation::text
    )::text,'sha256');

    IF p_transition_id IS NULL THEN
        INSERT INTO identity_transitions(
            user_id,kind,state,source_id,link_id,source_generation,
            link_generation,lifecycle_generation,preview_digest,
            preview_snapshot,preview_expires_at,actor_user_id,reason,
            idempotency_key,request_digest,protected
        ) VALUES(
            p_user_id,'directory_to_local','draft',v_source.id,v_link.id,
            v_source.generation,v_link.generation,v_authority.generation,
            v_digest,v_snapshot,v_expires,p_actor,p_reason,
            p_idempotency_key,v_request_digest,v_protected
        )
        ON CONFLICT(actor_user_id,kind,idempotency_key) DO NOTHING
        RETURNING id INTO v_id;
        IF v_id IS NULL THEN
            SELECT * INTO v_existing
              FROM identity_transitions
             WHERE actor_user_id=p_actor
               AND kind='directory_to_local'
               AND idempotency_key=p_idempotency_key
             FOR UPDATE;
            IF NOT FOUND
               OR v_existing.user_id<>p_user_id
               OR v_existing.request_digest<>v_request_digest THEN
                RAISE EXCEPTION 'identity transition idempotency key was reused with different input'
                    USING ERRCODE='BZ240',
                          HINT='{"type":"identity_idempotency_conflict","operation":"directory_to_local_preview"}';
            END IF;
            v_id := v_existing.id;
            v_replayed := true;
        ELSE
            PERFORM identity_transition_set_state(
                v_id,'draft','previewed',NULL
            );
            INSERT INTO identity_transition_steps(
                transition_id,ordinal,stage,state,attempt_count,
                input_digest,output_digest,started_at,finished_at
            ) VALUES(
                v_id,1,'preview','completed',1,
                v_request_digest,v_digest,
                statement_timestamp(),statement_timestamp()
            );
            INSERT INTO identity_link_events(
                actor_user_id,user_id,source_id,link_id,transition_id,
                action,reason,after_digest,metadata
            ) VALUES(
                p_actor,p_user_id,v_source.id,v_link.id,v_id,
                'transition_previewed',p_reason,v_digest,
                jsonb_build_object(
                    'protected',v_protected,
                    'previewVersion',1,
                    'expiresAt',v_expires
                )
            );
        END IF;
    ELSE
        SELECT * INTO v_existing
          FROM identity_transitions
         WHERE id=p_transition_id
           AND actor_user_id=p_actor
           AND user_id=p_user_id
           AND kind='directory_to_local'
         FOR UPDATE;
        IF NOT FOUND
           OR v_existing.state NOT IN (
               'previewed','awaiting_approval','authorized',
               'failed_precommit'
           ) THEN
            RAISE EXCEPTION 'identity transition cannot be re-previewed'
                USING ERRCODE='BZ234';
        END IF;
        IF NOT identity_transition_idempotency_claim(
            p_actor,'repreview',p_idempotency_key,p_transition_id,
            v_request_digest
        ) THEN
            v_id := p_transition_id;
            v_replayed := true;
        ELSE
            v_old_state := v_existing.state;
            IF v_existing.approval_request_id IS NOT NULL THEN
                UPDATE approval_requests
                   SET status='cancelled',
                       decided_at=statement_timestamp(),
                       decided_by_user_id=p_actor,
                       decision_comment='preview changed'
                 WHERE id=v_existing.approval_request_id
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
            UPDATE identity_transitions
               SET source_id=v_source.id,
                   link_id=v_link.id,
                   source_generation=v_source.generation,
                   link_generation=v_link.generation,
                   lifecycle_generation=v_authority.generation,
                   preview_version=preview_version+1,
                   preview_digest=v_digest,
                   preview_snapshot=v_snapshot,
                   preview_expires_at=v_expires,
                   reason=p_reason,
                   request_digest=v_request_digest,
                   protected=v_protected,
                   approval_request_id=NULL,
                   requester_elevation_id=NULL,
                   approver_elevation_id=NULL,
                   execution_elevation_id=NULL,
                   requested_at=NULL,
                   requested_generation=NULL,
                   approved_by_user_id=NULL,
                   approved_at=NULL,
                   authorized_at=NULL,
                   authorized_generation=NULL,
                   completed_at=NULL,
                   failure_code=NULL,
                   updated_at=statement_timestamp()
             WHERE id=p_transition_id;
            IF v_old_state<>'previewed' THEN
                PERFORM identity_transition_set_state(
                    p_transition_id,v_old_state,'previewed',NULL
                );
            ELSE
                UPDATE identity_transitions
                   SET transition_generation=transition_generation+1
                 WHERE id=p_transition_id;
            END IF;
            INSERT INTO identity_transition_steps(
                transition_id,ordinal,stage,state,attempt_count,
                input_digest,output_digest,started_at,finished_at
            ) VALUES(
                p_transition_id,1,'preview','completed',1,
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
                action,reason,before_digest,after_digest,metadata
            ) VALUES(
                p_actor,p_user_id,v_source.id,v_link.id,p_transition_id,
                'transition_previewed',p_reason,
                v_existing.preview_digest,v_digest,
                jsonb_build_object(
                    'protected',v_protected,
                    'previewVersion',v_existing.preview_version+1,
                    'driftedFromState',v_old_state,
                    'expiresAt',v_expires
                )
            );
            v_id := p_transition_id;
        END IF;
    END IF;

    RETURN (
        SELECT jsonb_build_object(
            'transitionId',t.id,
            'state',t.state,
            'transitionGeneration',t.transition_generation::text,
            'previewVersion',t.preview_version::text,
            'previewDigest',encode(t.preview_digest,'hex'),
            'previewExpiresAt',t.preview_expires_at,
            'protected',t.protected,
            'recoveryReady',t.preview_snapshot->'recoveryReady',
            'sourceGeneration',t.source_generation::text,
            'linkGeneration',t.link_generation::text,
            'lifecycleGeneration',t.lifecycle_generation::text,
            'preview',t.preview_snapshot,
            'replayed',v_replayed
        )
          FROM identity_transitions t
         WHERE t.id=v_id
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_preview(bigint,bigint,text,uuid,uuid)'::regprocedure
);
