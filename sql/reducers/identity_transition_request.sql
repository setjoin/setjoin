CREATE OR REPLACE FUNCTION identity_transition_request(
    p_actor BIGINT,
    p_transition_id UUID,
    p_preview_digest TEXT,
    p_elevation_id UUID,
    p_reason TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_first BOOLEAN;
    v_is_rollback BOOLEAN;
    v_match RECORD;
    v_approver RECORD;
    v_approval_id BIGINT;
    v_next_generation BIGINT;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_preview_digest IS NULL
       OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_elevation_id IS NULL
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition request'
            USING ERRCODE='BZ241';
    END IF;

    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
       AND actor_user_id=p_actor
     FOR UPDATE;
    IF NOT FOUND
       OR NOT admin_can_reach(p_actor,v_t.user_id)
       OR NOT EXISTS (
           SELECT 1 FROM users WHERE id=p_actor AND enabled
       ) THEN
        RAISE EXCEPTION 'identity transition not found'
            USING ERRCODE='BZ234';
    END IF;

    v_is_rollback := v_t.state='rollback_previewed';
    IF (NOT v_is_rollback AND v_t.state<>'previewed')
       OR (v_is_rollback
           AND v_t.rollback_preview_digest IS NULL) THEN
        RAISE EXCEPTION 'identity transition request is not available in this state'
            USING ERRCODE='BZ234';
    END IF;
    v_digest := decode(lower(p_preview_digest),'hex');
    IF (v_is_rollback
        AND (v_t.rollback_preview_digest<>v_digest
             OR v_t.rollback_preview_expires_at<=statement_timestamp()))
       OR (NOT v_is_rollback
           AND (v_t.preview_digest<>v_digest
                OR v_t.preview_expires_at<=statement_timestamp())) THEN
        RAISE EXCEPTION 'identity transition preview is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    IF p_reason IS DISTINCT FROM (
        CASE WHEN v_is_rollback
             THEN v_t.rollback_reason ELSE v_t.reason END
    ) THEN
        RAISE EXCEPTION 'identity transition reason differs from the preview'
            USING ERRCODE='BZ240',
                  HINT='{"type":"identity_idempotency_conflict","operation":"transition_request"}';
    END IF;

    v_request_digest := digest(jsonb_build_object(
        'operation',CASE WHEN v_is_rollback THEN 'rollback_request'
                         ELSE 'request' END,
        'transitionId',p_transition_id::text,
        'transitionGeneration',v_t.transition_generation::text,
        'previewDigest',lower(p_preview_digest),
        'elevationId',p_elevation_id::text,
        'reason',p_reason
    )::text,'sha256');
    v_first := identity_transition_idempotency_claim(
        p_actor,
        CASE WHEN v_is_rollback THEN 'rollback_request' ELSE 'request' END,
        p_idempotency_key,p_transition_id,v_request_digest
    );
    IF NOT v_first THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;

    PERFORM identity_transition_elevation_consume(
        p_elevation_id,p_actor,p_transition_id,v_digest,
        v_t.transition_generation
    );

    IF v_t.protected OR v_is_rollback THEN
        SELECT * INTO v_match
          FROM approval_match_policies(
              'identity.transition',
              jsonb_build_object(
                  'protected',true,
                  'operation',CASE WHEN v_is_rollback
                                   THEN 'rollback'
                                   ELSE v_t.kind END
              )
          );
        IF NOT COALESCE(v_match.required,false)
           OR v_match.winner_policy_id IS NULL THEN
            RAISE EXCEPTION 'protected identity transition approval policy is not configured'
                USING ERRCODE='BZ236',
                      HINT='{"type":"identity_approval_required","remediation":"enable an identity.transition policy with a named break-glass approver"}';
        END IF;
        SELECT * INTO v_approver
          FROM approval_resolve_approver(
              p_actor,v_match.approver_spec
          );
        IF v_approver.skip
           OR v_approver.kind<>'user'
           OR v_approver.ref IS NULL
           OR v_approver.ref=p_actor
           OR NOT EXISTS (
               SELECT 1
                 FROM users u,
                      system_config c,
                      LATERAL jsonb_array_elements_text(c.value) x(raw)
                WHERE u.id=v_approver.ref
                  AND u.enabled
                  AND c.key='ca_break_glass_user_ids'
                  AND x.raw::bigint=u.id
           ) THEN
            RAISE EXCEPTION 'independent active break-glass approver is unavailable'
                USING ERRCODE='BZ236',
                      HINT='{"type":"identity_approval_invalid"}';
        END IF;

        v_approval_id := approval_request_create(
            'identity.transition',
            p_actor,
            CASE WHEN v_is_rollback
                 THEN 'Identity transition rollback'
                 ELSE 'Protected identity transition' END,
            jsonb_build_object(
                'transitionId',p_transition_id::text,
                'operation',CASE WHEN v_is_rollback
                                 THEN 'rollback' ELSE 'execute' END,
                'previewDigest',lower(p_preview_digest),
                'transitionGeneration',v_t.transition_generation::text,
                'requesterElevationId',p_elevation_id::text,
                'requestDigest',encode(v_request_digest,'hex')
            ),
            v_match.winner_policy_id,
            v_approver.kind,
            v_approver.ref,
            240
        );
        IF v_is_rollback THEN
            UPDATE identity_transitions
               SET rollback_approval_request_id=v_approval_id,
                   rollback_requester_elevation_id=p_elevation_id,
                   rollback_requested_at=statement_timestamp(),
                   rollback_requested_generation=v_t.transition_generation,
                   updated_at=statement_timestamp()
             WHERE id=p_transition_id
               AND state='rollback_previewed';
            INSERT INTO identity_link_events(
                actor_user_id,user_id,source_id,link_id,transition_id,
                action,reason,after_digest,metadata
            ) VALUES(
                p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
                'transition_rollback_requested',p_reason,
                v_digest,jsonb_build_object('approvalRequestId',v_approval_id)
            );
        ELSE
            UPDATE identity_transitions
               SET approval_request_id=v_approval_id,
                   requester_elevation_id=p_elevation_id,
                   requested_at=statement_timestamp(),
                   requested_generation=v_t.transition_generation,
                   updated_at=statement_timestamp()
             WHERE id=p_transition_id AND state='previewed';
            v_next_generation := identity_transition_set_state(
                p_transition_id,'previewed','awaiting_approval',NULL
            );
            INSERT INTO identity_link_events(
                actor_user_id,user_id,source_id,link_id,transition_id,
                action,reason,after_digest,metadata
            ) VALUES(
                p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
                'transition_approval_requested',p_reason,
                v_digest,jsonb_build_object(
                    'approvalRequestId',v_approval_id,
                    'transitionGeneration',v_next_generation
                )
            );
        END IF;
    ELSE
        UPDATE identity_transitions
           SET requester_elevation_id=p_elevation_id,
               requested_at=statement_timestamp(),
               requested_generation=v_t.transition_generation,
               authorized_at=statement_timestamp(),
               updated_at=statement_timestamp()
         WHERE id=p_transition_id AND state='previewed';
        v_next_generation := identity_transition_set_state(
            p_transition_id,'previewed','authorized',NULL
        );
        UPDATE identity_transitions
           SET authorized_generation=v_next_generation
         WHERE id=p_transition_id;
        INSERT INTO identity_link_events(
            actor_user_id,user_id,source_id,link_id,transition_id,
            action,reason,after_digest,metadata
        ) VALUES(
            p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
            'transition_requested',p_reason,v_digest,
            jsonb_build_object(
                'approvalRequired',false,
                'transitionGeneration',v_next_generation
            )
        );
    END IF;

    INSERT INTO identity_transition_steps(
        transition_id,ordinal,stage,state,attempt_count,
        input_digest,output_digest,started_at,finished_at
    ) VALUES(
        p_transition_id,
        CASE WHEN v_is_rollback THEN 9 ELSE 2 END,
        CASE WHEN v_is_rollback THEN 'rollback_request' ELSE 'request' END,
        'completed',1,
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

    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_request(bigint,uuid,text,uuid,text,uuid)'::regprocedure
);
