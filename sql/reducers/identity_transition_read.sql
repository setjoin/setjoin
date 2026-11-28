CREATE OR REPLACE FUNCTION identity_transition_read(
    p_actor BIGINT,
    p_transition_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL THEN
        RAISE EXCEPTION 'identity transition not found'
            USING ERRCODE='BZ234';
    END IF;
    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id;
    IF NOT FOUND OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition not found'
            USING ERRCODE='BZ234';
    END IF;

    RETURN jsonb_build_object(
        'transitionId',v_t.id,
        'correlationId',v_t.correlation_id,
        'personId',v_t.user_id::text,
        'type',v_t.kind,
        'sourceId',v_t.source_id::text,
        'sourceLinkId',v_t.link_id::text,
        'targetSourceId',CASE WHEN v_t.target_source_id IS NULL THEN NULL ELSE v_t.target_source_id::text END,
        'targetLinkId',CASE WHEN v_t.target_link_id IS NULL THEN NULL ELSE v_t.target_link_id::text END,
        'state',v_t.state,
        'transitionGeneration',v_t.transition_generation::text,
        'previewVersion',v_t.preview_version::text,
        'previewDigest',encode(v_t.preview_digest,'hex'),
        'previewExpiresAt',v_t.preview_expires_at,
        'protected',v_t.protected,
        'requestedBy',v_t.actor_user_id::text,
        'requestedAt',v_t.requested_at,
        'approvalRequestId',CASE
            WHEN v_t.approval_request_id IS NULL THEN NULL
            ELSE v_t.approval_request_id::text
        END,
        'approvedBy',CASE
            WHEN v_t.approved_by_user_id IS NULL THEN NULL
            ELSE v_t.approved_by_user_id::text
        END,
        'approvedAt',v_t.approved_at,
        'authorizedAt',v_t.authorized_at,
        'rollback',jsonb_build_object(
            'boundary',v_t.rollback_boundary,
            'previewDigest',CASE
                WHEN v_t.rollback_preview_digest IS NULL THEN NULL
                ELSE encode(v_t.rollback_preview_digest,'hex')
            END,
            'previewExpiresAt',v_t.rollback_preview_expires_at,
            'approvalRequestId',CASE
                WHEN v_t.rollback_approval_request_id IS NULL THEN NULL
                ELSE v_t.rollback_approval_request_id::text
            END,
            'requestedAt',v_t.rollback_requested_at,
            'approvedBy',CASE
                WHEN v_t.rollback_approved_by_user_id IS NULL THEN NULL
                ELSE v_t.rollback_approved_by_user_id::text
            END,
            'approvedAt',v_t.rollback_approved_at
        ),
        'failureCode',v_t.failure_code,
        'createdAt',v_t.created_at,
        'committedAt',v_t.committed_at,
        'completedAt',v_t.completed_at,
        'steps',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'ordinal',s.ordinal,
                'stage',s.stage,
                'state',s.state,
                'attemptCount',s.attempt_count,
                'startedAt',s.started_at,
                'finishedAt',s.finished_at,
                'retryAt',s.retry_at,
                'errorCode',s.error_code
            ) ORDER BY s.ordinal)
              FROM identity_transition_steps s
             WHERE s.transition_id=v_t.id
        ),'[]'::jsonb),
        'effects',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'effectId',e.effect_id,
                'kind',e.effect_kind,
                'state',e.state,
                'attemptCount',e.attempt_count,
                'nextAttemptAt',e.next_attempt_at,
                'lastErrorCode',e.last_error_code,
                'completedAt',e.completed_at
            ) ORDER BY e.effect_kind)
              FROM identity_transition_effects e
             WHERE e.transition_id=v_t.id
        ),'[]'::jsonb)
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_read(bigint,uuid)'::regprocedure
);
