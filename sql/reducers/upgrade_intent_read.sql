CREATE OR REPLACE FUNCTION upgrade_intent_read(
    p_intent_id BIGINT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
BEGIN
    IF p_intent_id IS NOT NULL AND p_intent_id<=0 THEN
        RAISE EXCEPTION 'invalid upgrade intent id'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    IF p_intent_id IS NULL THEN
        SELECT * INTO v_intent FROM upgrade_intents
         ORDER BY (
            state NOT IN ('verified','rolled_back','failed','cancelled','expired')
         ) DESC,created_at DESC,id DESC LIMIT 1;
    ELSE
        SELECT * INTO v_intent FROM upgrade_intents WHERE id=p_intent_id;
    END IF;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN jsonb_build_object(
        'intentId',v_intent.id::text,
        'installationId',v_intent.installation_id::text,
        'releaseId',v_intent.release_id,
        'manifestDigest',encode(v_intent.manifest_digest,'hex'),
        'recoverySetId',CASE WHEN v_intent.recovery_set_id IS NULL
            THEN NULL ELSE v_intent.recovery_set_id::text END,
        'recoverySetDigest',CASE WHEN v_intent.recovery_set_digest IS NULL
            THEN NULL ELSE encode(v_intent.recovery_set_digest,'hex') END,
        'state',v_intent.state,
        'stateGeneration',v_intent.state_generation::text,
        'requestedByUserId',v_intent.requested_by_user_id::text,
        'approvedByUserId',CASE WHEN v_intent.approved_by_user_id IS NULL
            THEN NULL ELSE v_intent.approved_by_user_id::text END,
        'approvalRequestId',CASE WHEN v_intent.approval_request_id IS NULL
            THEN NULL ELSE v_intent.approval_request_id::text END,
        'reason',v_intent.reason,
        'scheduleAt',v_intent.schedule_at,
        'expiresAt',v_intent.expires_at,
        'executorId',v_intent.executor_id,
        'claimedAt',v_intent.claimed_at,
        'cancelRequestedAt',v_intent.cancel_requested_at,
        'completedAt',v_intent.completed_at,
        'result',v_intent.result,
        'createdAt',v_intent.created_at,
        'updatedAt',v_intent.updated_at,
        'events',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'generation',e.state_generation::text,
                'from',e.from_state,'to',e.to_state,
                'actorUserId',CASE WHEN e.actor_user_id IS NULL
                    THEN NULL ELSE e.actor_user_id::text END,
                'executorId',e.executor_id,
                'evidenceDigest',CASE WHEN e.evidence_digest IS NULL
                    THEN NULL ELSE encode(e.evidence_digest,'hex') END,
                'evidence',e.evidence,'occurredAt',e.occurred_at
            ) ORDER BY e.id)
              FROM upgrade_intent_events e WHERE e.intent_id=v_intent.id
        ),'[]'::jsonb)
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_read(bigint)'::regprocedure,true,true
);
