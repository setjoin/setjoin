CREATE OR REPLACE FUNCTION upgrade_console_read(
    p_actor BIGINT
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    RETURN jsonb_build_object(
        'schemaVersion',1,
        'flags',jsonb_build_object(
            'catalog',COALESCE((SELECT enabled FROM feature_toggles
                WHERE key='feature.transactional_upgrades_catalog'),false),
            'execution',COALESCE((SELECT enabled FROM feature_toggles
                WHERE key='feature.transactional_upgrades_execution'),false)
        ),
        'releases',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'releaseId',catalog.release_id,
                'version',catalog.version,
                'channel',catalog.channel,
                'manifestDigest',encode(catalog.manifest_digest,'hex'),
                'metadataExpiresAt',catalog.metadata_expires_at,
                'entitlementGraceUntil',catalog.entitlement_grace_until,
                'status',catalog.status,
                'readiness',CASE WHEN readiness.release_id IS NULL THEN NULL ELSE jsonb_build_object(
                    'status',readiness.status,
                    'generation',readiness.readiness_generation::text,
                    'checks',readiness.checks,
                    'blockerCount',readiness.blocker_count,
                    'expiresAt',readiness.expires_at
                ) END
            ) ORDER BY catalog.created_at DESC,catalog.release_id DESC)
              FROM upgrade_release_catalog catalog
              LEFT JOIN upgrade_readiness readiness USING(release_id)
        ),'[]'::jsonb),
        'recoverySet',upgrade_recovery_set_read(p_actor,NULL),
        'intent',upgrade_intent_read(NULL),
        'history',COALESCE((
            SELECT jsonb_agg(upgrade_intent_read(i.id) ORDER BY i.created_at DESC,i.id DESC)
              FROM (SELECT id,created_at FROM upgrade_intents ORDER BY created_at DESC,id DESC LIMIT 50) i
        ),'[]'::jsonb)
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_console_read(bigint)'::regprocedure,true,false
);

CREATE OR REPLACE FUNCTION upgrade_intent_diagnostics(
    p_actor BIGINT,
    p_intent_id BIGINT
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF p_intent_id IS NULL OR p_intent_id<=0 THEN
        RAISE EXCEPTION 'invalid upgrade intent id'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    SELECT * INTO v_intent FROM upgrade_intents WHERE id=p_intent_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN jsonb_build_object(
        'schemaVersion',1,
        'intentId',v_intent.id::text,
        'installationId',v_intent.installation_id::text,
        'releaseId',v_intent.release_id,
        'manifestDigest',encode(v_intent.manifest_digest,'hex'),
        'recoverySetId',CASE WHEN v_intent.recovery_set_id IS NULL THEN NULL ELSE v_intent.recovery_set_id::text END,
        'recoverySetDigest',CASE WHEN v_intent.recovery_set_digest IS NULL THEN NULL ELSE encode(v_intent.recovery_set_digest,'hex') END,
        'state',v_intent.state,
        'stateGeneration',v_intent.state_generation::text,
        'executorId',v_intent.executor_id,
        'createdAt',v_intent.created_at,
        'updatedAt',v_intent.updated_at,
        'events',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'generation',event.state_generation::text,
                'from',event.from_state,'to',event.to_state,
                'executorId',event.executor_id,
                'evidenceDigest',CASE WHEN event.evidence_digest IS NULL THEN NULL ELSE encode(event.evidence_digest,'hex') END,
                'occurredAt',event.occurred_at
            ) ORDER BY event.id)
              FROM upgrade_intent_events event WHERE event.intent_id=v_intent.id
        ),'[]'::jsonb)
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_diagnostics(bigint,bigint)'::regprocedure,true,false
);
