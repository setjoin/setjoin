CREATE OR REPLACE FUNCTION upgrade_preview_payload(
    p_actor BIGINT,
    p_release_id TEXT,
    p_reason TEXT,
    p_schedule_at TIMESTAMPTZ DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_release upgrade_release_catalog%ROWTYPE;
    v_ready upgrade_readiness%ROWTYPE;
    v_recovery upgrade_recovery_sets%ROWTYPE;
    v_control upgrade_control_state%ROWTYPE;
    v_approval RECORD;
BEGIN
    IF p_actor IS NULL OR p_release_id IS NULL
       OR p_release_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 8 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR (p_schedule_at IS NOT NULL AND (
            p_schedule_at<statement_timestamp()
            OR p_schedule_at>statement_timestamp()+interval '31 days'
       )) THEN
        RAISE EXCEPTION 'invalid upgrade preview input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF NOT COALESCE((
        SELECT enabled FROM feature_toggles
         WHERE key='feature.transactional_upgrades_catalog'
    ),false) THEN
        RAISE EXCEPTION 'transactional release catalog is disabled'
            USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"catalog_disabled"}';
    END IF;

    SELECT * INTO v_release
      FROM upgrade_release_catalog
     WHERE release_id=p_release_id AND status='available';
    IF NOT FOUND OR v_release.metadata_expires_at<=statement_timestamp() THEN
        RAISE EXCEPTION 'release metadata is missing, withdrawn, or expired'
            USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"metadata_unavailable"}';
    END IF;
    IF v_release.channel='enterprise'
       AND v_release.entitlement_grace_until<=statement_timestamp() THEN
        RAISE EXCEPTION 'enterprise entitlement is expired for this release'
            USING ERRCODE='BZ244',HINT='{"type":"upgrade_entitlement_scope","reason":"expired"}';
    END IF;

    SELECT * INTO v_ready
      FROM upgrade_readiness
     WHERE release_id=p_release_id;
    IF NOT FOUND OR v_ready.manifest_digest<>v_release.manifest_digest
       OR v_ready.status<>'ready' OR v_ready.blocker_count<>0
       OR v_ready.expires_at<=statement_timestamp()
       OR v_ready.updated_at+interval '5 minutes'<=statement_timestamp() THEN
        RAISE EXCEPTION 'release readiness is missing, blocked, or stale'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale"}';
    END IF;

    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton;
    SELECT * INTO v_recovery
      FROM upgrade_recovery_sets
     WHERE installation_id=v_control.installation_id
       AND status='verified'
       AND expires_at>statement_timestamp()
       AND created_at>=statement_timestamp()-interval '24 hours'
     ORDER BY created_at DESC,recovery_set_id DESC LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'fresh verified application recovery set is required'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale","reason":"recovery_set_missing"}';
    END IF;
    SELECT * INTO v_approval
      FROM approval_match_policies(
          'system_upgrade',
          jsonb_build_object(
              'channel',v_release.channel,
              'target_version',v_release.version,
              'scheduled',p_schedule_at IS NOT NULL
          )
      );

    RETURN jsonb_build_object(
        'schemaVersion',1,
        'installationId',v_control.installation_id::text,
        'actorId',p_actor::text,
        'releaseId',v_release.release_id,
        'targetVersion',v_release.version,
        'channel',v_release.channel,
        'manifestDigest',encode(v_release.manifest_digest,'hex'),
        'catalogGeneration',v_release.catalog_generation::text,
        'readinessGeneration',v_ready.readiness_generation::text,
        'recoverySetId',v_recovery.recovery_set_id::text,
        'recoverySetDigest',encode(v_recovery.manifest_digest,'hex'),
        'recoverySetExpiresAt',v_recovery.expires_at,
        'policyGeneration',v_control.policy_generation::text,
        'approvalRequired',COALESCE(v_approval.required,false),
        'sourceVersion',v_ready.source_version,
        'sourceSchemaVersion',v_ready.source_schema_version::text,
        'targetSchemaVersion',v_ready.target_schema_version::text,
        'reason',p_reason,
        'scheduleAt',p_schedule_at,
        'expiresAt',LEAST(v_ready.expires_at,v_ready.updated_at+interval '5 minutes')
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_preview_payload(bigint,text,text,timestamptz)'::regprocedure,true,false
);
