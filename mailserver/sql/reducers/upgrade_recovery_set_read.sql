CREATE OR REPLACE FUNCTION upgrade_recovery_set_read(
    p_actor BIGINT,
    p_recovery_set_id UUID DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_set upgrade_recovery_sets%ROWTYPE;
    v_proof upgrade_restore_proofs%ROWTYPE;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF p_recovery_set_id IS NULL THEN
        SELECT s.* INTO v_set
          FROM upgrade_recovery_sets s
          JOIN upgrade_control_state c ON c.installation_id=s.installation_id AND c.singleton
         ORDER BY (s.status='verified' AND s.expires_at>statement_timestamp()) DESC,
                  s.created_at DESC,s.recovery_set_id DESC LIMIT 1;
    ELSE
        SELECT s.* INTO v_set
          FROM upgrade_recovery_sets s
          JOIN upgrade_control_state c ON c.installation_id=s.installation_id AND c.singleton
         WHERE s.recovery_set_id=p_recovery_set_id;
    END IF;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO v_proof FROM upgrade_restore_proofs
     WHERE recovery_set_id=v_set.recovery_set_id
     ORDER BY proved_at DESC,proof_id DESC LIMIT 1;
    RETURN jsonb_build_object(
        'recoverySetId',v_set.recovery_set_id::text,
        'installationId',v_set.installation_id::text,
        'timelineId',v_set.timeline_id::text,
        'sourceReleaseId',v_set.source_release_id,
        'schemaVersion',v_set.schema_version,
        'manifestDigest',encode(v_set.manifest_digest,'hex'),
        'status',v_set.status,'checks',v_set.checks,
        'createdAt',v_set.created_at,'expiresAt',v_set.expires_at,
        'fresh',(v_set.status='verified' AND v_set.expires_at>statement_timestamp()),
        'restoreProof',CASE WHEN v_proof.proof_id IS NULL THEN NULL ELSE jsonb_build_object(
            'proofId',v_proof.proof_id::text,'targetId',v_proof.target_id,
            'checks',v_proof.checks,'provedAt',v_proof.proved_at,
            'staleWarning',(v_proof.proved_at<statement_timestamp()-interval '90 days')
        ) END
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_recovery_set_read(bigint,uuid)'::regprocedure,true,false
);

