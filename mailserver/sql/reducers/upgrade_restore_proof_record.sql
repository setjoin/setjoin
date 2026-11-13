CREATE OR REPLACE FUNCTION upgrade_restore_proof_record(
    p_actor BIGINT,
    p_proof_id UUID,
    p_recovery_set_id UUID,
    p_target_id TEXT,
    p_checks JSONB,
    p_proved_at TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_set upgrade_recovery_sets%ROWTYPE;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF p_proof_id IS NULL OR p_recovery_set_id IS NULL OR p_target_id IS NULL
       OR p_target_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR p_checks IS NULL OR jsonb_typeof(p_checks)<>'object'
       OR octet_length(p_checks::text)>65536
       OR NOT (p_checks @> '{"isolated":true,"schema":true,"login":true,"mail":true,"blob":true,"productionEndpointsAbsent":true}'::jsonb)
       OR p_proved_at IS NULL OR p_proved_at>statement_timestamp()+interval '1 minute' THEN
        RAISE EXCEPTION 'invalid isolated restore proof'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid","field":"restoreProof"}';
    END IF;
    SELECT * INTO v_set FROM upgrade_recovery_sets
     WHERE recovery_set_id=p_recovery_set_id AND status='verified' FOR SHARE;
    IF NOT FOUND OR p_target_id=v_set.installation_id::text OR p_proved_at<v_set.created_at THEN
        RAISE EXCEPTION 'restore proof target is not a new isolated target'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale","reason":"restore_not_isolated"}';
    END IF;
    INSERT INTO upgrade_restore_proofs(
        proof_id,recovery_set_id,target_id,checks,proved_at,recorded_by_user_id
    ) VALUES(p_proof_id,p_recovery_set_id,p_target_id,p_checks,p_proved_at,p_actor)
    ON CONFLICT(proof_id) DO NOTHING;
    PERFORM audit_write(
        p_actor,'upgrade_restore_proof_recorded','upgrade_recovery_set',NULL,NULL,
        jsonb_build_object('recoverySetId',p_recovery_set_id::text,
            'proofId',p_proof_id::text,'targetId',p_target_id,'provedAt',p_proved_at),
        NULL,NULL,'core'
    );
    RETURN jsonb_build_object(
        'proofId',p_proof_id::text,'recoverySetId',p_recovery_set_id::text,
        'targetId',p_target_id,'provedAt',p_proved_at
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_restore_proof_record(bigint,uuid,uuid,text,jsonb,timestamptz)'::regprocedure,
    true,false
);

