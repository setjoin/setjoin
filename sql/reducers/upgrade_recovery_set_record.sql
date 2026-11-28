CREATE OR REPLACE FUNCTION upgrade_recovery_set_record(
    p_actor BIGINT,
    p_recovery_set_id UUID,
    p_timeline_id UUID,
    p_source_release_id TEXT,
    p_schema_version INTEGER,
    p_manifest_digest TEXT,
    p_checks JSONB,
    p_created_at TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_digest BYTEA;
    v_existing upgrade_recovery_sets%ROWTYPE;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF p_recovery_set_id IS NULL OR p_timeline_id IS NULL
       OR p_source_release_id IS NULL
       OR p_source_release_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
       OR p_schema_version IS NULL OR p_schema_version<=0
       OR p_manifest_digest IS NULL OR p_manifest_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_checks IS NULL OR jsonb_typeof(p_checks)<>'object'
       OR octet_length(p_checks::text)>65536
       OR NOT (p_checks @> '{"database":true,"databaseRestoreList":true,"blobs":true,"configuration":true,"protectedKey":true,"featureToggles":true,"hmac":true}'::jsonb)
       OR p_created_at IS NULL OR p_expires_at IS NULL
       OR p_created_at>statement_timestamp()+interval '1 minute'
       OR p_created_at<statement_timestamp()-interval '24 hours'
       OR p_expires_at<=statement_timestamp()
       OR p_expires_at>p_created_at+interval '24 hours' THEN
        RAISE EXCEPTION 'invalid application recovery-set evidence'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid","field":"recoverySet"}';
    END IF;
    v_digest := decode(lower(p_manifest_digest),'hex');
    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton;
    IF p_timeline_id<>v_control.timeline_id THEN
        RAISE EXCEPTION 'recovery set timeline differs from current installation timeline'
            USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"timeline_mismatch"}';
    END IF;
    SELECT * INTO v_existing FROM upgrade_recovery_sets
     WHERE recovery_set_id=p_recovery_set_id FOR UPDATE;
    IF FOUND THEN
        IF v_existing.installation_id<>v_control.installation_id
           OR v_existing.timeline_id<>p_timeline_id
           OR v_existing.manifest_digest<>v_digest THEN
            RAISE EXCEPTION 'recovery-set identity was reused with different evidence'
                USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"recovery_set_equivocation"}';
        END IF;
        RETURN jsonb_build_object(
            'recoverySetId',v_existing.recovery_set_id::text,
            'manifestDigest',encode(v_existing.manifest_digest,'hex'),
            'status',v_existing.status,'expiresAt',v_existing.expires_at,
            'replayed',true
        );
    END IF;
    INSERT INTO upgrade_recovery_sets(
        recovery_set_id,installation_id,timeline_id,source_release_id,
        schema_version,manifest_digest,status,checks,created_at,expires_at,
        recorded_by_user_id
    ) VALUES(
        p_recovery_set_id,v_control.installation_id,p_timeline_id,
        p_source_release_id,p_schema_version,v_digest,'verified',p_checks,
        p_created_at,p_expires_at,p_actor
    );
    PERFORM audit_write(
        p_actor,'upgrade_recovery_set_verified','upgrade_recovery_set',NULL,NULL,
        jsonb_build_object(
            'recoverySetId',p_recovery_set_id::text,
            'manifestDigest',lower(p_manifest_digest),
            'timelineId',p_timeline_id::text,'expiresAt',p_expires_at
        ),NULL,NULL,'core'
    );
    PERFORM app_notify('upgrade_recovery_set_changed',json_build_object(
        'recovery_set_id',p_recovery_set_id::text,'status','verified'
    )::text);
    RETURN jsonb_build_object(
        'recoverySetId',p_recovery_set_id::text,
        'manifestDigest',lower(p_manifest_digest),'status','verified',
        'expiresAt',p_expires_at,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_recovery_set_record(bigint,uuid,uuid,text,integer,text,jsonb,timestamptz,timestamptz)'::regprocedure,
    true,false
);
