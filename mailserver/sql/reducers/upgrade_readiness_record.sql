CREATE OR REPLACE FUNCTION upgrade_readiness_record(
    p_actor BIGINT,
    p_release_id TEXT,
    p_manifest_digest TEXT,
    p_status TEXT,
    p_source_version TEXT,
    p_source_schema_version BIGINT,
    p_target_schema_version BIGINT,
    p_checks JSONB,
    p_blocker_count INTEGER,
    p_expires_at TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_release upgrade_release_catalog%ROWTYPE;
    v_generation BIGINT;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF p_manifest_digest IS NULL OR p_manifest_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_status NOT IN ('checking','ready','blocked')
       OR p_source_version IS NULL OR octet_length(p_source_version) NOT BETWEEN 1 AND 64
       OR p_source_version ~ '[[:cntrl:]]'
       OR p_source_schema_version IS NULL OR p_source_schema_version<=0
       OR p_target_schema_version IS NULL OR p_target_schema_version<=0
       OR p_checks IS NULL OR jsonb_typeof(p_checks)<>'object'
       OR octet_length(p_checks::text)>262144
       OR p_blocker_count IS NULL OR p_blocker_count NOT BETWEEN 0 AND 1024
       OR (p_status='ready' AND p_blocker_count<>0)
       OR p_expires_at IS NULL
       OR p_expires_at<=statement_timestamp()
       OR p_expires_at>statement_timestamp()+interval '24 hours' THEN
        RAISE EXCEPTION 'invalid upgrade readiness evidence'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    SELECT * INTO v_release
      FROM upgrade_release_catalog
     WHERE release_id=p_release_id AND status='available'
     FOR SHARE;
    IF NOT FOUND OR v_release.manifest_digest<>decode(lower(p_manifest_digest),'hex')
       OR v_release.metadata_expires_at<=statement_timestamp() THEN
        RAISE EXCEPTION 'readiness does not bind current trusted release metadata'
            USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"digest_or_expiry"}';
    END IF;

    INSERT INTO upgrade_readiness(
        release_id,manifest_digest,readiness_generation,status,source_version,
        source_schema_version,target_schema_version,checks,blocker_count,
        expires_at,checked_by_user_id
    ) VALUES(
        p_release_id,v_release.manifest_digest,1,p_status,p_source_version,
        p_source_schema_version,p_target_schema_version,p_checks,p_blocker_count,
        p_expires_at,p_actor
    )
    ON CONFLICT(release_id) DO UPDATE SET
        manifest_digest=EXCLUDED.manifest_digest,
        readiness_generation=upgrade_readiness.readiness_generation+1,
        status=EXCLUDED.status,
        source_version=EXCLUDED.source_version,
        source_schema_version=EXCLUDED.source_schema_version,
        target_schema_version=EXCLUDED.target_schema_version,
        checks=EXCLUDED.checks,
        blocker_count=EXCLUDED.blocker_count,
        expires_at=EXCLUDED.expires_at,
        checked_by_user_id=EXCLUDED.checked_by_user_id,
        updated_at=statement_timestamp()
    RETURNING readiness_generation INTO v_generation;

    PERFORM audit_write(
        p_actor,'upgrade_readiness_recorded','upgrade_release',NULL,NULL,
        jsonb_build_object(
            'releaseId',p_release_id,'status',p_status,
            'blockerCount',p_blocker_count,'readinessGeneration',v_generation::text
        ),NULL,NULL,'core'
    );
    RETURN jsonb_build_object(
        'releaseId',p_release_id,'status',p_status,
        'readinessGeneration',v_generation::text,'expiresAt',p_expires_at
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_readiness_record(bigint,text,text,text,text,bigint,bigint,jsonb,integer,timestamptz)'::regprocedure,
    true,false
);
