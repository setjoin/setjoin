CREATE OR REPLACE FUNCTION upgrade_catalog_record(
    p_actor BIGINT,
    p_release_id TEXT,
    p_version TEXT,
    p_channel TEXT,
    p_platform TEXT,
    p_architecture TEXT,
    p_manifest_digest TEXT,
    p_manifest JSONB,
    p_metadata_version BIGINT,
    p_verified_by_key_ids TEXT[],
    p_verified_at TIMESTAMPTZ,
    p_metadata_expires_at TIMESTAMPTZ,
    p_entitlement_digest TEXT DEFAULT NULL,
    p_entitlement_grace_until TIMESTAMPTZ DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_manifest_digest BYTEA;
    v_entitlement_digest BYTEA;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF p_release_id IS NULL OR p_release_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
       OR p_version IS NULL OR octet_length(p_version) NOT BETWEEN 1 AND 64
       OR p_version ~ '[[:cntrl:]]'
       OR p_channel NOT IN ('community','enterprise')
       OR p_platform<>'linux' OR p_architecture NOT IN ('amd64','arm64')
       OR p_manifest_digest IS NULL OR p_manifest_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_manifest IS NULL OR jsonb_typeof(p_manifest)<>'object'
       OR octet_length(p_manifest::text)>1048576
       OR p_metadata_version IS NULL OR p_metadata_version<=0
       OR p_verified_by_key_ids IS NULL
       OR cardinality(p_verified_by_key_ids) NOT BETWEEN 1 AND 16
       OR p_verified_at IS NULL OR p_metadata_expires_at<=p_verified_at
       OR p_verified_at>statement_timestamp()+interval '5 minutes'
       OR (p_channel='community' AND (
            p_entitlement_digest IS NOT NULL OR p_entitlement_grace_until IS NOT NULL
       ))
       OR (p_channel='enterprise' AND (
            p_entitlement_digest IS NULL
            OR p_entitlement_digest !~ '^[0-9a-fA-F]{64}$'
            OR p_entitlement_grace_until IS NULL
       ))
       OR EXISTS (
            SELECT 1 FROM unnest(p_verified_by_key_ids) k
             WHERE k IS NULL OR octet_length(k) NOT BETWEEN 1 AND 128
                OR k !~ '^[A-Za-z0-9._:-]+$'
       ) THEN
        RAISE EXCEPTION 'release manifest evidence is malformed or out of scope'
            USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"invalid_evidence"}';
    END IF;
    v_manifest_digest := decode(lower(p_manifest_digest),'hex');
    IF p_entitlement_digest IS NOT NULL THEN
        v_entitlement_digest := decode(lower(p_entitlement_digest),'hex');
    END IF;

    SELECT * INTO v_control FROM upgrade_control_state WHERE singleton FOR UPDATE;
    IF EXISTS (
        SELECT 1 FROM upgrade_release_catalog
         WHERE release_id=p_release_id
           AND (manifest_digest<>v_manifest_digest OR metadata_version>p_metadata_version)
    ) THEN
        RAISE EXCEPTION 'release metadata replay or equivocation detected'
            USING ERRCODE='BZ245',HINT='{"type":"upgrade_manifest_trust","reason":"replay_or_equivocation"}';
    END IF;
    UPDATE upgrade_control_state
       SET catalog_generation=catalog_generation+1,
           updated_at=statement_timestamp()
     WHERE singleton
     RETURNING * INTO v_control;

    INSERT INTO upgrade_release_catalog(
        release_id,version,channel,platform,architecture,manifest_digest,manifest,
        metadata_version,catalog_generation,verified_by_key_ids,verified_at,
        metadata_expires_at,entitlement_digest,entitlement_grace_until,
        imported_by_user_id
    ) VALUES(
        p_release_id,p_version,p_channel,p_platform,p_architecture,
        v_manifest_digest,p_manifest,p_metadata_version,v_control.catalog_generation,
        (SELECT array_agg(DISTINCT k ORDER BY k) FROM unnest(p_verified_by_key_ids) k),
        p_verified_at,p_metadata_expires_at,v_entitlement_digest,
        p_entitlement_grace_until,p_actor
    )
    ON CONFLICT(release_id) DO UPDATE SET
        status='available',
        catalog_generation=EXCLUDED.catalog_generation,
        verified_by_key_ids=EXCLUDED.verified_by_key_ids,
        verified_at=EXCLUDED.verified_at,
        metadata_expires_at=EXCLUDED.metadata_expires_at,
        entitlement_digest=EXCLUDED.entitlement_digest,
        entitlement_grace_until=EXCLUDED.entitlement_grace_until,
        imported_by_user_id=EXCLUDED.imported_by_user_id
    WHERE upgrade_release_catalog.manifest_digest=EXCLUDED.manifest_digest
      AND upgrade_release_catalog.metadata_version<=EXCLUDED.metadata_version;

    PERFORM audit_write(
        p_actor,'upgrade_catalog_verified','upgrade_release',NULL,NULL,
        jsonb_build_object(
            'releaseId',p_release_id,'version',p_version,'channel',p_channel,
            'manifestDigest',lower(p_manifest_digest),
            'catalogGeneration',v_control.catalog_generation::text
        ),NULL,NULL,'core'
    );
    PERFORM app_notify('upgrade_catalog_changed',json_build_object(
        'release_id',p_release_id,'generation',v_control.catalog_generation
    )::text);
    RETURN jsonb_build_object(
        'releaseId',p_release_id,
        'catalogGeneration',v_control.catalog_generation::text,
        'manifestDigest',lower(p_manifest_digest)
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_catalog_record(bigint,text,text,text,text,text,text,jsonb,bigint,text[],timestamptz,timestamptz,text,timestamptz)'::regprocedure,
    true,false
);
