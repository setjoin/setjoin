CREATE OR REPLACE FUNCTION upgrade_recovery_context_read(
    p_actor BIGINT
) RETURNS JSONB
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_schema INTEGER;
    v_users BIGINT;
    v_mailboxes BIGINT;
    v_blobs BIGINT;
    v_blob_bytes BIGINT;
    v_representative_ids JSONB;
BEGIN
    IF NOT upgrade_actor_authorized(p_actor) THEN
        RAISE EXCEPTION 'global system.upgrade authority is required'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton;
    SELECT COALESCE(max(version),0) INTO v_schema FROM schema_migrations;
    SELECT count(*) INTO v_users FROM users;
    SELECT count(*) INTO v_mailboxes FROM mailboxes;
    SELECT count(*),COALESCE(sum(size_bytes),0) INTO v_blobs,v_blob_bytes
      FROM blobs WHERE ref_count>0;
    SELECT COALESCE(jsonb_agg(candidate ORDER BY candidate),'[]'::jsonb)
      INTO v_representative_ids
      FROM (
        (SELECT 'user:'||id::text AS candidate FROM users ORDER BY id LIMIT 4)
        UNION ALL
        (SELECT 'mailbox:'||id::text FROM mailboxes ORDER BY id LIMIT 4)
        UNION ALL
        (SELECT 'blob:'||sha256 FROM blobs WHERE ref_count>0 ORDER BY sha256 LIMIT 4)
      ) sample;
    RETURN jsonb_build_object(
        'installationId',v_control.installation_id::text,
        'timelineId',v_control.timeline_id::text,
        'schemaVersion',v_schema,
        'counts',jsonb_build_object(
            'users',v_users,'mailboxes',v_mailboxes,
            'blobs',v_blobs,'blobBytes',v_blob_bytes
        ),
        'representativeIds',v_representative_ids
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_recovery_context_read(bigint)'::regprocedure,true,false
);
