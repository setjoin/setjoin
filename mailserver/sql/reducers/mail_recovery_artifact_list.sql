CREATE OR REPLACE FUNCTION mail_recovery_artifact_list(
    p_actor_user_id bigint,
    p_incident_id uuid,
    p_limit integer
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_list jsonb;
BEGIN
    IF NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_incident_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR
       NOT EXISTS(SELECT 1 FROM mail_recovery_incidents WHERE id=p_incident_id) THEN
        RAISE EXCEPTION 'invalid recovery artifact list request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT COALESCE(jsonb_agg(item ORDER BY created_at DESC),'[]'::jsonb)
      INTO v_list
      FROM (
        SELECT artifact.created_at,jsonb_build_object(
            'id',artifact.id,
            'mailboxId',artifact.mailbox_id::text,
            'uploadingUserId',artifact.uploading_user_id::text,
            'deviceId',artifact.device_id,
            'artifactIdentity',encode(artifact.artifact_identity,'hex'),
            'rawMimeSha256',encode(artifact.raw_mime_sha256,'hex'),
            'rawMimeSize',artifact.raw_mime_size::text,
            'signedTimeline',artifact.signed_timeline::text,
            'signedBootEpoch',artifact.signed_boot_epoch,
            'headers',artifact.parsed_headers,
            'malwareStatus',artifact.malware_status,
            'status',artifact.status,
            'rejectionReason',artifact.rejection_reason,
            'forkConsented',artifact.fork_consented_at IS NOT NULL,
            'createdAt',artifact.created_at,
            'terminalAt',artifact.terminal_at
        ) item
          FROM mail_recovery_quarantine_artifacts artifact
         WHERE artifact.incident_id=p_incident_id
         ORDER BY artifact.created_at DESC
         LIMIT p_limit
      ) bounded;
    RETURN jsonb_build_object('incidentId',p_incident_id,'list',v_list);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_artifact_list(bigint,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_artifact_list(bigint,uuid,integer) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_artifact_list(bigint,uuid,integer)'::regprocedure);
