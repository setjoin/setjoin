CREATE OR REPLACE FUNCTION mail_recovery_incident_list(
    p_actor_user_id bigint,
    p_limit integer,
    p_before timestamptz,
    p_status text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_list jsonb;
BEGIN
    IF NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR
       (p_status IS NOT NULL AND p_status NOT IN ('open','closed','expired')) THEN
        RAISE EXCEPTION 'invalid recovery incident list request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT COALESCE(jsonb_agg(row_json ORDER BY created_at DESC),'[]'::jsonb) INTO v_list
      FROM (
        SELECT incident.created_at,jsonb_build_object(
            'id',incident.id,'status',CASE WHEN incident.status='open' AND incident.expires_at<=statement_timestamp()
                                           THEN 'expired' ELSE incident.status END,
            'minimumTimeline',incident.minimum_timeline::text,
            'maximumTimeline',incident.maximum_timeline::text,
            'reason',incident.reason,'openedBy',incident.opened_by::text,
            'approvalRequired',incident.approval_required,
            'approvedBy',CASE WHEN incident.approved_by IS NULL THEN NULL ELSE incident.approved_by::text END,
            'expiresAt',incident.expires_at,'createdAt',incident.created_at,
            'mailboxCount',(SELECT count(*) FROM mail_recovery_incident_accounts account WHERE account.incident_id=incident.id),
            'counts',jsonb_build_object(
                'uploading',(SELECT count(*) FROM mail_recovery_upload_sessions session WHERE session.incident_id=incident.id AND session.status IN ('uploading','committing')),
                'quarantined',(SELECT count(*) FROM mail_recovery_quarantine_artifacts artifact WHERE artifact.incident_id=incident.id AND artifact.status IN ('quarantined','fork_conflict')),
                'accepted',(SELECT count(*) FROM mail_recovery_quarantine_artifacts artifact WHERE artifact.incident_id=incident.id AND artifact.status='accepted'),
                'rejected',(SELECT count(*) FROM mail_recovery_quarantine_artifacts artifact WHERE artifact.incident_id=incident.id AND artifact.status IN ('rejected','tampered')),
                'deduplicated',(SELECT count(*) FROM mail_recovery_quarantine_artifacts artifact WHERE artifact.incident_id=incident.id AND artifact.status='deduplicated')
            )
        ) row_json
          FROM mail_recovery_incidents incident
         WHERE (p_before IS NULL OR incident.created_at<p_before)
           AND (p_status IS NULL OR CASE WHEN incident.status='open' AND incident.expires_at<=statement_timestamp()
                                         THEN 'expired' ELSE incident.status END=p_status)
         ORDER BY incident.created_at DESC
         LIMIT p_limit
      ) bounded;
    RETURN jsonb_build_object('list',v_list);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_incident_list(bigint,integer,timestamptz,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_incident_list(bigint,integer,timestamptz,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_incident_list(bigint,integer,timestamptz,text)'::regprocedure);
