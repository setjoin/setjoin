CREATE OR REPLACE FUNCTION mail_recovery_user_incident_list(p_user_id bigint)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_list jsonb;
BEGIN
    IF p_user_id IS NULL OR NOT mail_recovery_feature_enabled() OR
       NOT EXISTS(SELECT 1 FROM users WHERE id=p_user_id AND enabled) THEN
        RETURN jsonb_build_object('list','[]'::jsonb);
    END IF;
    SELECT COALESCE(jsonb_agg(item ORDER BY expires_at),'[]'::jsonb)
      INTO v_list
      FROM (
        SELECT incident.expires_at,jsonb_build_object(
            'id',incident.id,
            'mailboxId',account.mailbox_id::text,
            'minimumTimeline',incident.minimum_timeline::text,
            'maximumTimeline',incident.maximum_timeline::text,
            'expiresAt',incident.expires_at,
            'reason',incident.reason
        ) item
          FROM mail_recovery_incidents incident
          JOIN mail_recovery_incident_accounts account ON account.incident_id=incident.id
         WHERE incident.status='open' AND incident.expires_at>statement_timestamp()
           AND (NOT incident.approval_required OR incident.approved_by IS NOT NULL)
           AND mail_recovery_user_can_upload(p_user_id,account.mailbox_id)
         ORDER BY incident.expires_at
         LIMIT 100
      ) bounded;
    RETURN jsonb_build_object('list',v_list);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_user_incident_list(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_user_incident_list(bigint) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_user_incident_list(bigint)'::regprocedure);
