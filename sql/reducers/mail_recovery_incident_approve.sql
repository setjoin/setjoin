CREATE OR REPLACE FUNCTION mail_recovery_incident_approve(
    p_actor_user_id bigint,
    p_incident_id uuid,
    p_reason text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_incident mail_recovery_incidents%ROWTYPE;
BEGIN
    IF NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_incident_id IS NULL OR length(btrim(COALESCE(p_reason,''))) NOT BETWEEN 8 AND 1024 OR p_reason~'[\r\n]' THEN
        RAISE EXCEPTION 'invalid recovery approval request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_incident FROM mail_recovery_incidents WHERE id=p_incident_id FOR UPDATE;
    IF v_incident.status<>'open' OR v_incident.expires_at<=statement_timestamp() THEN
        RAISE EXCEPTION 'recovery incident is not open'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    IF NOT v_incident.approval_required THEN
        RETURN jsonb_build_object('id',v_incident.id,'approvalRequired',false,'replayed',true);
    END IF;
    IF v_incident.opened_by=p_actor_user_id THEN
        RAISE EXCEPTION 'recovery approval must be independent'
            USING ERRCODE='BZ003',HINT='{"type":"separation_of_duties"}';
    END IF;
    IF v_incident.approved_by IS NOT NULL THEN
        RETURN jsonb_build_object('id',v_incident.id,'approvedBy',v_incident.approved_by::text,'replayed',true);
    END IF;
    UPDATE mail_recovery_incidents SET approved_by=p_actor_user_id,approved_at=statement_timestamp()
     WHERE id=p_incident_id;
    PERFORM audit_write(p_actor_user_id,'mail_recovery_incident_approve','mail_recovery_incident',NULL,NULL,
        jsonb_build_object('incidentId',p_incident_id,'reason',btrim(p_reason)),NULL,NULL,'core');
    RETURN jsonb_build_object('id',p_incident_id,'approvedBy',p_actor_user_id::text,'replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_incident_approve(bigint,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_incident_approve(bigint,uuid,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_incident_approve(bigint,uuid,text)'::regprocedure);
