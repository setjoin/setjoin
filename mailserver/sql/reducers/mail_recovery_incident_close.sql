CREATE OR REPLACE FUNCTION mail_recovery_incident_close(
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
        RAISE EXCEPTION 'invalid recovery close request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_incident FROM mail_recovery_incidents WHERE id=p_incident_id FOR UPDATE;
    IF v_incident.status='closed' THEN
        RETURN jsonb_build_object('id',v_incident.id,'status','closed','replayed',true);
    END IF;
    UPDATE mail_recovery_incidents
       SET status='closed',closed_at=statement_timestamp(),closed_by=p_actor_user_id,close_reason=btrim(p_reason)
     WHERE id=p_incident_id;
    UPDATE mail_recovery_upload_sessions
       SET status='aborted',terminal_reason='incident_closed',updated_at=statement_timestamp()
     WHERE incident_id=p_incident_id AND status IN ('uploading','committing');
    PERFORM audit_write(p_actor_user_id,'mail_recovery_incident_close','mail_recovery_incident',NULL,NULL,
        jsonb_build_object('incidentId',p_incident_id,'reason',btrim(p_reason)),NULL,NULL,'core');
    PERFORM app_notify('mail_recovery_incident_changed',jsonb_build_object('incident_id',p_incident_id,'status','closed')::text);
    RETURN jsonb_build_object('id',p_incident_id,'status','closed','replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_incident_close(bigint,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_incident_close(bigint,uuid,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_incident_close(bigint,uuid,text)'::regprocedure);
