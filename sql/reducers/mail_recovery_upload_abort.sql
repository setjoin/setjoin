CREATE OR REPLACE FUNCTION mail_recovery_upload_abort(
    p_user_id bigint,
    p_session_id uuid
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_session mail_recovery_upload_sessions%ROWTYPE;
    v_keys jsonb;
BEGIN
    IF p_user_id IS NULL OR p_session_id IS NULL THEN
        RAISE EXCEPTION 'invalid recovery upload abort request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_session FROM mail_recovery_upload_sessions
     WHERE id=p_session_id AND uploading_user_id=p_user_id FOR UPDATE;
    SELECT COALESCE(jsonb_agg(object_key ORDER BY object_key),'[]'::jsonb)
      INTO v_keys FROM mail_recovery_upload_chunks WHERE session_id=p_session_id;
    IF v_session.status IN ('quarantined','deduplicated','rejected') THEN
        RAISE EXCEPTION 'terminal recovery upload cannot be aborted'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    IF v_session.status<>'aborted' THEN
        UPDATE mail_recovery_upload_sessions
           SET status='aborted',terminal_reason='user_cancelled',updated_at=statement_timestamp()
         WHERE id=p_session_id;
        UPDATE mail_recovery_upload_items SET status='aborted' WHERE session_id=p_session_id AND status='uploading';
        PERFORM audit_write(p_user_id,'mail_recovery_upload_abort','mail_recovery_incident',NULL,NULL,
            jsonb_build_object('incidentId',v_session.incident_id,'sessionId',p_session_id,
                               'mailboxId',v_session.mailbox_id::text),NULL,NULL,'core');
    END IF;
    RETURN jsonb_build_object('sessionId',p_session_id,'status','aborted','objectKeys',v_keys);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_upload_abort(bigint,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_upload_abort(bigint,uuid) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_upload_abort(bigint,uuid)'::regprocedure);
