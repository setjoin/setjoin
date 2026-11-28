CREATE OR REPLACE FUNCTION mail_recovery_uploads_expire()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_session record;
    v_count integer:=0;
BEGIN
    FOR v_session IN
        SELECT id,incident_id,mailbox_id,uploading_user_id
          FROM mail_recovery_upload_sessions
         WHERE status IN ('uploading','committing') AND expires_at<=statement_timestamp()
         FOR UPDATE SKIP LOCKED
    LOOP
        UPDATE mail_recovery_upload_sessions
           SET status='expired',terminal_reason='upload_expired',updated_at=statement_timestamp()
         WHERE id=v_session.id;
        UPDATE mail_recovery_upload_items SET status='aborted'
         WHERE session_id=v_session.id AND status='uploading';
        PERFORM audit_write(v_session.uploading_user_id,'mail_recovery_upload_expire',
            'mail_recovery_incident',NULL,NULL,
            jsonb_build_object('incidentId',v_session.incident_id,'sessionId',v_session.id,
                               'mailboxId',v_session.mailbox_id::text),NULL,NULL,'core');
        v_count:=v_count+1;
    END LOOP;
    RETURN v_count;
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_uploads_expire() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_uploads_expire() TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_uploads_expire()'::regprocedure);
