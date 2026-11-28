CREATE OR REPLACE FUNCTION mail_recovery_fork_consent(
    p_user_id bigint,
    p_quarantine_id uuid,
    p_device_id uuid
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_artifact mail_recovery_quarantine_artifacts%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_quarantine_id IS NULL OR p_device_id IS NULL THEN
        RAISE EXCEPTION 'invalid recovery fork consent'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_artifact FROM mail_recovery_quarantine_artifacts
     WHERE id=p_quarantine_id FOR UPDATE;
    IF v_artifact.status<>'fork_conflict' OR v_artifact.device_id<>p_device_id OR
       NOT mail_recovery_user_can_upload(p_user_id,v_artifact.mailbox_id) THEN
        RAISE EXCEPTION 'recovery fork consent is not authorized'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF v_artifact.fork_consented_by IS NOT NULL THEN
        RETURN jsonb_build_object('id',v_artifact.id,'consentedAt',v_artifact.fork_consented_at,'replayed',true);
    END IF;
    UPDATE mail_recovery_quarantine_artifacts
       SET fork_consented_by=p_user_id,fork_consented_at=statement_timestamp()
     WHERE id=p_quarantine_id;
    PERFORM audit_write(p_user_id,'mail_recovery_fork_consent','mail_recovery_artifact',NULL,NULL,
        jsonb_build_object('quarantineId',p_quarantine_id,'mailboxId',v_artifact.mailbox_id::text,
                           'deviceId',p_device_id),NULL,NULL,'core');
    RETURN jsonb_build_object('id',p_quarantine_id,'consentedAt',statement_timestamp(),'replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_fork_consent(bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_fork_consent(bigint,uuid,uuid) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_fork_consent(bigint,uuid,uuid)'::regprocedure);
