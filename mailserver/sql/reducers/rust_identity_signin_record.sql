-- Frozen shared/threat.RecordSignIn's independent best-effort transaction.
-- Caller supplies only resolved user identity (or NULL for an unknown login).
CREATE OR REPLACE FUNCTION rust_identity_signin_record(
    p_user_id bigint, p_success boolean, p_source_ip text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    IF p_user_id IS NOT NULL THEN
        PERFORM set_config('app.current_user_id',p_user_id::text,true);
    END IF;
    INSERT INTO login_events(user_id,device_fingerprint,device_name,platform,source_ip,
        location,success,fail_reason,client,protocol,auth_method,session_id,correlation_id,occurred_at)
    VALUES(p_user_id,NULL,NULL,NULL,NULLIF(p_source_ip,'')::inet,NULL,p_success,
        CASE WHEN p_success THEN NULL ELSE 'invalid_credentials' END,
        'web','http','password',NULL,NULL,now());
END;
$$;
