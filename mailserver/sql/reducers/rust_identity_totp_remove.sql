-- #334: frozen DisableTOTPWithStepUp transaction; user/session are verified claims.
CREATE OR REPLACE FUNCTION rust_identity_totp_remove(
    p_user_id bigint, p_session_jti text, p_token_hash text, p_client_ip text
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    -- The person fence serializes this user's removal attempts. Do not consume
    -- a valid proof when the factor is absent: Go rolls that transaction back.
    IF NOT EXISTS (SELECT 1 FROM totp_removal_step_ups WHERE user_id=p_user_id
                   AND session_jti=p_session_jti AND token_hash=p_token_hash AND expires_at>now()) THEN
        RETURN 'invalid';
    END IF;
    PERFORM 1 FROM users WHERE id=p_user_id AND totp_enabled=TRUE FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_enabled'; END IF;
    DELETE FROM totp_removal_step_ups WHERE user_id=p_user_id AND session_jti=p_session_jti
        AND token_hash=p_token_hash AND expires_at>now();
    IF NOT FOUND THEN RETURN 'invalid'; END IF;
    UPDATE users SET totp_enabled=FALSE,totp_enabled_at=NULL,totp_secret_enc=NULL,
        totp_backup_codes_enc=NULL,totp_failed_attempts=0,totp_locked_until=NULL,
        last_totp_used_at=NULL,factor_generation=factor_generation+1 WHERE id=p_user_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id)
        VALUES(p_user_id,p_client_ip::inet,'totp_removed','user',p_user_id);
    RETURN 'removed';
END;
$$;
