-- #334: frozen password-login bootstrap token/grant publication transaction.
CREATE OR REPLACE FUNCTION rust_identity_mfa_bootstrap_grant(
    p_user_id bigint,p_password_hash text,p_token_hash text,p_jti text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_capable boolean;
BEGIN
    PERFORM identity_auth_local_mint_fence(p_user_id);
    PERFORM 1 FROM users WHERE id=p_user_id AND enabled AND password_hash=p_password_hash;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    SELECT COALESCE(u.totp_enabled,FALSE) OR EXISTS(SELECT 1 FROM passkey_credentials pc
        WHERE pc.user_id=u.id AND pc.revoked_at IS NULL AND pc.uv_capable)
        INTO v_capable FROM users u WHERE u.id=p_user_id;
    IF NOT v_capable THEN
        DELETE FROM mfa_reauth_step_ups WHERE user_id=p_user_id;
        INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,target_ref,proof_method,
            proving_factor_id,bound_factor_generation,token_scope,refresh_family_id,expires_at)
        SELECT p_token_hash,p_user_id,p_jti,'bootstrap.totp.enroll',NULL,'password',NULL,
            factor_generation,'mfa_pending',NULL,now()+interval '5 minutes' FROM users WHERE id=p_user_id;
    END IF;
    IF NULLIF(current_setting('app.rust_operation_id',true),'') IS NOT NULL THEN
        INSERT INTO rust_operation_receipts(operation_id,family,command)
            VALUES(current_setting('app.rust_operation_id')::uuid,'F21','mfa-bootstrap-grant');
    END IF;
    RETURN TRUE;
END;
$$;
