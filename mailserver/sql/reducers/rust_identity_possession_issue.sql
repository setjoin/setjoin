-- #336: password proof outcome, budget and grant under the retained canonical fences.
CREATE OR REPLACE FUNCTION rust_identity_possession_issue(
    p_user_id bigint,p_claims jsonb,p_operation text,p_target text,p_hash text,p_valid boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    IF p_valid IS DISTINCT FROM TRUE THEN
        UPDATE users SET possession_password_failed_attempts=possession_password_failed_attempts+1,
            possession_password_locked_until=CASE WHEN possession_password_failed_attempts+1>=5
                THEN now()+interval '15 minutes' ELSE possession_password_locked_until END
            WHERE id=p_user_id AND (possession_password_locked_until IS NULL OR possession_password_locked_until<=now());
        RETURN jsonb_build_object('status','invalid');
    END IF;
    UPDATE users SET possession_password_failed_attempts=0,possession_password_locked_until=NULL WHERE id=p_user_id;
    IF p_target IS NOT NULL AND NOT EXISTS(SELECT 1 FROM passkey_credentials
        WHERE user_id=p_user_id AND id=decode(translate(p_target,'-_','+/') || repeat('=',(4-length(p_target)%4)%4),'base64')
        AND revoked_at IS NULL) THEN
        -- Go rolls the success budget reset back when ownership fails.
        RAISE EXCEPTION 'invalid possession target' USING ERRCODE='22023',HINT='possession_invalid_target';
    END IF;
    DELETE FROM mfa_reauth_step_ups WHERE user_id=p_user_id;
    INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,target_ref,
        proof_method,proving_factor_id,bound_factor_generation,token_scope,refresh_family_id,expires_at)
        SELECT p_hash,p_user_id,COALESCE(p_claims->>'jti',''),p_operation,p_target,'password',NULL,
            factor_generation,'session',NULLIF(p_claims->>'fam',''),now()+interval '5 minutes'
        FROM users WHERE id=p_user_id;
    RETURN jsonb_build_object('status','issued');
END;
$$;
