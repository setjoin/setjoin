-- #334: fenced full-tuple preparation; typed refusal cleanup is reducer-owned.
CREATE OR REPLACE FUNCTION rust_identity_totp_confirm_read(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_enrollment text,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_generation bigint; v_enabled boolean; v_secret text;
    v_jti text:=COALESCE(p_claims->>'jti',''); v_family text:=NULLIF(p_claims->>'fam','');
    v_grant mfa_reauth_step_ups%ROWTYPE; v_stage text:='fence';
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    SELECT factor_generation,COALESCE(totp_enabled,FALSE) INTO v_generation,v_enabled
        FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','internal'); END IF;
    IF EXISTS(SELECT 1 FROM session_revocations WHERE user_id=p_user_id
       AND (expires_at IS NULL OR expires_at>now()) AND
       ((scope='jti' AND jti=v_jti) OR (scope='family' AND family_id=COALESCE(v_family,''))
       OR (scope='all' AND (p_claims->>'iat' IS NULL OR to_timestamp((p_claims->>'iat')::double precision)<=not_before)))) THEN
        RETURN jsonb_build_object('status','revoked');
    END IF;
    v_stage:='confirm';
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation=CASE WHEN v_enabled THEN 'totp.replace' ELSE 'totp.enroll' END
        AND target_ref IS NOT DISTINCT FROM p_enrollment AND token_scope='session'
        AND refresh_family_id IS NOT DISTINCT FROM v_family AND expires_at>now() AND bound_factor_generation=v_generation;
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
            AND session_jti=v_jti AND expires_at>now();
        RETURN jsonb_build_object('status','reauth_gate');
    END IF;
    SELECT pgp_sym_decrypt(secret_enc::bytea,current_setting('app.encryption_key')) INTO v_secret
        FROM totp_pending_enrollments WHERE id=p_enrollment::uuid AND user_id=p_user_id
            AND staged_by_jti=v_jti AND expires_at>now();
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id AND session_jti=v_jti;
        INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes)
            VALUES(p_user_id,NULLIF(p_ip,'')::inet,'mfa_reauth_refused','user',p_user_id,'totp confirm binding mismatch');
        RETURN jsonb_build_object('status','reauth_binding');
    END IF;
    RETURN jsonb_build_object('status','ready','secret',v_secret,'enabled',v_enabled);
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('status',CASE WHEN v_stage='fence' THEN 'internal' ELSE 'confirm_failed' END);
END;
$$;
