-- #334: fenced full-tuple preparation; typed refusal cleanup is reducer-owned.
CREATE OR REPLACE FUNCTION rust_identity_totp_bootstrap_read(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_enrollment text,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_generation bigint; v_enabled boolean; v_secret text;
    v_jti text:=COALESCE(p_claims->>'jti',''); v_family text:=NULLIF(p_claims->>'fam','');
    v_grant mfa_reauth_step_ups%ROWTYPE; v_stage text:='identity'; v_hash text;v_hint text;v_user_enabled boolean;
BEGIN
    IF COALESCE(p_claims->>'credential_fence','')<>'' OR (p_claims->'identity_fence' IS NOT NULL AND p_claims->'identity_fence'<>'null'::jsonb) THEN
    IF p_claims->'identity_fence' IS NOT NULL AND p_claims->'identity_fence'<>'null'::jsonb THEN
        IF COALESCE((p_claims#>>'{identity_fence,source_id}')::bigint,0)<=0
           OR COALESCE((p_claims#>>'{identity_fence,source_generation}')::bigint,0)<=0
           OR COALESCE((p_claims#>>'{identity_fence,link_id}')::bigint,0)<=0
           OR COALESCE((p_claims#>>'{identity_fence,link_generation}')::bigint,0)<=0 THEN
            RETURN jsonb_build_object('status','identity_changed');
        END IF;
        PERFORM identity_auth_mint_fence(p_user_id,(p_claims#>>'{identity_fence,source_id}')::bigint,
            (p_claims#>>'{identity_fence,source_generation}')::bigint,(p_claims#>>'{identity_fence,link_id}')::bigint,
            (p_claims#>>'{identity_fence,link_generation}')::bigint);
    ELSE PERFORM identity_auth_local_mint_fence(p_user_id); END IF;
    v_stage:='credential';
    IF COALESCE(p_claims->>'credential_fence','')<>'' THEN
        SELECT password_hash INTO v_hash FROM users WHERE id=p_user_id AND enabled;
        IF NOT FOUND OR translate(rtrim(encode(digest(v_hash,'sha256'),'base64'),'='),'+/','-_')<>p_claims->>'credential_fence' THEN
            RETURN jsonb_build_object('status','credential_changed');
        END IF;
    END IF;
    END IF;
    v_stage:='confirm';
    PERFORM identity_auth_person_fence(p_user_id);
    SELECT factor_generation,COALESCE(totp_enabled,FALSE),enabled INTO v_generation,v_enabled,v_user_enabled
        FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','internal'); END IF;
    IF EXISTS(SELECT 1 FROM session_revocations WHERE user_id=p_user_id
       AND (expires_at IS NULL OR expires_at>now()) AND
       ((scope='jti' AND jti=v_jti) OR (scope='family' AND family_id=COALESCE(v_family,''))
       OR (scope='all' AND (p_claims->>'iat' IS NULL OR to_timestamp((p_claims->>'iat')::double precision)<=not_before)))) THEN
        RETURN jsonb_build_object('status','revoked');
    END IF;
    IF (mfa_status(p_user_id)->>'status') IS DISTINCT FROM 'enrollment_required' THEN RETURN jsonb_build_object('status','state_changed'); END IF;
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation='bootstrap.totp.enroll'
        AND target_ref IS NOT DISTINCT FROM p_enrollment AND token_scope='mfa_pending'
        AND refresh_family_id IS NULL AND expires_at>now() AND bound_factor_generation=v_generation;
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
            AND session_jti=v_jti;
        INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes) VALUES(p_user_id,NULLIF(p_ip,'')::inet,'mfa_reauth_refused','user',p_user_id,'bootstrap enrollment grant mismatch');
        RETURN jsonb_build_object('status','reauth_binding');
    END IF;
    SELECT pgp_sym_decrypt(secret_enc::bytea,current_setting('app.encryption_key')) INTO v_secret
        FROM totp_pending_enrollments WHERE id=p_enrollment::uuid AND user_id=p_user_id
            AND staged_by_jti=v_jti AND expires_at>now();
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id AND session_jti=v_jti;
        INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes)
            VALUES(p_user_id,NULLIF(p_ip,'')::inet,'mfa_reauth_refused','user',p_user_id,'bootstrap enrollment binding mismatch');
        RETURN jsonb_build_object('status','reauth_binding');
    END IF;
    IF EXISTS(SELECT 1 FROM users WHERE id=p_user_id AND totp_locked_until>clock_timestamp()) THEN RETURN jsonb_build_object('status','locked'); END IF;
    RETURN jsonb_build_object('status','ready','secret',v_secret,'user_enabled',v_user_enabled);
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_hint=PG_EXCEPTION_HINT;
    RETURN jsonb_build_object('status',CASE WHEN v_stage='identity' THEN 'identity_changed' WHEN v_stage='credential' THEN 'credential_changed' ELSE 'confirm_failed' END,'sqlstate',SQLSTATE,'hint',v_hint);
END;
$$;
