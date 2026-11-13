-- #334: one Go caller-owned transaction: promote, consume, audit and refresh anchor.
DROP FUNCTION IF EXISTS rust_identity_totp_bootstrap_confirm(bigint,jsonb,text,text,text,bytea,bigint,uuid);
CREATE OR REPLACE FUNCTION rust_identity_totp_bootstrap_confirm(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_enrollment text,p_ip text,
    p_refresh_hash bytea,p_expiry bigint,p_family uuid,p_counter bigint,p_secret_hash bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_grant mfa_reauth_step_ups%ROWTYPE;v_secret text;v_live boolean;v_stage text:='confirm';
    v_jti text:=COALESCE(p_claims->>'jti','');
BEGIN
    -- bootstrap_read already holds the fences and checked policy/revocation.
    -- Repeating policy here would add a check that frozen Go never performs.
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND target_ref=p_enrollment AND operation='bootstrap.totp.enroll'
        AND token_scope='mfa_pending' AND refresh_family_id IS NULL AND expires_at>now()
        AND bound_factor_generation=(SELECT factor_generation FROM users WHERE id=p_user_id);
    IF NOT FOUND THEN RETURN jsonb_build_object('status','confirm_failed'); END IF;
    v_live:=TRUE;
    IF v_grant.proof_method='totp' THEN SELECT COALESCE(totp_enabled,FALSE) INTO v_live FROM users WHERE id=p_user_id;
    ELSIF v_grant.proof_method='webauthn_uv' THEN
        SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE id=v_grant.proving_factor_id AND user_id=p_user_id AND revoked_at IS NULL) INTO v_live;
    END IF;
    IF NOT v_live THEN RETURN jsonb_build_object('status','reauth_binding'); END IF;
    PERFORM 1 FROM users WHERE id=p_user_id AND enabled AND NOT COALESCE(totp_enabled,FALSE);
    IF NOT FOUND THEN RETURN jsonb_build_object('status','state_changed'); END IF;
    SELECT pgp_sym_decrypt(secret_enc::bytea,current_setting('app.encryption_key')) INTO v_secret
        FROM totp_pending_enrollments WHERE id=p_enrollment::uuid AND user_id=p_user_id AND staged_by_jti=v_jti AND expires_at>now();
    IF NOT FOUND THEN RETURN jsonb_build_object('status','confirm_failed'); END IF;
    DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND target_ref=p_enrollment AND operation='bootstrap.totp.enroll'
        AND token_scope='mfa_pending' AND refresh_family_id IS NULL AND expires_at>now()
        AND bound_factor_generation=(SELECT factor_generation FROM users WHERE id=p_user_id);
    IF NOT FOUND THEN RETURN jsonb_build_object('status','confirm_failed'); END IF;
    UPDATE users SET totp_secret_enc=pgp_sym_encrypt(v_secret,current_setting('app.encryption_key')),
        totp_enabled=TRUE,totp_enabled_at=clock_timestamp(),last_totp_used_at=clock_timestamp(),
        totp_failed_attempts=0,totp_locked_until=NULL,factor_generation=factor_generation+1
        WHERE id=p_user_id AND enabled AND NOT COALESCE(totp_enabled,FALSE);
    IF p_counter IS NULL OR p_counter<0 OR octet_length(p_secret_hash) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'verified TOTP counter binding missing' USING ERRCODE='22023';
    END IF;
    INSERT INTO totp_counter_claims(user_id,secret_hash,last_counter) VALUES(p_user_id,p_secret_hash,p_counter)
        ON CONFLICT(user_id) DO UPDATE SET secret_hash=EXCLUDED.secret_hash,last_counter=EXCLUDED.last_counter
        WHERE totp_counter_claims.user_id=p_user_id;
    DELETE FROM totp_pending_enrollments WHERE id=p_enrollment::uuid AND user_id=p_user_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id)
        VALUES(p_user_id,NULLIF(p_ip,'')::inet,'totp_confirmed','user',p_user_id);
    v_stage:='store';
    INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id)
        VALUES(p_user_id,p_refresh_hash,'refresh',now()+make_interval(secs=>p_expiry),p_family);
    IF NULLIF(current_setting('app.rust_operation_id',true),'') IS NOT NULL THEN
        INSERT INTO rust_operation_receipts(operation_id,family,command)
            VALUES(current_setting('app.rust_operation_id')::uuid,'F21','mfa-bootstrap');
    END IF;
    RETURN jsonb_build_object('status','minted');
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('status',CASE WHEN v_stage='store' THEN 'store_failed' ELSE 'confirm_failed' END);
END;
$$;
