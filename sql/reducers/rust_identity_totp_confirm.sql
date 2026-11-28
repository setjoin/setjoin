-- #334: called only after server TOTP proof under confirm_read's retained fence.
DROP FUNCTION IF EXISTS rust_identity_totp_confirm(bigint,jsonb,text,text,text);
CREATE OR REPLACE FUNCTION rust_identity_totp_confirm(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_enrollment text,p_ip text,p_counter bigint,p_secret_hash bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_read jsonb; v_grant mfa_reauth_step_ups%ROWTYPE;
    v_jti text:=COALESCE(p_claims->>'jti',''); v_live boolean;
BEGIN
    v_read:=rust_identity_totp_confirm_read(p_user_id,p_claims,p_token_hash,p_enrollment,p_ip);
    IF v_read->>'status'<>'ready' THEN RETURN v_read; END IF;
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND target_ref=p_enrollment AND expires_at>now();
    IF NOT FOUND THEN RETURN jsonb_build_object('status','reauth_gate'); END IF;
    v_live:=TRUE;
    IF v_grant.proof_method='totp' THEN
        SELECT COALESCE(totp_enabled,FALSE) INTO v_live FROM users WHERE id=p_user_id;
    ELSIF v_grant.proof_method='webauthn_uv' THEN
        SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE id=v_grant.proving_factor_id
            AND user_id=p_user_id AND revoked_at IS NULL) INTO v_live;
    END IF;
    IF NOT v_live THEN RETURN jsonb_build_object('status','proving_factor'); END IF;
    PERFORM 1 FROM users WHERE id=p_user_id AND enabled=TRUE
        AND COALESCE(totp_enabled,FALSE)=(v_read->>'enabled')::boolean;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','state_changed'); END IF;
    DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id AND session_jti=v_jti
        AND target_ref=p_enrollment AND operation=CASE WHEN (v_read->>'enabled')::boolean THEN 'totp.replace' ELSE 'totp.enroll' END
        AND token_scope='session' AND refresh_family_id IS NOT DISTINCT FROM NULLIF(p_claims->>'fam','')
        AND expires_at>now() AND bound_factor_generation=(SELECT factor_generation FROM users WHERE id=p_user_id);
    IF NOT FOUND THEN RETURN jsonb_build_object('status','reauth_gate'); END IF;
    UPDATE users SET totp_secret_enc=pgp_sym_encrypt(v_read->>'secret',current_setting('app.encryption_key')),
        totp_enabled=TRUE,totp_enabled_at=now(),last_totp_used_at=now(),totp_failed_attempts=0,
        totp_locked_until=NULL,factor_generation=factor_generation+1 WHERE id=p_user_id AND enabled=TRUE
        AND COALESCE(totp_enabled,FALSE)=(v_read->>'enabled')::boolean;
    IF p_counter IS NULL OR p_counter<0 OR octet_length(p_secret_hash) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'verified TOTP counter binding missing' USING ERRCODE='22023';
    END IF;
    INSERT INTO totp_counter_claims(user_id,secret_hash,last_counter) VALUES(p_user_id,p_secret_hash,p_counter)
        ON CONFLICT(user_id) DO UPDATE SET secret_hash=EXCLUDED.secret_hash,last_counter=EXCLUDED.last_counter
        WHERE totp_counter_claims.user_id=p_user_id;
    DELETE FROM totp_pending_enrollments WHERE id=p_enrollment::uuid AND user_id=p_user_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id)
        VALUES(p_user_id,p_ip::inet,'totp_confirmed','user',p_user_id);
    RETURN jsonb_build_object('status','confirmed');
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('status','confirm_failed');
END;
$$;
