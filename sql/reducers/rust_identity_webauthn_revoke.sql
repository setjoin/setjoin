-- #335: established-session target-bound revocation under the person/users fence.
CREATE OR REPLACE FUNCTION rust_identity_webauthn_revoke(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_target text,p_id bytea,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_fence jsonb;v_grant mfa_reauth_step_ups%ROWTYPE;v_live boolean:=TRUE;
    v_jti text:=COALESCE(p_claims->>'jti','');v_phase text:='grant';
BEGIN
    v_fence:=rust_identity_webauthn_fence(p_user_id,p_claims);
    IF v_fence->>'status'<>'ready' THEN RETURN v_fence; END IF;
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation='webauthn.revoke' AND target_ref=p_target
        AND token_scope='session' AND refresh_family_id IS NOT DISTINCT FROM NULLIF(p_claims->>'fam','')
        AND expires_at>now() AND bound_factor_generation=(v_fence->>'generation')::bigint;
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
            AND session_jti=v_jti AND expires_at>now();
        RETURN jsonb_build_object('status','reauth_gate');
    END IF;
    IF v_grant.proof_method='totp' THEN
        SELECT COALESCE(totp_enabled,FALSE) INTO v_live FROM users WHERE id=p_user_id;
    ELSIF v_grant.proof_method='webauthn_uv' THEN
        SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id=p_user_id
            AND id=v_grant.proving_factor_id AND revoked_at IS NULL) INTO v_live;
    END IF;
    IF NOT v_live THEN RETURN jsonb_build_object('status','proving_factor'); END IF;
    -- Go rolls the consumed grant back when the owned target is already dead/missing.
    IF NOT EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id=p_user_id AND id=p_id AND revoked_at IS NULL) THEN
        RETURN jsonb_build_object('status','missing');
    END IF;
    DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation='webauthn.revoke' AND target_ref=p_target
        AND token_scope='session' AND refresh_family_id IS NOT DISTINCT FROM NULLIF(p_claims->>'fam','')
        AND expires_at>now() AND bound_factor_generation=(v_fence->>'generation')::bigint;
    IF NOT FOUND THEN RAISE EXCEPTION 'revocation grant changed under user fence'; END IF;
    v_phase:='revoke';
    UPDATE passkey_credentials SET revoked_at=now() WHERE id=p_id AND user_id=p_user_id AND revoked_at IS NULL;
    v_phase:='tail';
    UPDATE users SET factor_generation=factor_generation+1 WHERE id=p_user_id;
    DELETE FROM mfa_reauth_step_ups WHERE user_id=p_user_id AND proving_factor_id=p_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id)
        VALUES(p_user_id,p_ip::inet,'passkey_revoked','user',p_user_id);
    RETURN jsonb_build_object('status','revoked_credential');
EXCEPTION WHEN OTHERS THEN
    IF v_phase='revoke' THEN RETURN jsonb_build_object('status','update_error','detail','ERROR: '||SQLERRM||' (SQLSTATE '||SQLSTATE||')'); END IF;
    RETURN jsonb_build_object('status','internal');
END;
$$;
