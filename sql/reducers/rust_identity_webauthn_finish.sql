-- #335: called only after attestation verification under registration_read's retained fence.
CREATE OR REPLACE FUNCTION rust_identity_webauthn_finish(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_challenge_hash text,
    p_id bytea,p_key bytea,p_attestation text,p_count integer,p_uv boolean,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_fence jsonb;v_grant mfa_reauth_step_ups%ROWTYPE;v_jti text:=COALESCE(p_claims->>'jti','');
    v_live boolean:=TRUE;v_has_grant boolean;
BEGIN
    v_fence:=rust_identity_webauthn_fence(p_user_id,p_claims);
    IF v_fence->>'status'<>'ready' THEN RETURN v_fence; END IF;
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation='webauthn.register' AND target_ref=p_challenge_hash
        AND token_scope='session' AND refresh_family_id IS NOT DISTINCT FROM NULLIF(p_claims->>'fam','')
        AND expires_at>now() AND bound_factor_generation=(v_fence->>'generation')::bigint;
    v_has_grant:=FOUND;
    -- Go rolls both DELETEs back when the proving factor died. Read first under
    -- the retained user fence, then repeat the complete predicates at mutation.
    IF v_has_grant THEN
        IF v_grant.proof_method='totp' THEN
            SELECT COALESCE(totp_enabled,FALSE) INTO v_live FROM users WHERE id=p_user_id;
        ELSIF v_grant.proof_method='webauthn_uv' THEN
            SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id=p_user_id
                AND id=v_grant.proving_factor_id AND revoked_at IS NULL) INTO v_live;
        END IF;
        IF NOT v_live AND EXISTS(SELECT 1 FROM webauthn_ceremonies WHERE user_id=p_user_id
            AND kind='registration' AND token_scope='session' AND session_jti=v_jti
            AND challenge_hash=p_challenge_hash AND expires_at>now()) THEN
            RETURN jsonb_build_object('status','proving_factor');
        END IF;
    END IF;
    DELETE FROM webauthn_ceremonies WHERE user_id=p_user_id AND kind='registration'
        AND token_scope='session' AND session_jti=v_jti AND challenge_hash=p_challenge_hash AND expires_at>now();
    IF NOT FOUND THEN RETURN jsonb_build_object('status','reauth_ceremony'); END IF;
    DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation='webauthn.register' AND target_ref=p_challenge_hash
        AND token_scope='session' AND refresh_family_id IS NOT DISTINCT FROM NULLIF(p_claims->>'fam','')
        AND expires_at>now() AND bound_factor_generation=(v_fence->>'generation')::bigint;
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
            AND session_jti=v_jti AND expires_at>now();
        RETURN jsonb_build_object('status','reauth_gate');
    END IF;
    INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable)
        VALUES(p_id,p_user_id,p_key,p_attestation,p_count,'',now(),p_uv)
        ON CONFLICT(id) DO UPDATE SET public_key=p_key,sign_count=p_count,last_used_at=now(),uv_capable=p_uv
        WHERE passkey_credentials.user_id=EXCLUDED.user_id;
    IF NOT FOUND THEN RAISE unique_violation USING MESSAGE='credential id already registered to another account'; END IF;
    UPDATE users SET factor_generation=factor_generation+1 WHERE id=p_user_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes)
        VALUES(p_user_id,p_ip::inet,'passkey_registered','user',p_user_id,
            CASE WHEN p_uv THEN 'uv_capable=true' ELSE 'uv_capable=false' END);
    RETURN jsonb_build_object('status','registered');
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('status','internal');
END;
$$;
