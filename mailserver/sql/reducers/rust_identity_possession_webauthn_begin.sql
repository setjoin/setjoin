-- #336: no proof is consumed when creating a management assertion ceremony.
CREATE OR REPLACE FUNCTION rust_identity_possession_webauthn_begin(
    p_user_id bigint,p_claims jsonb,p_operation text,p_target text,p_hash text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_fence jsonb;v_user users%ROWTYPE;v_keys jsonb;
    v_scope text:=CASE WHEN p_claims->>'typ'='mfa_pending' THEN 'mfa_pending' ELSE 'session' END;
BEGIN
    v_fence:=rust_identity_webauthn_fence(p_user_id,p_claims);
    IF v_fence->>'status'<>'ready' THEN RETURN v_fence; END IF;
    SELECT * INTO STRICT v_user FROM users WHERE id=p_user_id;
    IF NOT (COALESCE(v_user.totp_enabled,FALSE) OR EXISTS(SELECT 1 FROM passkey_credentials
        WHERE user_id=p_user_id AND revoked_at IS NULL AND uv_capable)) THEN
        RETURN jsonb_build_object('status','cohort');
    END IF;
    IF v_user.possession_webauthn_locked_until>clock_timestamp() THEN
        RETURN jsonb_build_object('status','locked');
    END IF;
    IF p_target IS NOT NULL AND NOT EXISTS(SELECT 1 FROM passkey_credentials
        WHERE user_id=p_user_id AND revoked_at IS NULL
        AND id=decode(translate(p_target,'-_','+/')||repeat('=',(4-length(p_target)%4)%4),'base64')) THEN
        RETURN jsonb_build_object('status','target');
    END IF;
    IF NOT v_user.enabled THEN RETURN jsonb_build_object('status','internal'); END IF;
    IF EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id=p_user_id AND revoked_at IS NULL AND uv_capable AND sign_count<0) THEN
        RETURN jsonb_build_object('status','internal');
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',encode(id,'hex'),'key',encode(public_key,'hex'),'count',sign_count)),'[]'::jsonb)
        INTO v_keys FROM passkey_credentials WHERE user_id=p_user_id AND revoked_at IS NULL AND uv_capable;
    DELETE FROM webauthn_ceremonies WHERE user_id=p_user_id AND kind='management_assertion';
    INSERT INTO webauthn_ceremonies(challenge_hash,user_id,kind,operation,target_ref,session_jti,token_scope,refresh_family_id,expires_at)
        VALUES(p_hash,p_user_id,'management_assertion',p_operation,p_target,COALESCE(p_claims->>'jti',''),v_scope,
            CASE WHEN v_scope='session' THEN NULLIF(p_claims->>'fam','') ELSE NULL END,now()+interval '5 minutes');
    RETURN jsonb_build_object('status','created','keys',v_keys);
END;
$$;
