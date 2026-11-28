-- #336: retain the canonical user fence across the management assertion verifier.
CREATE OR REPLACE FUNCTION rust_identity_possession_webauthn_read(p_user_id bigint,p_claims jsonb,p_hash text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_fence jsonb;v_user users%ROWTYPE;v_ceremony webauthn_ceremonies%ROWTYPE;v_keys jsonb;v_handle bytea;
    v_scope text:=CASE WHEN p_claims->>'typ'='mfa_pending' THEN 'mfa_pending' ELSE 'session' END;
BEGIN
    v_fence:=rust_identity_webauthn_fence(p_user_id,p_claims);
    IF v_fence->>'status'<>'ready' THEN RETURN v_fence; END IF;
    SELECT * INTO STRICT v_user FROM users WHERE id=p_user_id;
    IF v_user.possession_webauthn_locked_until>clock_timestamp() THEN RETURN jsonb_build_object('status','locked'); END IF;
    SELECT * INTO v_ceremony FROM webauthn_ceremonies WHERE user_id=p_user_id AND challenge_hash=p_hash
        AND kind='management_assertion' AND token_scope=v_scope AND session_jti=COALESCE(p_claims->>'jti','') AND expires_at>now();
    IF NOT FOUND THEN RETURN jsonb_build_object('status','reauth'); END IF;
    IF v_ceremony.target_ref IS NOT NULL AND NOT EXISTS(SELECT 1 FROM passkey_credentials
        WHERE user_id=p_user_id AND revoked_at IS NULL AND id=decode(translate(v_ceremony.target_ref,'-_','+/')||repeat('=',(4-length(v_ceremony.target_ref)%4)%4),'base64')) THEN
        RETURN jsonb_build_object('status','target');
    END IF;
    IF NOT v_user.enabled OR EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id=p_user_id AND revoked_at IS NULL AND uv_capable AND sign_count<0) THEN
        RETURN jsonb_build_object('status','ready','force_invalid',TRUE);
    END IF;
    v_handle:=v_user.webauthn_user_handle;
    IF v_handle IS NULL OR octet_length(v_handle)=0 THEN v_handle:=convert_to(p_user_id::text,'UTF8'); END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',encode(id,'hex'),'key',encode(public_key,'hex'),'count',sign_count)),'[]'::jsonb)
        INTO v_keys FROM passkey_credentials WHERE user_id=p_user_id AND revoked_at IS NULL AND uv_capable;
    RETURN jsonb_build_object('status','ready','keys',v_keys,'handle',encode(v_handle,'hex'));
END;
$$;

CREATE OR REPLACE FUNCTION rust_identity_possession_webauthn_finish(
    p_user_id bigint,p_claims jsonb,p_hash text,p_verdict text,p_factor bytea,p_grant_hash text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_ceremony webauthn_ceremonies%ROWTYPE;v_hint text;
    v_scope text:=CASE WHEN p_claims->>'typ'='mfa_pending' THEN 'mfa_pending' ELSE 'session' END;
BEGIN
    IF p_verdict='malformed' THEN RETURN jsonb_build_object('status','malformed'); END IF;
    IF p_verdict<>'accepted' THEN
        UPDATE users SET possession_webauthn_failed_attempts=possession_webauthn_failed_attempts+1,
            possession_webauthn_locked_until=CASE WHEN possession_webauthn_failed_attempts+1>=5 THEN now()+interval '15 minutes' ELSE possession_webauthn_locked_until END
            WHERE id=p_user_id AND (possession_webauthn_locked_until IS NULL OR possession_webauthn_locked_until<=now());
        RETURN jsonb_build_object('status','invalid');
    END IF;
    UPDATE users SET possession_webauthn_failed_attempts=0,possession_webauthn_locked_until=NULL WHERE id=p_user_id;
    DELETE FROM webauthn_ceremonies WHERE user_id=p_user_id AND kind='management_assertion'
        AND token_scope=v_scope AND session_jti=COALESCE(p_claims->>'jti','') AND challenge_hash=p_hash AND expires_at>now()
        RETURNING * INTO v_ceremony;
    IF NOT FOUND THEN RAISE EXCEPTION 'management ceremony missing' USING HINT='possession_ceremony_missing'; END IF;
    DELETE FROM mfa_reauth_step_ups WHERE user_id=p_user_id;
    INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,target_ref,proof_method,proving_factor_id,bound_factor_generation,token_scope,refresh_family_id,expires_at)
        SELECT p_grant_hash,p_user_id,COALESCE(p_claims->>'jti',''),v_ceremony.operation,v_ceremony.target_ref,'webauthn_uv',p_factor,factor_generation,v_scope,
            CASE WHEN v_scope='session' THEN NULLIF(p_claims->>'fam','') ELSE NULL END,now()+interval '5 minutes' FROM users WHERE id=p_user_id;
    RETURN jsonb_build_object('status','issued');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_hint=PG_EXCEPTION_HINT;
    RETURN jsonb_build_object('status',CASE WHEN v_hint='possession_ceremony_missing' THEN 'reauth' ELSE 'internal' END);
END;
$$;
