-- #335: frozen register begin transaction. Proof issuers remain #336.
CREATE OR REPLACE FUNCTION rust_identity_webauthn_begin(
    p_user_id bigint,p_claims jsonb,p_token_hash text,p_challenge_hash text,p_handle bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_fence jsonb;v_grant mfa_reauth_step_ups%ROWTYPE;v_handle bytea;v_email text;v_display text;
    v_jti text:=COALESCE(p_claims->>'jti','');v_stage text:='gate';
BEGIN
    v_fence:=rust_identity_webauthn_fence(p_user_id,p_claims);
    IF v_fence->>'status'<>'ready' THEN RETURN v_fence; END IF;
    SELECT * INTO v_grant FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
        AND session_jti=v_jti AND operation='webauthn.register' AND token_scope='session'
        AND refresh_family_id IS NOT DISTINCT FROM NULLIF(p_claims->>'fam','')
        AND expires_at>now() AND bound_factor_generation=(v_fence->>'generation')::bigint;
    IF NOT FOUND THEN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_token_hash AND user_id=p_user_id
            AND session_jti=v_jti AND expires_at>now();
        RETURN jsonb_build_object('status','reauth');
    END IF;
    IF v_grant.target_ref IS NOT NULL THEN
        IF EXISTS(SELECT 1 FROM webauthn_ceremonies WHERE challenge_hash=v_grant.target_ref
            AND user_id=p_user_id AND kind='registration' AND expires_at>now()) THEN
            RETURN jsonb_build_object('status','bound');
        END IF;
        RETURN jsonb_build_object('status','bound_dead');
    END IF;
    v_stage:='begin';
    SELECT email,display_name,webauthn_user_handle INTO v_email,v_display,v_handle
        FROM users WHERE id=p_user_id AND enabled=TRUE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','webauthn_error','detail','no rows in result set'); END IF;
    IF v_handle IS NULL OR octet_length(v_handle)=0 THEN
        UPDATE users SET webauthn_user_handle=p_handle WHERE id=p_user_id;
        v_handle:=p_handle;
    END IF;
    v_stage:='gate';
    UPDATE mfa_reauth_step_ups SET target_ref=p_challenge_hash WHERE token_hash=p_token_hash
        AND user_id=p_user_id AND session_jti=v_jti AND target_ref IS NULL;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','bound_dead'); END IF;
    DELETE FROM webauthn_ceremonies WHERE user_id=p_user_id AND kind='registration';
    INSERT INTO webauthn_ceremonies(challenge_hash,user_id,kind,operation,target_ref,session_jti,token_scope,refresh_family_id,expires_at)
        VALUES(p_challenge_hash,p_user_id,'registration','webauthn.register',p_challenge_hash,v_jti,'session',NULLIF(p_claims->>'fam',''),now()+interval '5 minutes');
    RETURN jsonb_build_object('status','created','email',v_email,'display',v_display,'handle',encode(v_handle,'hex'));
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('status',CASE WHEN v_stage='begin' THEN 'webauthn_error' ELSE 'internal' END,'detail',SQLERRM);
END;
$$;
