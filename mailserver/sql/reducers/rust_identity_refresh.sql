-- #332 frozen RefreshTokens (rotation grace hardened by #490). Read a mint proposal, then re-derive it under the
-- SAME person/row fences at the write seam. A changed proposal retries without
-- writing. Rust signs outside SQL; no stale proposal may publish an anchor.
CREATE OR REPLACE FUNCTION rust_identity_refresh(
    p_user_id bigint, p_hash bytea, p_claim_family text,
    p_expected jsonb, p_new_hash bytea, p_expiry_seconds bigint, p_new_family uuid
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_parent oauth_tokens%ROWTYPE;
    v_tip oauth_tokens%ROWTYPE;
    v_user users%ROWTYPE;
    v_admin boolean;
    v_guest boolean;
    v_context jsonb;
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    SELECT * INTO v_parent FROM oauth_tokens WHERE token_hash=p_hash FOR UPDATE;
    IF NOT FOUND THEN
        IF EXISTS(SELECT 1 FROM oauth_tokens WHERE user_id=p_user_id AND previous_token_hash=p_hash AND revoked_at IS NULL) THEN
            PERFORM revoke_user_sessions(p_user_id,'all','token_revoke_all',NULL,NULL,NULL);
        END IF;
        RETURN jsonb_build_object('status','denied');
    END IF;
    IF v_parent.user_id<>p_user_id THEN
        -- Exact signed-token hash is the authority for this corruption fence.
        UPDATE oauth_tokens SET revoked_at=COALESCE(revoked_at,statement_timestamp())
         WHERE token_hash=p_hash AND user_id=v_parent.user_id;
        RETURN jsonb_build_object('status','denied');
    END IF;
    IF NOT identity_transition_admission_allowed(p_user_id) THEN
        RETURN jsonb_build_object('status','denied');
    END IF;
    v_tip:=v_parent;
    IF v_parent.rotated_at IS NOT NULL THEN
        -- Owner-approved security fix 2026-11-05 (#490): the 30 s rotation grace
        -- never admits a revoked or expired rotated parent.
        IF v_parent.revoked_at IS NOT NULL OR v_parent.expires_at<clock_timestamp() THEN
            RETURN jsonb_build_object('status','denied');
        END IF;
        IF clock_timestamp()-v_parent.rotated_at<=interval '30 seconds' THEN
            SELECT * INTO v_tip FROM oauth_tokens
             WHERE family_id::text=p_claim_family AND rotated_at IS NULL
               AND revoked_at IS NULL AND expires_at>now()
             ORDER BY id DESC LIMIT 1 FOR UPDATE;
            IF FOUND AND v_tip.user_id<>p_user_id THEN
                RETURN jsonb_build_object('status','denied');
            END IF;
            IF NOT FOUND THEN v_tip.id:=NULL; END IF;
        ELSE v_tip.id:=NULL;
        END IF;
        IF v_tip.id IS NULL THEN
            PERFORM revoke_user_sessions(p_user_id,'all','token_revoke_all',NULL,NULL,NULL);
            RETURN jsonb_build_object('status','denied');
        END IF;
    ELSIF v_parent.revoked_at IS NOT NULL OR v_parent.expires_at<clock_timestamp() THEN
        RETURN jsonb_build_object('status','denied');
    END IF;
    SELECT * INTO v_user FROM users WHERE id=p_user_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','denied'); END IF;
    v_guest:=is_guest_account(p_user_id);
    SELECT EXISTS(SELECT 1 FROM admin_role_assignments WHERE user_id=p_user_id AND (expires_at IS NULL OR expires_at>now())) INTO v_admin;
    IF NOT v_user.enabled THEN
        PERFORM revoke_user_sessions(p_user_id,'all','token_revoke_all',NULL,NULL,NULL);
        RETURN jsonb_build_object('status','denied');
    END IF;
    v_context:=jsonb_build_object('status','mint','user',p_user_id,'email',v_user.email,
        'admin',v_admin,'guest',v_guest,'parent',encode(v_tip.token_hash,'hex'),'family',v_tip.family_id);
    IF p_expected IS NULL THEN RETURN v_context; END IF;
    IF p_expected<>v_context THEN RETURN jsonb_build_object('status','retry'); END IF;
    UPDATE oauth_tokens SET rotated_at=now() WHERE user_id=p_user_id AND token_hash=v_tip.token_hash;
    INSERT INTO oauth_tokens(user_id,token_hash,token_type,previous_token_hash,expires_at,family_id)
    VALUES(p_user_id,p_new_hash,'refresh',v_tip.token_hash,now()+make_interval(secs=>p_expiry_seconds),COALESCE(v_tip.family_id,p_new_family));
    IF NULLIF(current_setting('app.rust_operation_id',true),'') IS NOT NULL THEN
        INSERT INTO rust_operation_receipts(operation_id,family,command)
        VALUES(current_setting('app.rust_operation_id')::uuid,'F21','refresh');
    END IF;
    RETURN v_context;
END;
$$;
