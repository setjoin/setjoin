-- #340: exact Go local/normalized SSO mint fence and refresh anchor. All
-- principal/fence values come from the verified external assertion's resolution.
CREATE OR REPLACE FUNCTION rust_identity_rp_mint(
    p_user_id bigint,p_fence jsonb,p_hash bytea,p_expiry bigint,p_family uuid
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_stage text:='identity';v_hint text;
BEGIN
    IF p_fence IS NOT NULL AND p_fence<>'null'::jsonb THEN
        PERFORM identity_auth_mint_fence(p_user_id,(p_fence->>'source_id')::bigint,
            (p_fence->>'source_generation')::bigint,(p_fence->>'link_id')::bigint,(p_fence->>'link_generation')::bigint);
    ELSE
        PERFORM identity_auth_local_mint_fence(p_user_id);
    END IF;
    v_stage:='store';
    INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id)
    VALUES(p_user_id,p_hash,'refresh',now()+make_interval(secs=>p_expiry),p_family);
    IF NULLIF(current_setting('app.rust_operation_id',true),'') IS NOT NULL THEN
        INSERT INTO rust_operation_receipts(operation_id,family,command)
        VALUES(current_setting('app.rust_operation_id')::uuid,'F21','rp-mint');
    END IF;
    RETURN jsonb_build_object('status','minted');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_hint=PG_EXCEPTION_HINT;
    RETURN jsonb_build_object('status',v_stage||'_failed','sqlstate',SQLSTATE,'hint',v_hint);
END;
$$;
