-- #335: retain the Go person/users fence across Rust attestation verification.
CREATE OR REPLACE FUNCTION rust_identity_webauthn_registration_read(p_user_id bigint,p_claims jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_fence jsonb;v_handle bytea;v_credentials jsonb;
BEGIN
    v_fence:=rust_identity_webauthn_fence(p_user_id,p_claims);
    IF v_fence->>'status'<>'ready' THEN RETURN v_fence; END IF;
    SELECT webauthn_user_handle INTO v_handle FROM users WHERE id=p_user_id AND enabled=TRUE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','load_error','detail','no rows in result set'); END IF;
    -- The frozen read-only loader also reads live credentials before verification.
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',encode(id,'hex'),'key',encode(public_key,'hex'),
        'attestation',attestation_type,'count',sign_count)),'[]') INTO v_credentials
        FROM passkey_credentials WHERE user_id=p_user_id AND revoked_at IS NULL;
    RETURN jsonb_build_object('status','ready','handle',CASE WHEN v_handle IS NULL OR octet_length(v_handle)=0
        THEN encode(convert_to(p_user_id::text,'UTF8'),'hex') ELSE encode(v_handle,'hex') END,'credentials',v_credentials);
END;
$$;
