-- #341: frozen SAML link elevation plus the actor-bound opaque COMMIT receipt.
CREATE OR REPLACE FUNCTION rust_identity_saml_link_begin(
    p_user_id bigint,p_flow uuid,p_jti text,p_hash bytea,p_provider_key text,p_expiry bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_result jsonb;
BEGIN
    v_result:=identity_auth_link_elevation_begin(
        p_user_id,p_flow,p_jti,p_hash,'saml',p_provider_key,to_timestamp(p_expiry)
    );
    INSERT INTO rust_operation_receipts(operation_id,family,command)
    VALUES(current_setting('app.rust_operation_id')::uuid,'F21','saml-link-begin');
    RETURN v_result;
END;
$$;
