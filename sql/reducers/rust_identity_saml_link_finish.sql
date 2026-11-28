-- #546: the SAML counterpart of rust_identity_rp_link_finish. The authorized
-- link (one-use V171 elevation bound to the live session), exact-provider group
-- mapping and normalized entitlement reconciliation share one transaction.
-- The subject is the verified assertion's NameID and the provider is the
-- registration's IdP entity ID; never an address.
CREATE OR REPLACE FUNCTION rust_identity_saml_link_finish(
    p_user_id bigint,p_provider text,p_subject text,p_provider_key text,
    p_flow uuid,p_hash bytea,p_groups jsonb,p_mappings jsonb,p_allow_super boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_stage text:='link';v_result jsonb;v_hint text;
BEGIN
    PERFORM identity_auth_link_authorized(p_user_id,p_user_id,'saml',p_provider,p_subject,p_provider_key,
        'authenticated federated account linking',p_flow,p_hash);
    v_stage:='mapping';
    PERFORM rust_identity_rp_map(p_user_id,p_provider_key,p_groups,p_mappings,p_allow_super);
    v_stage:='normalized';
    v_result:=identity_entitlements_reconcile_sso(p_user_id,p_provider_key);
    IF NOT COALESCE((v_result->>'reconciled')::boolean,false) THEN
        RAISE EXCEPTION 'normalized SSO entitlement reconciliation refused' USING ERRCODE='BZ230',HINT='{"type":"identity_subject_conflict"}';
    END IF;
    INSERT INTO rust_operation_receipts(operation_id,family,command)
    VALUES(current_setting('app.rust_operation_id')::uuid,'F21','saml-link-finish');
    RETURN jsonb_build_object('status','linked');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_hint=PG_EXCEPTION_HINT;
    RETURN jsonb_build_object('status',v_stage||'_failed','sqlstate',SQLSTATE,'hint',v_hint);
END;
$$;
