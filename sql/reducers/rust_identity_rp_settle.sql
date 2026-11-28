-- #340: frozen Go's committed SSO profile/entitlement transaction. User is
-- resolved from a cryptographically verified, nonce-bound external assertion.
-- Owner-approved security fix 2026-11-05 (#547): the IdP-asserted address no longer
-- rewrites the linked account's mailbox address (Go updated users.email on every login, so
-- an IdP could move a mailbox identity, bounded only by the #530 verified-email rule). The
-- address stays in the signature for the reducer contract and is not recorded or applied.
CREATE OR REPLACE FUNCTION rust_identity_rp_settle(
    p_user_id bigint,p_email text,p_provider_key text,p_groups jsonb,
    p_mappings jsonb,p_allow_super boolean,p_normalized boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_stage text:='profile';v_result jsonb;
BEGIN
    v_stage:='mapping';
    PERFORM rust_identity_rp_map(p_user_id,p_provider_key,p_groups,p_mappings,p_allow_super);
    IF p_normalized THEN
        v_stage:='normalized';
        v_result:=identity_entitlements_reconcile_sso(p_user_id,p_provider_key);
        IF NOT COALESCE((v_result->>'reconciled')::boolean,false) THEN
            RAISE EXCEPTION 'normalized SSO entitlement reconciliation refused' USING ERRCODE='BZ230',HINT='{"type":"identity_subject_conflict"}';
        END IF;
    END IF;
    RETURN jsonb_build_object('status','settled');
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('status',v_stage||'_failed');
END;
$$;
