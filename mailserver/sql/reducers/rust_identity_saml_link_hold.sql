-- #546: a link-purpose SAML assertion that verified at the ACS waits for the same
-- session's same-site completion request. The row binds the assertion's subject and
-- groups to one link flow and a one-time token (stored as its SHA-256), for two minutes.
-- Nothing here mints a session or provisions a user.
CREATE OR REPLACE FUNCTION rust_identity_saml_link_hold(
    p_registration_id bigint,p_flow uuid,p_token_hash bytea,p_subject text,p_groups jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_registration_id IS NULL OR p_registration_id<=0 OR p_flow IS NULL
       OR p_token_hash IS NULL OR octet_length(p_token_hash)<>32
       OR p_subject IS NULL OR octet_length(p_subject) NOT BETWEEN 1 AND 2048 THEN
        RETURN jsonb_build_object('status','invalid');
    END IF;
    IF NOT EXISTS(SELECT 1 FROM saml_sp_registrations WHERE id=p_registration_id AND enabled) THEN
        RETURN jsonb_build_object('status','unknown_registration');
    END IF;
    DELETE FROM saml_link_completions c WHERE c.ctid IN (
        SELECT ctid FROM saml_link_completions WHERE expires_at<now() LIMIT 100);
    -- One pending completion per flow: a newer assertion replaces an older one.
    DELETE FROM saml_link_completions WHERE registration_id=p_registration_id AND flow_id=p_flow;
    INSERT INTO saml_link_completions(token_hash,registration_id,flow_id,subject,groups,expires_at)
    VALUES(p_token_hash,p_registration_id,p_flow,p_subject,p_groups,now()+interval '2 minutes');
    RETURN jsonb_build_object('status','held');
END;
$$;
SELECT apply_worker_ownership(
    'rust_identity_saml_link_hold(bigint,uuid,bytea,text,jsonb)'::regprocedure
);
