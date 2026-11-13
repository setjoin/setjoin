-- #547: a link-purpose OIDC assertion that verified at the callback waits for the same
-- session's same-site completion request. The row binds the assertion's issuer, subject and
-- groups to one link flow and a one-time token (stored as its SHA-256), for two minutes.
-- Nothing here mints a session, links, or provisions a user.
CREATE OR REPLACE FUNCTION rust_identity_rp_link_hold(
    p_provider_key text,p_flow uuid,p_token_hash bytea,p_issuer text,p_subject text,p_groups jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_provider_key IS NULL OR octet_length(p_provider_key) NOT BETWEEN 1 AND 2048
       OR p_flow IS NULL OR p_token_hash IS NULL OR octet_length(p_token_hash)<>32
       OR p_issuer IS NULL OR octet_length(p_issuer) NOT BETWEEN 1 AND 2048
       OR p_subject IS NULL OR octet_length(p_subject) NOT BETWEEN 1 AND 2048 THEN
        RETURN jsonb_build_object('status','invalid');
    END IF;
    DELETE FROM oidc_link_completions c WHERE c.ctid IN (
        SELECT ctid FROM oidc_link_completions WHERE expires_at<now() LIMIT 100);
    -- One pending completion per flow: a newer assertion replaces an older one.
    DELETE FROM oidc_link_completions WHERE provider_key=p_provider_key AND flow_id=p_flow;
    INSERT INTO oidc_link_completions(token_hash,provider_key,flow_id,issuer,subject,groups,expires_at)
    VALUES(p_token_hash,p_provider_key,p_flow,p_issuer,p_subject,p_groups,now()+interval '2 minutes');
    RETURN jsonb_build_object('status','held');
END;
$$;
SELECT apply_worker_ownership(
    'rust_identity_rp_link_hold(text,uuid,bytea,text,text,jsonb)'::regprocedure
);
