-- #523 owner-approved security fix 2026-11-05: presenting an already-rotated
-- (or revoked) refresh token again means it leaked. Revoke every live token of
-- its family in one transaction. Identity comes only from the proved user: the
-- family is found through the presented hash under the same user and client.
CREATE OR REPLACE FUNCTION rust_identity_oidc_reuse(p_user_id bigint,p_client_id text,p_hash text)
RETURNS TABLE(revoked bigint)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_family text;v_count bigint;
BEGIN
    IF p_user_id IS NULL OR p_user_id<=0 OR
       NULLIF(current_setting('app.current_user_id',true),'')::bigint IS DISTINCT FROM p_user_id THEN RETURN; END IF;
    SELECT COALESCE(t.refresh_family,t.id) INTO v_family FROM oidc_tokens t
     WHERE t.refresh_token_hash=p_hash AND t.user_id=p_user_id
       AND t.client_id=p_client_id AND t.revoked_at IS NOT NULL LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('oidc-family:'||v_family,0));
    UPDATE oidc_tokens t SET revoked_at=now()
     WHERE t.user_id=p_user_id AND t.client_id=p_client_id
       AND (t.refresh_family=v_family OR t.id=v_family) AND t.revoked_at IS NULL;
    GET DIAGNOSTICS v_count=ROW_COUNT;
    RETURN QUERY SELECT v_count;
END;
$$;
