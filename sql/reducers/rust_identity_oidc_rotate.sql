-- #339/#523: frozen OP refresh lock + access insert + hash attach + predecessor
-- revocation, in one transaction. All identity comes from the proved old hash.
CREATE OR REPLACE FUNCTION rust_identity_oidc_rotate(
    p_user_id bigint,p_client_id text,p_old_hash text,p_id text,
    p_scopes text[],p_refresh_hash text
) RETURNS TABLE(expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_old text;v_family text;v_family_expiry timestamptz;v_expiry timestamptz;v_phase text:='lock refresh token';
BEGIN
    IF p_user_id IS NULL OR p_user_id<=0 OR
       NULLIF(current_setting('app.current_user_id',true),'')::bigint IS DISTINCT FROM p_user_id THEN RETURN; END IF;
    -- #523: serialise with reuse revocation per family (same key as
    -- rust_identity_oidc_reuse), so a concurrent successor cannot outlive a revoke.
    SELECT COALESCE(t.refresh_family,t.id) INTO v_family FROM oidc_tokens t
     WHERE t.refresh_token_hash=p_old_hash AND t.user_id=p_user_id AND t.client_id=p_client_id LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('oidc-family:'||v_family,0));
    -- #523: the family's hard absolute lifetime bounds every rotation; legacy
    -- rows without a family are a family of one, capped 90 days from creation.
    SELECT t.id,COALESCE(t.refresh_family,t.id),
           COALESCE(t.refresh_family_expires_at,t.created_at+interval '90 days')
      INTO v_old,v_family,v_family_expiry FROM oidc_tokens t
     WHERE t.refresh_token_hash=p_old_hash AND t.user_id=p_user_id
       AND t.client_id=p_client_id AND t.revoked_at IS NULL AND t.refresh_expires_at>now()
       AND COALESCE(t.refresh_family_expires_at,t.created_at+interval '90 days')>now()
     LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    v_phase:='create access token';v_expiry:=clock_timestamp()+interval '5 minutes';
    INSERT INTO oidc_tokens(id,client_id,user_id,subject,scopes,expires_at,refresh_family,refresh_family_expires_at)
    VALUES(p_id,p_client_id,p_user_id,p_user_id::text,p_scopes,v_expiry,v_family,v_family_expiry);
    v_phase:='set refresh hash';
    UPDATE oidc_tokens t SET refresh_token_hash=p_refresh_hash,
        refresh_expires_at=LEAST(clock_timestamp()+interval '30 days',v_family_expiry)
     WHERE t.id=p_id AND t.user_id=p_user_id;
    v_phase:='revoke rotated refresh token';
    UPDATE oidc_tokens t SET revoked_at=now(),refresh_family=v_family
     WHERE t.refresh_token_hash=p_old_hash AND t.user_id=p_user_id AND t.revoked_at IS NULL;
    RETURN QUERY SELECT v_expiry;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION USING ERRCODE=SQLSTATE,MESSAGE=SQLERRM,
        HINT=jsonb_build_object('oidc_phase',v_phase)::text;
END;
$$;
