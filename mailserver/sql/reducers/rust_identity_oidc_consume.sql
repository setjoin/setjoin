-- #339/#523: p_client_id (the authenticated presenting client) is part of the
-- predicate, so another client cannot burn a code. Frozen OP AuthRequestByCode's SELECT FOR UPDATE + DELETE transaction.
-- The presented code hash proves a candidate owner; the same owner and hash
-- are repeated under lock and in DELETE. No PKCE/client checks move into this
-- transaction: Go consumes the code before those independent validations.
CREATE OR REPLACE FUNCTION rust_identity_oidc_consume(p_user_id bigint,p_code_hash bytea,p_client_id text)
RETURNS TABLE(id text,client_id text,redirect_uri text,state text,nonce text,
              code_challenge text,scopes text[],user_id bigint,done boolean,
              auth_time timestamptz,acr text,amr text[])
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_row oidc_auth_requests%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_user_id<=0 OR
       NULLIF(current_setting('app.current_user_id',true),'')::bigint IS DISTINCT FROM p_user_id THEN
        RETURN;
    END IF;
    SELECT r.* INTO v_row FROM oidc_auth_requests r
     WHERE r.code_hash=p_code_hash AND r.user_id=p_user_id AND r.client_id=p_client_id
       AND r.expires_at>now() AND r.done=true FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    DELETE FROM oidc_auth_requests r
     WHERE r.id=v_row.id AND r.user_id=p_user_id AND r.code_hash=p_code_hash AND r.client_id=p_client_id;
    RETURN QUERY SELECT v_row.id,v_row.client_id,v_row.redirect_uri,v_row.state,
        v_row.nonce,v_row.code_challenge,v_row.scopes,v_row.user_id,v_row.done,
        COALESCE(v_row.auth_time,v_row.created_at),COALESCE(v_row.acr,''),v_row.amr;
END;
$$;
