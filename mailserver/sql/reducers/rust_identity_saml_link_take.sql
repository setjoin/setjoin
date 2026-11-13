-- #546: single-use take of a held link assertion. Returns it only for the registration
-- and link flow it was held for, before expiry, and deletes it in the same statement.
CREATE OR REPLACE FUNCTION rust_identity_saml_link_take(
    p_registration_id bigint,p_flow uuid,p_token_hash bytea
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_subject text;v_groups jsonb;
BEGIN
    IF p_registration_id IS NULL OR p_flow IS NULL OR p_token_hash IS NULL THEN
        RETURN jsonb_build_object('status','none');
    END IF;
    DELETE FROM saml_link_completions
     WHERE token_hash=p_token_hash AND registration_id=p_registration_id
       AND flow_id=p_flow AND expires_at>now()
    RETURNING subject,groups INTO v_subject,v_groups;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status','none');
    END IF;
    RETURN jsonb_build_object('status','taken','subject',v_subject,'groups',v_groups);
END;
$$;
SELECT apply_worker_ownership(
    'rust_identity_saml_link_take(bigint,uuid,bytea)'::regprocedure
);
