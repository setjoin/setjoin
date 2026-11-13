-- #546: SAML replay cache. One atomic call consumes the request ID (a SP-initiated
-- login answers exactly once) and the assertion ID (an assertion is accepted once
-- until it can no longer be presented). Both rows live until p_expires_at, which the
-- caller sets to the assertion's NotOnOrAfter plus the verification skew. All
-- values come from a verified assertion and the SP-signed tracking cookie.
CREATE OR REPLACE FUNCTION rust_identity_saml_consume(
    p_registration_id bigint,p_assertion_id text,p_request_id text,p_expires_at bigint
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_expiry timestamptz;
    v_rows int;
BEGIN
    IF p_registration_id IS NULL OR p_registration_id<=0
       OR p_assertion_id IS NULL OR octet_length(p_assertion_id) NOT BETWEEN 1 AND 512
       OR (p_request_id IS NOT NULL AND octet_length(p_request_id) NOT BETWEEN 1 AND 512)
       OR p_expires_at IS NULL THEN
        RETURN jsonb_build_object('status','invalid');
    END IF;
    IF NOT EXISTS(SELECT 1 FROM saml_sp_registrations WHERE id=p_registration_id AND enabled) THEN
        RETURN jsonb_build_object('status','unknown_registration');
    END IF;
    -- Bounded housekeeping: rows past their expiry can no longer matter.
    DELETE FROM saml_assertion_replay r WHERE r.ctid IN (
        SELECT ctid FROM saml_assertion_replay WHERE expires_at<now() LIMIT 100);
    v_expiry:=GREATEST(to_timestamp(p_expires_at),now()+interval '1 second');
    IF p_request_id IS NOT NULL THEN
        INSERT INTO saml_assertion_replay(registration_id,kind,token_hash,expires_at)
        VALUES(p_registration_id,'request',digest(p_request_id,'sha256'),v_expiry)
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_rows=ROW_COUNT;
        IF v_rows=0 THEN
            RETURN jsonb_build_object('status','replayed','what','request');
        END IF;
    END IF;
    INSERT INTO saml_assertion_replay(registration_id,kind,token_hash,expires_at)
    VALUES(p_registration_id,'assertion',digest(p_assertion_id,'sha256'),v_expiry)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
    IF v_rows=0 THEN
        RETURN jsonb_build_object('status','replayed','what','assertion');
    END IF;
    RETURN jsonb_build_object('status','consumed');
END;
$$;
SELECT apply_worker_ownership(
    'rust_identity_saml_consume(bigint,text,text,bigint)'::regprocedure
);
