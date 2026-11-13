-- SCIM requests are already one remote object per HTTP transaction. Wrap the
-- common inbox/apply/finish reducers in one database transaction so concurrent
-- SCIM requests serialize on the source row without exposing an open-batch
-- window between client round trips.
CREATE OR REPLACE FUNCTION identity_source_scim_apply(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_request_id UUID,
    p_external_subject TEXT,
    p_payload JSONB
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_apply JSONB;
    v_finish JSONB;
BEGIN
    PERFORM identity_source_batch_begin(
        p_source_id,
        p_expected_generation,
        p_request_id,
        jsonb_build_object('requestId',p_request_id),
        jsonb_build_array(jsonb_build_object(
            'objectKey',p_external_subject,
            'immutableSubject',p_external_subject,
            'payload',p_payload
        ))
    );
    v_apply := identity_source_entry_apply(
        p_source_id,p_expected_generation,p_request_id,p_external_subject
    );
    IF v_apply->>'state' <> 'applied' THEN
        RETURN v_apply;
    END IF;
    v_finish := identity_source_batch_finish(
        p_source_id,p_expected_generation,p_request_id,0
    );
    RETURN v_apply || jsonb_build_object(
        'cursorAdvanced',COALESCE((v_finish->>'cursorAdvanced')::boolean,false)
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_scim_apply(bigint,bigint,uuid,text,jsonb)'::regprocedure
);
