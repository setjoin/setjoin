CREATE OR REPLACE FUNCTION identity_transition_challenge_complete(
    p_actor BIGINT,
    p_transition_id UUID,
    p_challenge_id UUID,
    p_preview_digest TEXT,
    p_session_digest BYTEA,
    p_factor_digest BYTEA,
    p_amr TEXT[],
    p_acr TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT identity_transition_elevation_issue(
        p_actor,p_transition_id,p_challenge_id,p_preview_digest,
        p_session_digest,p_factor_digest,p_amr,p_acr,p_idempotency_key
    )
$$;
SELECT apply_worker_ownership(
    'identity_transition_challenge_complete(bigint,uuid,uuid,text,bytea,bytea,text[],text,uuid)'::regprocedure
);
