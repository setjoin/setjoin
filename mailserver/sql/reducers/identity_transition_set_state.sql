CREATE OR REPLACE FUNCTION identity_transition_set_state(
    p_transition_id UUID,
    p_expected_state TEXT,
    p_next_state TEXT,
    p_failure_code TEXT DEFAULT NULL
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_generation BIGINT;
BEGIN
    IF p_transition_id IS NULL
       OR p_expected_state IS NULL
       OR p_next_state IS NULL
       OR NOT identity_transition_state_allowed(
           p_expected_state,p_next_state
       ) THEN
        RAISE EXCEPTION 'illegal identity transition state change'
            USING ERRCODE='BZ234',
                  HINT=jsonb_build_object(
                      'type','identity_transition_preflight',
                      'from',p_expected_state,
                      'to',p_next_state
                  )::text;
    END IF;

    UPDATE identity_transitions
       SET state=p_next_state,
           transition_generation=transition_generation+1,
           failure_code=CASE
               WHEN p_next_state IN ('failed_precommit','failed_recoverable')
                   THEN p_failure_code
               ELSE NULL
           END,
           started_at=CASE
               WHEN p_next_state='executing'
                   THEN statement_timestamp()
               ELSE started_at
           END,
           completed_at=CASE
               WHEN p_next_state IN (
                   'completed','rolled_back','cancelled','expired'
               ) THEN statement_timestamp()
               ELSE completed_at
           END,
           updated_at=statement_timestamp()
     WHERE id=p_transition_id AND state=p_expected_state
    RETURNING transition_generation INTO v_generation;

    IF v_generation IS NULL THEN
        RAISE EXCEPTION 'identity transition state changed concurrently'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_preview_stale","remediation":"read the durable transition and retry only its named next action"}';
    END IF;
    RETURN v_generation;
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_set_state(uuid,text,text,text)'::regprocedure
);
