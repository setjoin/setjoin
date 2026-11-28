CREATE OR REPLACE FUNCTION identity_transition_elevation_consume(
    p_elevation_id UUID,
    p_actor BIGINT,
    p_transition_id UUID,
    p_preview_digest BYTEA,
    p_transition_generation BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_id UUID;
BEGIN
    UPDATE identity_transition_elevations e
       SET consumed_at=statement_timestamp()
      FROM users u
     WHERE e.id=p_elevation_id
       AND e.actor_user_id=p_actor
       AND e.transition_id=p_transition_id
       AND e.preview_digest=p_preview_digest
       AND e.transition_generation=p_transition_generation
       AND e.consumed_at IS NULL
       AND e.invalidated_at IS NULL
       AND e.expires_at>statement_timestamp()
       AND u.id=e.actor_user_id
       AND u.enabled
    RETURNING e.id INTO v_id;

    IF v_id IS NULL THEN
        RAISE EXCEPTION 'identity transition elevation is missing, expired, stale, disabled, or already consumed'
            USING ERRCODE='BZ236',
                  HINT='{"type":"identity_approval_invalid","remediation":"complete a fresh transition-scoped step-up"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_elevation_consume(uuid,bigint,uuid,bytea,bigint)'::regprocedure
);
