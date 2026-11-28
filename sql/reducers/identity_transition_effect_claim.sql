CREATE OR REPLACE FUNCTION identity_transition_effect_claim(
    p_worker_id TEXT,
    p_lease_seconds INTEGER DEFAULT 120
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_effect identity_transition_effects%ROWTYPE;
BEGIN
    IF p_worker_id IS NULL
       OR octet_length(p_worker_id) NOT BETWEEN 1 AND 255
       OR p_worker_id ~ '[[:cntrl:]]'
       OR p_lease_seconds NOT BETWEEN 10 AND 600 THEN
        RAISE EXCEPTION 'invalid identity transition effect claim'
            USING ERRCODE='BZ241';
    END IF;

    SELECT e.* INTO v_effect
      FROM identity_transition_effects e
      JOIN identity_transitions t ON t.id=e.transition_id
     WHERE e.attempt_count<20
       AND (
           (t.state='effects_pending'
            AND e.effect_kind NOT LIKE 'rollback\_%' ESCAPE '\')
           OR
           (t.state='rolling_back'
            AND e.effect_kind LIKE 'rollback\_%' ESCAPE '\')
           OR
           (t.state='completed'
            AND e.effect_kind='subscriber_notice')
           OR
           (t.state='rolled_back'
            AND e.effect_kind='rollback_subscriber_notice')
       )
       AND (
           (e.state='pending'
            AND e.next_attempt_at<=statement_timestamp())
           OR
           (e.state='running'
            AND e.lease_expires_at<=statement_timestamp())
       )
     -- An explicitly retried effect has a non-zero attempt count and must be
     -- reclaimed before untouched siblings; otherwise a generic old pending
     -- sibling would run first and obscure the operator's exact retry.
     ORDER BY e.attempt_count DESC,e.next_attempt_at,
              e.transition_id,e.effect_kind
     FOR UPDATE OF e SKIP LOCKED
     LIMIT 1;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    UPDATE identity_transition_effects
       SET state='running',
           attempt_count=attempt_count+1,
           worker_id=p_worker_id,
           lease_expires_at=statement_timestamp()
               + make_interval(secs=>p_lease_seconds),
           updated_at=statement_timestamp()
     WHERE transition_id=v_effect.transition_id
       AND effect_kind=v_effect.effect_kind;
    UPDATE identity_transition_steps
       SET state='running',
           attempt_count=attempt_count+1,
           started_at=statement_timestamp(),
           finished_at=NULL,
           retry_at=NULL,
           error_code=NULL,
           error_detail=NULL
     WHERE transition_id=v_effect.transition_id
       AND stage=v_effect.effect_kind;

    RETURN (
        SELECT jsonb_build_object(
            'transitionId',e.transition_id,
            'effectId',e.effect_id,
            'kind',e.effect_kind,
            'userId',t.user_id::text,
            'attemptCount',e.attempt_count,
            'leaseExpiresAt',e.lease_expires_at,
            'targets',COALESCE((
                SELECT jsonb_agg(et.target_key ORDER BY et.target_key)
                  FROM identity_transition_effect_targets et
                 WHERE et.transition_id=e.transition_id
                   AND et.effect_kind=e.effect_kind
                   AND et.completed_at IS NULL
            ),'[]'::jsonb)
        )
          FROM identity_transition_effects e
          JOIN identity_transitions t ON t.id=e.transition_id
         WHERE e.transition_id=v_effect.transition_id
           AND e.effect_kind=v_effect.effect_kind
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_effect_claim(text,integer)'::regprocedure
);
