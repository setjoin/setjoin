CREATE OR REPLACE FUNCTION identity_transition_state_allowed(
    p_from TEXT,
    p_to TEXT
) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE p_from
        WHEN 'draft' THEN p_to IN ('previewed','cancelled','expired')
        WHEN 'previewed' THEN p_to IN (
            'awaiting_approval','authorized','cancelled','expired'
        )
        WHEN 'awaiting_approval' THEN p_to IN (
            'authorized','previewed','cancelled','expired'
        )
        WHEN 'authorized' THEN p_to IN (
            'executing','previewed','cancelled','expired'
        )
        WHEN 'executing' THEN p_to IN (
            'authority_committed','failed_precommit'
        )
        WHEN 'authority_committed' THEN p_to IN (
            'effects_pending','completed'
        )
        WHEN 'effects_pending' THEN p_to IN (
            'completed','failed_recoverable'
        )
        WHEN 'failed_precommit' THEN p_to IN ('previewed','cancelled')
        WHEN 'failed_recoverable' THEN p_to IN (
            'effects_pending','rollback_previewed','rolling_back'
        )
        WHEN 'rollback_previewed' THEN p_to IN (
            'rolling_back','failed_recoverable','expired'
        )
        WHEN 'rolling_back' THEN p_to IN (
            'rolled_back','failed_recoverable'
        )
        ELSE false
    END
$$;
SELECT apply_worker_ownership(
    'identity_transition_state_allowed(text,text)'::regprocedure
);
