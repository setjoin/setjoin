-- identity_transition_admission_allowed is the single database-owned fence
-- consulted before minting a new authenticated session or Meet grant.
--
-- A directory transition commits authority and revokes database sessions in
-- one transaction, but LiveKit eviction converges asynchronously. Until every
-- mandatory session/SFU effect in the active forward/rollback journey is
-- completed (or explicitly disposed), issuing another token could recreate
-- exactly the stale access the worker is trying to remove.
--
-- Subscriber notice is deliberately not an admission fence. It remains
-- visible and exactly retryable as an operator warning, but it cannot prevent
-- the person from signing in after the security effects have converged.
CREATE OR REPLACE FUNCTION identity_transition_admission_allowed(
    p_user_id BIGINT
) RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT p_user_id IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
             FROM identity_transitions t
             JOIN identity_transition_effects e
               ON e.transition_id=t.id
            WHERE t.user_id=p_user_id
              AND t.committed_at IS NOT NULL
              AND t.state IN (
                  'authority_committed','effects_pending',
                  'failed_recoverable','rollback_previewed','rolling_back'
              )
              AND e.effect_kind IN (
                  'auth_sessions','livekit_sessions',
                  'rollback_auth_sessions','rollback_livekit_sessions'
              )
              AND e.state NOT IN ('completed','disposed')
       );
$$;
SELECT apply_worker_ownership(
    'identity_transition_admission_allowed(bigint)'::regprocedure
);
