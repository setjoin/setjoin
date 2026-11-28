-- identity_auth_person_fence is the lock-only primitive shared by credential
-- changes, refresh rotation, complete revocation, and full mint validation.
-- It deliberately does not require users.enabled: a disabled principal's
-- refresh request still needs this lock so it can revoke every durable token
-- anchor before failing closed.
CREATE OR REPLACE FUNCTION identity_auth_person_fence(
    p_user_id BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'invalid identity mint principal'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text, 0
    ));
END;
$$;

-- Serialize every non-federated first-party session mint with identity
-- transition execution/rollback. The caller keeps its transaction open until
-- the oauth_tokens family anchor is inserted.
--
-- Whichever transaction wins the per-person advisory lock determines the safe
-- order: an already-committed transition fails this recheck, while a transition
-- that starts later waits and then revokes the newly committed family.
CREATE OR REPLACE FUNCTION identity_auth_local_mint_fence(
    p_user_id BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    PERFORM 1
      FROM users
     WHERE id=p_user_id
       AND enabled
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity mint principal is unavailable'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;

    IF NOT identity_transition_admission_allowed(p_user_id) THEN
        RAISE EXCEPTION 'identity transition security effects are unfinished'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_transition_in_progress","remediation":"wait for mandatory authentication and media revocation effects to converge"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership(
    'identity_auth_person_fence(bigint)'::regprocedure
);
SELECT apply_worker_ownership(
    'identity_auth_local_mint_fence(bigint)'::regprocedure
);
