-- Hold the exact normalized authentication source+link stable while the
-- authserver stores the new refresh-family anchor. The caller invokes this
-- inside a transaction and keeps that transaction open until token persistence
-- completes. A concurrent detach/retire/generation bump either wins first and
-- makes this fail, or waits and then revokes the newly persisted family.
CREATE OR REPLACE FUNCTION identity_auth_mint_fence(
    p_user_id BIGINT,
    p_source_id BIGINT,
    p_source_generation BIGINT,
    p_link_id BIGINT,
    p_link_generation BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_link user_identity_links%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_source_id IS NULL
       OR p_source_generation IS NULL OR p_source_generation<=0
       OR p_link_id IS NULL OR p_link_generation IS NULL
       OR p_link_generation<=0 THEN
        RAISE EXCEPTION 'invalid normalized identity mint fence'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_link_stale"}';
    END IF;

    -- Serialize the account-state check with disable/detach/transition and keep
    -- the users row locked through refresh-family persistence. If disable wins
    -- first this fails; if mint wins first, disable waits and then revokes the
    -- newly committed family.
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text, 0
    ));
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

    SELECT * INTO v_source
      FROM identity_sources
     WHERE id=p_source_id
     FOR SHARE;
    IF NOT FOUND OR v_source.state<>'active'
       OR v_source.generation<>p_source_generation
       OR v_source.kind NOT IN ('saml','oidc') THEN
        RAISE EXCEPTION 'identity source changed before token mint'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_link_stale","remediation":"restart sign-in against the current source generation"}';
    END IF;

    SELECT * INTO v_link
      FROM user_identity_links
     WHERE id=p_link_id
     FOR SHARE;
    IF NOT FOUND OR v_link.user_id<>p_user_id
       OR v_link.source_id<>p_source_id
       OR v_link.generation<>p_link_generation
       OR v_link.state<>'active'
       OR NOT ('authenticate'=ANY(v_link.purposes)) THEN
        RAISE EXCEPTION 'identity link changed before token mint'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_link_stale","remediation":"restart sign-in; the federated link changed"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership(
    'identity_auth_mint_fence(bigint,bigint,bigint,bigint,bigint)'::regprocedure
);
