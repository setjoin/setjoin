-- m365_consent_state_mint.sql — mint ONE server-side, expiring, single-use M365
-- admin-consent authorization (m365_consent_states, V234) for an authenticated
-- admin and prune the SAME actor's spent/expired rows in the same transaction.
--
-- med-shard2-023 (D-MAILSERVER-INTERNAL-USER-F-002): the consent lifecycle is
-- reducer-authoritative; the gateway (internal/user M365Connect) only
-- orchestrates — it generates the random token and calls this reducer inside
-- dbscope.RunUserScoped so the FORCE-RLS actor GUC admits the row. Ownership is
-- ALSO in every statement (R1/R3, never GUC-only): both the prune and the
-- insert filter/bind actor_user_id = p_actor, so the reducer can never touch
-- another actor's authorizations.
--
-- p_token is the 32-byte random hex token the gateway also puts in the OAuth
-- state; p_ttl_seconds is the consumability window (the gateway uses
-- m365ConsentStateTTL = 10 minutes). Expiry is stamped from the DATABASE clock
-- so app/DB skew cannot extend or shorten the window. Returns the minted
-- expires_at.
CREATE OR REPLACE FUNCTION m365_consent_state_mint(
    p_actor       BIGINT,
    p_token       TEXT,
    p_cloud       TEXT,
    p_ttl_seconds INTEGER
) RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_expires TIMESTAMPTZ;
BEGIN
    IF p_actor IS NULL OR p_actor <= 0 THEN
        RAISE EXCEPTION 'm365_consent_state_mint: p_actor is required'
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_actor"}'::TEXT;
    END IF;
    IF p_token IS NULL OR length(p_token) = 0 THEN
        RAISE EXCEPTION 'm365_consent_state_mint: p_token is required'
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_token"}'::TEXT;
    END IF;
    IF p_cloud IS NULL OR p_cloud NOT IN ('global', 'china') THEN
        RAISE EXCEPTION 'm365_consent_state_mint: p_cloud must be global or china (got %)',
            COALESCE(p_cloud, 'NULL')
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_cloud"}'::TEXT;
    END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 THEN
        RAISE EXCEPTION 'm365_consent_state_mint: p_ttl_seconds must be positive (got %)',
            COALESCE(p_ttl_seconds, -1)
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_ttl_seconds"}'::TEXT;
    END IF;

    -- Prune THIS actor's spent/expired authorizations so abandoned consent
    -- attempts cannot accumulate (never another actor's rows — R1/R3).
    DELETE FROM m365_consent_states
     WHERE actor_user_id = p_actor
       AND (consumed_at IS NOT NULL OR expires_at <= now());

    INSERT INTO m365_consent_states (state_token, actor_user_id, cloud, expires_at)
    VALUES (p_token, p_actor, p_cloud, now() + make_interval(secs => p_ttl_seconds))
    RETURNING expires_at INTO v_expires;

    RETURN v_expires;
END;
$$ LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public;
