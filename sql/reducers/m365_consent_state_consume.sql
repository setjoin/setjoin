-- m365_consent_state_consume.sql — guarded single-use consumption of a server-
-- side M365 admin-consent authorization (m365_consent_states, V234).
--
-- med-shard2-023 (D-MAILSERVER-INTERNAL-USER-F-002): the callback's consent
-- authorization check is reducer-authoritative. The gateway (internal/user
-- M365Callback) calls this reducer inside dbscope.RunUserScoped BEFORE any
-- verification or config write; a BZ002 here means the state is fabricated,
-- replayed, expired, or bound to a different admin.
--
-- EXACTLY-ONE-WINNER: the consumption is ONE atomic UPDATE whose predicate
-- (state_token + actor_user_id + unconsumed + unexpired) is re-evaluated
-- against the current row version for every concurrent claimant — the first
-- commit wins and sets consumed_at; every other concurrent caller matches no
-- row and raises BZ002. Replay after a winner is likewise dead (consumed_at IS
-- NOT NULL). Ownership is in the statement (R1/R3, never GUC-only).
--
-- Returns the consented cloud ('global'|'china') that the mint stored, so the
-- gateway persists exactly the cloud the authorization was issued for.
CREATE OR REPLACE FUNCTION m365_consent_state_consume(
    p_actor BIGINT,
    p_token TEXT
) RETURNS TEXT AS $$
DECLARE
    v_cloud TEXT;
BEGIN
    IF p_actor IS NULL OR p_actor <= 0 OR p_token IS NULL OR length(p_token) = 0 THEN
        RAISE EXCEPTION 'm365_consent_state_consume: actor and token are required'
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments"}'::TEXT;
    END IF;

    UPDATE m365_consent_states
       SET consumed_at = now()
     WHERE state_token = p_token
       AND actor_user_id = p_actor
       AND consumed_at IS NULL
       AND expires_at > now()
    RETURNING cloud INTO v_cloud;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'm365_consent_state_consume: no unconsumed, unexpired consent authorization for this actor and token'
            USING ERRCODE = 'BZ002',
            HINT = '{"type":"forbidden"}'::TEXT;
    END IF;

    RETURN v_cloud;
END;
$$ LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public;
