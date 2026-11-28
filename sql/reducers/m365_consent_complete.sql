-- m365_consent_complete.sql — the consent-completion mutation: persist the
-- verified M365 tenant binding into system_config AND write the
-- m365_consent_completed audit row in ONE transaction — either both land or
-- neither does.
--
-- med-shard2-023 (D-MAILSERVER-INTERNAL-USER-F-002): the config-plus-audit
-- mutation is reducer-authoritative; the gateway (internal/user M365Callback)
-- runs it AFTER the verifyM365Tenant seam succeeds (verify-before-persist is
-- preserved: the two short transactions bracket the verification, and a failed
-- verification persists nothing — the consumed state stays spent).
--
-- The key is hard-coded to 'm365.app' and the action to 'm365_consent_completed'
-- so this reducer cannot be repurposed to write arbitrary config keys with an
-- audit veneer. p_config_value is the encrypted-wrapper JSON the gateway
-- marshals; the ::jsonb cast (system_config.value is jsonb) fails the whole
-- completion on malformed JSON. p_tier flows from the gateway's
-- audit.TierForPerm (single source of truth for sensitivity) and is validated
-- by audit_write itself (BZ067). Audit goes through the audit_write choke
-- point — never a raw INSERT.
CREATE OR REPLACE FUNCTION m365_consent_complete(
    p_actor        BIGINT,
    p_config_value TEXT,
    p_notes        TEXT,
    p_tier         TEXT
) RETURNS VOID AS $$
BEGIN
    IF p_actor IS NULL OR p_actor <= 0 THEN
        RAISE EXCEPTION 'm365_consent_complete: p_actor is required'
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_actor"}'::TEXT;
    END IF;
    IF p_config_value IS NULL OR length(p_config_value) = 0 THEN
        RAISE EXCEPTION 'm365_consent_complete: p_config_value is required'
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_config_value"}'::TEXT;
    END IF;

    UPDATE system_config
       SET value = p_config_value::jsonb, encrypted = TRUE, updated_at = now()
     WHERE key = 'm365.app';

    PERFORM audit_write(p_actor, 'm365_consent_completed', 'system_config', NULL,
                        NULL, NULL, NULL, p_notes, p_tier);
END;
$$ LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public;
