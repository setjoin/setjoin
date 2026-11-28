-- purge_saml_assertions.sql: weekly cron purge for the SAML replay cache
-- (registered task purge-saml-assertions). used_saml_assertions exists to
-- deny replay of an assertion ID while that assertion can still be presented;
-- assertions are valid for minutes, so a row older than the retention window
-- is far past any NotOnOrAfter lifetime and its replay guard is dead weight.
-- The default window (30 days) is deliberately orders of magnitude beyond any
-- real assertion lifetime — never set it below the longest IdP assertion
-- validity. The window comes from the optional system_config key
-- saml_assertions_retain_days and is resolved through cron_retention_days so
-- zero/negative/invalid stored values are refused (BZ040) instead of
-- mass-deleting the cache.
-- Returns the number of cached assertion IDs deleted.
CREATE OR REPLACE FUNCTION purge_saml_assertions() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('saml_assertions_retain_days', 30);
    DELETE FROM used_saml_assertions
     WHERE used_at < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
