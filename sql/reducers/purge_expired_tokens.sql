-- purge_expired_tokens.sql: weekly cron purge for expired bearer/refresh/SCIM
-- tokens (registered task purge-expired-tokens). Token rows whose validity
-- has fully lapsed are dead weight and a lingering hash-liability; deleting
-- them changes no live session. Safety properties pinned here:
--   * oauth_tokens / scim_tokens with expires_at IS NULL never expire by
--     design (app passwords, permanent SCIM tokens) and are NEVER touched;
--   * an oidc_tokens row is only purged once BOTH its access expiry and its
--     optional refresh expiry have passed — a refreshable row stays alive;
--   * used_password_reset_tokens is deliberately NOT this function's job: its
--     consumed-hash pruner is owned separately (authserver remediation).
-- The grace window comes from the optional system_config key
-- expired_tokens_retain_days (default 30) and is resolved through
-- cron_retention_days so zero/negative/invalid stored values are refused
-- (BZ040) instead of mass-deleting the tables.
-- Returns the total number of token rows deleted across the three tables.
CREATE OR REPLACE FUNCTION purge_expired_tokens() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_cutoff  timestamptz;
    v_step    bigint;
    v_deleted bigint := 0;
BEGIN
    v_days := cron_retention_days('expired_tokens_retain_days', 30);
    v_cutoff := now() - make_interval(days => v_days);

    -- oauth_tokens (access / refresh / xoauth2 / app_password / authorization_code).
    DELETE FROM oauth_tokens
     WHERE expires_at IS NOT NULL
       AND expires_at < v_cutoff;
    GET DIAGNOSTICS v_step = ROW_COUNT;
    v_deleted := v_deleted + v_step;

    -- oidc_tokens: access expiry alone does not kill the row while its
    -- refresh token could still mint a new access token.
    DELETE FROM oidc_tokens
     WHERE expires_at < v_cutoff
       AND (refresh_expires_at IS NULL OR refresh_expires_at < v_cutoff);
    GET DIAGNOSTICS v_step = ROW_COUNT;
    v_deleted := v_deleted + v_step;

    -- scim_tokens (provisioning tokens; no FK in the way, source_id nullable).
    DELETE FROM scim_tokens
     WHERE expires_at IS NOT NULL
       AND expires_at < v_cutoff;
    GET DIAGNOSTICS v_step = ROW_COUNT;
    v_deleted := v_deleted + v_step;

    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
