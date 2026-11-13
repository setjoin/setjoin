-- V241: cron retention sweeps — install the eight reducer functions
-- (med-shard3-010, Astra wave6/7 HOLD).
--
-- The cron prune registry's sweeps used to 42883 on every nightly run (the
-- functions did not exist in any migration). This migration is the deployment
-- install record for them: the LIVE source stays reducers/*.sql (post-ARCH-007
-- the fixed-point reducer reload re-applies it on top, so any later logic fix
-- is a reducer edit, never a new migration — this file keeps only the original
-- CREATEs, mirroring how V222/V227/V232 registered their reducer-owned
-- functions). The bodies below are byte-identical to the reducer files at
-- install time, including the Astra-review fix: prune_spam never deletes a
-- disabled (scoring-opted-out) user_spam_model row, because a missing row
-- reads back as a fresh ENABLED model — deleting aged disabled rows would
-- silently re-enable spam scoring.
--
-- Installed functions (helper first — the sweeps call it in the same file):
--
--   cron_retention_days(p_key text, p_default int) — STABLE shared
--       retention-window resolver: system_config key → default when
--       absent/blank; REFUSES (BZ040) zero/negative/non-integer values so a
--       bad key can never turn a sweep into a mass delete.
--   prune_dmarc_reports()       — dmarc_reports past the window
--                                 (dmarc_reports_retain_days, default 90)
--   prune_spam()                — user_spam_model not retrained in-window
--                                 (spam_model_retain_days, default 180;
--                                 disabled rows are NEVER pruned)
--   prune_greylist_entries()    — greylist triplets unseen in-window
--                                 (greylist_retain_days, default 7;
--                                 whitelisted never age-pruned)
--   prune_health_history()      — health_history past the window
--                                 (health_history_retain_days, default 90)
--   prune_vacation_replies()    — vacation_replies ledger past the window
--                                 (vacation_replies_retain_days, default 30)
--   purge_expired_tokens()      — fully-lapsed oauth/oidc/scim tokens
--                                 (expired_tokens_retain_days, default 30;
--                                 NULL expiry never touched)
--   purge_saml_assertions()     — used_saml_assertions replay cache
--                                 (saml_assertions_retain_days, default 30)
--
-- No schema objects: the sweeps touch only pre-existing tables — there is
-- nothing here for the schema-truth determinism guard to diff beyond the
-- functions themselves.
--
-- BZ040 reuse note: the cron prune paths are not HTTP-facing reducers (the Go
-- cron worker only logs the raised error), and BZ040's registered slug
-- (`invalidArguments`) is the registry's generic invalid-argument code, so
-- reusing it needs no reducererr contract change.

-- From reducers/cron_retention_days.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.cron_retention_days(p_key text, p_default int) RETURNS integer AS $$
DECLARE
    v_raw  text;
    v_days int;
BEGIN
    -- A sweep wired with a non-positive built-in default is a programming
    -- error, not a runtime condition: refuse it too.
    IF p_default IS NULL OR p_default <= 0 THEN
        RAISE EXCEPTION 'cron_retention_days: built-in default for % must be a positive day count (got %)',
            p_key, COALESCE(p_default, -1)
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_default"}'::TEXT;
    END IF;

    SELECT value #>> '{}' INTO v_raw FROM system_config WHERE key = p_key;
    IF v_raw IS NULL OR btrim(v_raw) = '' THEN
        RETURN p_default;
    END IF;

    BEGIN
        v_days := btrim(v_raw)::int;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION 'cron retention key % holds a non-integer day count (%)', p_key, v_raw
                USING ERRCODE = 'BZ040',
                HINT = '{"type":"invalidArguments","param":"retention_days"}'::TEXT;
    END;

    IF v_days <= 0 THEN
        RAISE EXCEPTION 'cron retention key % must hold a positive day count (got %)', p_key, v_days
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"retention_days"}'::TEXT;
    END IF;
    RETURN v_days;
END;
$$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public;

-- From reducers/prune_dmarc_reports.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_dmarc_reports() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('dmarc_reports_retain_days', 90);
    DELETE FROM dmarc_reports
     WHERE end_time < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- From reducers/prune_spam.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_spam() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('spam_model_retain_days', 180);
    DELETE FROM user_spam_model
     WHERE trained_at < now() - make_interval(days => v_days)
       AND NOT disabled;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- From reducers/prune_greylist_entries.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_greylist_entries() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('greylist_retain_days', 7);
    DELETE FROM greylist
     WHERE whitelisted = FALSE
       AND last_seen < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- From reducers/prune_health_history.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_health_history() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('health_history_retain_days', 90);
    DELETE FROM health_history
     WHERE checked_at < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- From reducers/prune_vacation_replies.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_vacation_replies() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('vacation_replies_retain_days', 30);
    DELETE FROM vacation_replies
     WHERE replied_at < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- From reducers/purge_expired_tokens.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.purge_expired_tokens() RETURNS bigint AS $$
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

-- From reducers/purge_saml_assertions.sql (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.purge_saml_assertions() RETURNS bigint AS $$
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

INSERT INTO public.schema_migrations (version, applied_at) VALUES (241, now())
  ON CONFLICT (version) DO NOTHING;
