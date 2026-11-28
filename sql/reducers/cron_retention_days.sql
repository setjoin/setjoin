-- cron_retention_days.sql: shared retention-window resolver for the no-argument
-- cron prune sweeps (prune_dmarc_reports, prune_spam, prune_greylist_entries,
-- prune_health_history, prune_vacation_replies, purge_expired_tokens,
-- purge_saml_assertions). Reads the optional system_config day count for
-- p_key, falls back to p_default when the key is absent or blank, and REFUSES
-- (BZ040) any zero, negative or non-integer stored value so a bad config key
-- can never turn a retention sweep into a mass delete (destructive-parameter
-- clamping, CWE-20). Refusing — instead of clamping silently — means the
-- nightly task fails loudly on every run until the operator fixes the value.
--
-- BZ040 reuse note: the cron prune paths are not HTTP-facing reducers (the Go
-- cron worker only logs the raised error), and BZ040's registered slug
-- (`invalidArguments`) is the registry's generic invalid-argument code, so
-- reusing it needs no reducererr contract change.
CREATE OR REPLACE FUNCTION cron_retention_days(p_key text, p_default int) RETURNS integer AS $$
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
