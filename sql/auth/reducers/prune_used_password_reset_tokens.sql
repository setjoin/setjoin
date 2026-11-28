-- prune_used_password_reset_tokens: retention sweep for the consumed
-- forgot-password reset-token tombstones in used_password_reset_tokens.
-- Each tombstone exists for replay prevention only and must outlive the
-- reset-token JWT's 5-minute validity (authserver/internal/token/jwt.go,
-- IssuePasswordReset); past that window the lingering hash is pure
-- liability — unbounded growth of consumed hashes into the live table and
-- every backup. Before this reducer the promised pruner existed nowhere:
-- the pgTAP coverage executed an inline DELETE itself (false-green,
-- D-AUTHSERVER-SQL-TESTS-002). The live registration is the Go cron task
-- prune-used-password-reset-tokens (mailserver/internal/cron/tasks.go, the
-- pg_cron replacement); used_password_reset_tokens is deliberately NOT
-- purge_expired_tokens' job (see that reducer's contract comment).
--
-- Retention window: p_older_than, NULL (the default) resolves to the
-- built-in 10 minutes — 2x the JWT validity, the window the superseded
-- inline-DELETE test pinned. Any explicit window below the 5-minute token
-- validity is REFUSED (BZ040, the cron-prune family's generic
-- invalidArguments code, same reuse rationale as cron_retention_days):
-- a shorter window would delete tombstones whose JWTs could still replay.
CREATE OR REPLACE FUNCTION prune_used_password_reset_tokens(p_older_than interval DEFAULT NULL)
RETURNS bigint AS $$
DECLARE
    v_window  interval;
    v_deleted bigint;
BEGIN
    v_window := COALESCE(p_older_than, interval '10 minutes');
    IF v_window < interval '5 minutes' THEN
        RAISE EXCEPTION 'prune_used_password_reset_tokens: p_older_than must be at least the 5-minute reset-token validity (got %)',
            v_window
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_older_than"}'::TEXT;
    END IF;

    DELETE FROM used_password_reset_tokens
     WHERE created_at < now() - v_window;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
