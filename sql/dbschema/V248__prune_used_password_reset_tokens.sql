-- V248: consumed-password-reset-token retention sweep — install the reducer
-- function (med-shard3-003, wave 9).
--
-- used_password_reset_tokens is the forgot-password replay-prevention
-- tombstone table: every consumed reset-token JWT hash is inserted there and
-- replay is rejected on PK conflict. The promised retention pruner existed
-- nowhere — the pgTAP coverage executed an inline DELETE itself, so consumed
-- hashes grew unbounded (D-AUTHSERVER-SQL-TESTS-002). purge_expired_tokens
-- (V241) deliberately excludes this table: the consumed-hash pruner is owned
-- by the authserver (see that reducer's contract comment).
--
-- This migration is the deployment install record for the pruner; the LIVE
-- source stays authserver/sql/reducers/prune_used_password_reset_tokens.sql
-- (post-ARCH-007 the fixed-point reducer reload re-applies it on top, so any
-- later logic fix is a reducer edit, never a new migration). The body below
-- is byte-identical to the reducer file at install time. The window default
-- (10 minutes) is 2x the reset-token JWT's 5-minute validity; windows below
-- the validity floor are refused (BZ040) because they would delete
-- tombstones whose JWTs could still replay.
--
-- Registered as Go cron task prune-used-password-reset-tokens
-- (mailserver/internal/cron/tasks.go, the pg_cron replacement — the old
-- cron.job assertion in forgot_password.pg only ever passed via pg_cron
-- absence skips). Startup/test-time validation:
-- mailserver/internal/cron ValidateRegistrations (42883 on drift).
--
-- From authserver/sql/reducers/prune_used_password_reset_tokens.sql
-- (byte-identical body; schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_used_password_reset_tokens(p_older_than interval DEFAULT NULL)
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

INSERT INTO public.schema_migrations (version, applied_at) VALUES (248, now())
  ON CONFLICT (version) DO NOTHING;
