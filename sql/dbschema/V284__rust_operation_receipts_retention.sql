-- V284: bounded retention purge and privilege hardening for rust_operation_receipts (#473).
--
-- V276 created public.rust_operation_receipts without a retention sweep or an
-- index on committed_at, and scripts/provision-roles.sql's blanket table GRANT
-- inadvertently re-widened UPDATE/DELETE on setjoin_app. This migration:
--   1. Indexes committed_at for bounded oldest-first pruning.
--   2. Narrows table privileges: revokes PUBLIC, limits setjoin_app to
--      SELECT/INSERT, and grants setjoin_worker SELECT/INSERT/DELETE.
--   3. Installs public.prune_rust_operation_receipts(integer DEFAULT 5000)
--      (SECURITY INVOKER, worker-only EXECUTE) backed by
--      cron_retention_days('rust_operation_receipts_retain_days', 30).
--
-- Reducer-source discipline (V241/V261 precedent): the live source stays
-- mailserver/sql/reducers/prune_rust_operation_receipts.sql; this file keeps
-- the byte-identical function body for forward upgrades via `mailctl schema apply`.

CREATE INDEX IF NOT EXISTS idx_rust_operation_receipts_committed_at
    ON public.rust_operation_receipts (committed_at);

REVOKE ALL ON public.rust_operation_receipts FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON public.rust_operation_receipts FROM setjoin_app;
        GRANT SELECT, INSERT ON public.rust_operation_receipts TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        REVOKE ALL ON public.rust_operation_receipts FROM setjoin_worker;
        GRANT SELECT, INSERT, DELETE ON public.rust_operation_receipts TO setjoin_worker;
    END IF;
END $$;

-- From reducers/prune_rust_operation_receipts.sql (byte-identical body;
-- schema-qualified name):
CREATE OR REPLACE FUNCTION public.prune_rust_operation_receipts(p_batch_size integer DEFAULT 5000) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_days    integer;
    v_cutoff  timestamptz;
    v_deleted bigint;
BEGIN
    IF p_batch_size IS NULL OR p_batch_size < 1 OR p_batch_size > 50000 THEN
        RAISE EXCEPTION 'prune_rust_operation_receipts: p_batch_size must be between 1 and 50000 (got %)',
            COALESCE(p_batch_size::text, 'NULL')
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_batch_size"}'::TEXT;
    END IF;

    v_days := cron_retention_days('rust_operation_receipts_retain_days', 30);
    v_cutoff := now() - make_interval(days => v_days);

    WITH victims AS (
        SELECT operation_id
          FROM public.rust_operation_receipts
         WHERE committed_at < v_cutoff
         ORDER BY committed_at, operation_id
         LIMIT p_batch_size
    ), deleted AS (
        DELETE FROM public.rust_operation_receipts r
         USING victims v
         WHERE r.operation_id = v.operation_id
         RETURNING 1
    )
    SELECT count(*)::bigint INTO v_deleted FROM deleted;

    RETURN v_deleted;
END;
$$;

COMMENT ON FUNCTION public.prune_rust_operation_receipts(integer) IS
  'Bounded oldest-first retention sweep for public.rust_operation_receipts (#473): '
  'deletes up to p_batch_size (1..=50000, default 5000) rows older than '
  'system_config rust_operation_receipts_retain_days (default 30, BZ040 refusal of '
  'zero/negative/non-integer). SECURITY INVOKER; worker-only EXECUTE and table DELETE '
  '(setjoin_app denied EXECUTE and retains only SELECT/INSERT).';

REVOKE ALL ON FUNCTION public.prune_rust_operation_receipts(integer) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON FUNCTION public.prune_rust_operation_receipts(integer) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.prune_rust_operation_receipts(integer) TO setjoin_worker;
    END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (284, now()) ON CONFLICT (version) DO NOTHING;
