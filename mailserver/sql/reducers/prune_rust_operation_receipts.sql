-- prune_rust_operation_receipts.sql: bounded oldest-first retention sweep for
-- public.rust_operation_receipts (V276/V284, #473).
--
-- Deletes up to p_batch_size (1..=50000, default 5000) expired rows whose
-- committed_at left the retention window resolved by
-- cron_retention_days('rust_operation_receipts_retain_days', 30). Invalid
-- batch sizes or zero/negative/non-integer config values raise BZ040 before
-- touching any row. Uses primary key operation_id (portable across Xinchuang
-- PG engines) with ORDER BY committed_at, operation_id LIMIT p_batch_size
-- (omitting FOR UPDATE SKIP LOCKED because PostgreSQL requires table UPDATE
-- privilege for row-locking SELECT clauses, while rust_operation_receipts is
-- intentionally append/delete-only with NO UPDATE on setjoin_worker; the cron
-- task is serialized by cron-task:prune-rust-operation-receipts).
--
-- Caller posture: SECURITY INVOKER with worker-only EXECUTE (setjoin_app
-- retains only SELECT/INSERT on rust_operation_receipts and has no EXECUTE on
-- this function; scripts/provision-roles.sql restates both restrictions after
-- its blanket GRANTs).
CREATE OR REPLACE FUNCTION prune_rust_operation_receipts(p_batch_size integer DEFAULT 5000) RETURNS bigint
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
