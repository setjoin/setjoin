-- Reducer: login_events_prune — drop whole login_events partitions older than the
-- retention window. Run by setjoin_worker on DB_WORKER_DSN (BYPASSRLS).
-- SECURITY DEFINER so DROP TABLE succeeds even when DB_WORKER_DSN is not yet split
-- and the caller is the regular pool user (mirrors ca_signin_log_prune pattern).
-- Returns the number of partitions dropped.
-- ponytail: whole-partition DROP (not row-level DELETE) — zero bloat, instant;
--           ceiling = only monthly granularity; upgrade path = row-level prune if
--           sub-month retention ever needed.
-- med-shard3-010: destructive-parameter guard (CWE-20) — zero, negative or NULL
-- day counts are REFUSED (BZ040, generic invalidArguments slug) before any
-- catalog scan, so a bad system_config value (the cron task SQL reads
-- login_events_retain_days unclamped) can never mass-drop partitions; a refused
-- call drops nothing. Partition targeting is unchanged: only whole partitions
-- whose month fully ends before the cutoff are dropped, in-window partitions
-- are never touched.
CREATE OR REPLACE FUNCTION login_events_prune(p_retain_days integer)
RETURNS bigint AS $$
DECLARE
    v_cutoff  date;
    v_part    record;
    v_dropped bigint := 0;
BEGIN
    IF p_retain_days IS NULL OR p_retain_days <= 0 THEN
        RAISE EXCEPTION 'login_events_prune: p_retain_days must be a positive day count (got %)',
            COALESCE(p_retain_days, -1)
            USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","param":"p_retain_days"}'::TEXT;
    END IF;

    v_cutoff := (date_trunc('month', now()) - make_interval(days => p_retain_days))::date;

    FOR v_part IN
        SELECT c.relname,
               to_date(substr(c.relname, 14), 'YYYY_MM') AS part_month
        FROM pg_inherits i
        JOIN pg_class c      ON c.oid = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE parent.relname = 'login_events'
          AND c.relname ~ '^login_events_[0-9]{4}_[0-9]{2}$'
    LOOP
        -- Drop partition when its entire month ends before the cutoff
        -- (i.e., month + 1 month <= cutoff means all rows are outside the window).
        IF (v_part.part_month + interval '1 month')::date <= v_cutoff THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', v_part.relname);
            v_dropped := v_dropped + 1;
        END IF;
    END LOOP;
    RETURN v_dropped;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
