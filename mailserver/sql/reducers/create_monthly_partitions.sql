-- create_monthly_partitions(p_months_ahead): ensure monthly range partitions
-- exist (offsets 0..p_months_ahead from the current month) for EVERY
-- month-partitioned table, derived from the catalog — no hand list to drift.
--
-- Covered set = every RANGE-partitioned parent in `public` whose partition key
-- is a single timestamptz column (pg_partitioned_table ⋈ pg_attribute). Today:
-- messages, message_trace, message_tags, mailbox_audit_log, audit_log,
-- auth_attempts, login_events — and any future such table automatically.
-- Expression keys / non-time keys are excluded by the predicate (we can't
-- derive `<table>_YYYY_MM` bounds for them).
--
-- WHY (c11-bug, now c11 structural): the cron's previous monthly tasks called
-- rotators that no longer existed post-ARCH-007, and the audit trio
-- (audit_log / auth_attempts / login_events) has NO DEFAULT partition, so on a
-- gateway running past the month boundary without a restart the insert
-- hard-fails ("no partition of relation … found for row") and audit +
-- auth-attempt logging silently dies. ONE owner now: boot calls
-- create_monthly_partitions(1) on the owner pool (current+next, owner-owned
-- partitions); the cron monthly task calls the same. DDL requires parent-table
-- ownership — native-RLS W4 moves the cron call to DB_OWNER_DSN.
DROP FUNCTION IF EXISTS create_monthly_partitions();  -- pre-c11 zero-arg overload; kept would make no-arg calls ambiguous
CREATE OR REPLACE FUNCTION create_monthly_partitions(p_months_ahead INT DEFAULT 1) RETURNS void AS $$
DECLARE
  v_tbl    TEXT;
  v_offset INT;
  v_start  DATE;
  v_end    DATE;
  v_name   TEXT;
BEGIN
  FOR v_tbl IN
    SELECT c.relname
    FROM pg_partitioned_table p
    JOIN pg_class     c ON c.oid = p.partrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
    WHERE n.nspname = 'public'
      AND p.partstrat = 'r'                       -- RANGE only
      AND p.partnatts = 1                         -- single-column key (excludes expression keys: attnum 0 never joins)
      AND a.atttypid = 'timestamptz'::regtype     -- month-partitioned by time
    ORDER BY c.relname
  LOOP
    FOR v_offset IN 0..p_months_ahead LOOP
      v_start := date_trunc('month', now() + make_interval(months => v_offset))::DATE;
      v_end   := (v_start + INTERVAL '1 month')::DATE;
      v_name  := v_tbl || '_' || to_char(v_start, 'YYYY_MM');
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
        -- Per-table isolation: one table's failure must NOT abort the rest —
        -- the audit trio (no DEFAULT partition) is the safety-critical set.
        -- Known conflict: a table WITH a default partition already holding
        -- rows for the target month (e.g. future-dated scheduled/snoozed
        -- message_tags) raises 23514 on CREATE PARTITION — Postgres validates
        -- but does not move rows. Inserts still work via the default; only
        -- pruning granularity degrades. WARN and continue.
        BEGIN
          EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            v_name, v_tbl, v_start, v_end);
        EXCEPTION WHEN OTHERS THEN
          RAISE WARNING 'create_monthly_partitions: % skipped (%: %)', v_name, SQLSTATE, SQLERRM;
        END;
      END IF;
    END LOOP;
  END LOOP;
END;
$$ LANGUAGE plpgsql;
