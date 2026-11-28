-- prune_health_history.sql: daily cron sweep for the health_history telemetry
-- ring (registered task prune-health-history). Deletes check results older
-- than the retention window; current health state lives in the live check
-- path, not in this history. The window comes from the optional system_config
-- key health_history_retain_days (default 90) and is resolved through
-- cron_retention_days so zero/negative/invalid stored values are refused
-- (BZ040) instead of mass-deleting the table.
-- Returns the number of history rows deleted.
CREATE OR REPLACE FUNCTION prune_health_history() RETURNS bigint AS $$
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
