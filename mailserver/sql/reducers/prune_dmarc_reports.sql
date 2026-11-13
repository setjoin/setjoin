-- prune_dmarc_reports.sql: daily cron sweep for aggregate DMARC reports
-- (registered task prune-dmarc-reports). Deletes reports whose reporting
-- period (end_time) is older than the retention window. The window comes from
-- the optional system_config key dmarc_reports_retain_days (default 90) and is
-- resolved through cron_retention_days so zero/negative/invalid stored values
-- are refused (BZ040) instead of mass-deleting the table.
-- Returns the number of reports deleted.
CREATE OR REPLACE FUNCTION prune_dmarc_reports() RETURNS bigint AS $$
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
