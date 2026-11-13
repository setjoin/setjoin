-- prune_greylist_entries.sql: daily cron sweep for expired greylisting
-- triplets (registered task prune-greylist). A triplet unseen for the
-- retention window is simply re-greylisted on its next attempt, so pruning is
-- lossless. WHITELISTED triplets are never pruned by age — explicit trust
-- must not silently decay. The window comes from the optional system_config
-- key greylist_retain_days (default 7) and is resolved through
-- cron_retention_days so zero/negative/invalid stored values are refused
-- (BZ040) instead of mass-deleting the table.
-- Returns the number of entries deleted.
CREATE OR REPLACE FUNCTION prune_greylist_entries() RETURNS bigint AS $$
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
