-- prune_vacation_replies.sql: daily cron sweep for the vacation auto-reply
-- dedup ledger (registered task prune-vacation-replies). One reply is sent
-- per (sender, mailbox, vacation_start); once a vacation window has been over
-- for the retention period its rows can never match an active vacation again,
-- so pruning is lossless. The window comes from the optional system_config
-- key vacation_replies_retain_days (default 30) and is resolved through
-- cron_retention_days so zero/negative/invalid stored values are refused
-- (BZ040) instead of mass-deleting the table.
-- Returns the number of ledger rows deleted.
CREATE OR REPLACE FUNCTION prune_vacation_replies() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('vacation_replies_retain_days', 30);
    DELETE FROM vacation_replies
     WHERE replied_at < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
