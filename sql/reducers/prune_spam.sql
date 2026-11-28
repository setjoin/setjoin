-- prune_spam.sql: daily cron sweep for per-user spam models (registered task
-- prune-spam). Deletes user_spam_model rows that have not been retrained
-- within the retention window — a stale model falls back to the global
-- filtering defaults and is rebuilt on the user's next training event
-- (internal/spam upserts on every train). The window comes from the optional
-- system_config key spam_model_retain_days (default 180) and is resolved
-- through cron_retention_days so zero/negative/invalid stored values are
-- refused (BZ040) instead of mass-deleting the table.
--
-- Scoring opt-out (disabled rows) is NEVER pruned: user_spam_model.disabled =
-- TRUE is the durable admin opt-out (admin_spam DisableModel; internal/spam
-- store.go refuses to score or rebuild while the row exists). A MISSING row
-- reads back as a fresh ENABLED model, so deleting an aged disabled row would
-- silently re-enable spam scoring for that user — the prune therefore deletes
-- only enabled (NOT disabled) stale rows.
-- Returns the number of stale models deleted.
CREATE OR REPLACE FUNCTION prune_spam() RETURNS bigint AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('spam_model_retain_days', 180);
    DELETE FROM user_spam_model
     WHERE trained_at < now() - make_interval(days => v_days)
       AND NOT disabled;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
