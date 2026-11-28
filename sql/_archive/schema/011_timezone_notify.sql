-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 011_timezone_notify.sql — LISTEN/NOTIFY invalidation for CalDAV timezone cache.
-- Fires pg_notify('timezone_changed', ...) whenever vt_timezone is modified,
-- enabling the Go gateway to reload its in-memory timezone cache without polling.
CREATE OR REPLACE FUNCTION notify_timezone_changed()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify(
        'timezone_changed',
        json_build_object(
            'tzid', COALESCE(NEW.tzid, OLD.tzid),
            'op',   TG_OP
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS timezone_change_trigger ON vt_timezone;
CREATE TRIGGER timezone_change_trigger
    AFTER INSERT OR UPDATE OR DELETE ON vt_timezone
    FOR EACH ROW
    EXECUTE FUNCTION notify_timezone_changed();
