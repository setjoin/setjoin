-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V067: Create drain_outbound_hot() — drains the unlogged hot queue into the
-- logged outbound_queue table. Replaces the inline pg_cron job that was moved
-- to the Go cron worker in Phase 37.
CREATE OR REPLACE FUNCTION drain_outbound_hot() RETURNS VOID AS $$
BEGIN
    WITH drained AS (
        DELETE FROM outbound_queue_hot
        RETURNING *
    )
    INSERT INTO outbound_queue
    SELECT * FROM drained
    ON CONFLICT (id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

INSERT INTO schema_migrations (version) VALUES (67) ON CONFLICT (version) DO NOTHING;
