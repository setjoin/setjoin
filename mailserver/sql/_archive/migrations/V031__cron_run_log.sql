-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V031: cron_run_log table for Go cron worker observability
CREATE UNLOGGED TABLE IF NOT EXISTS cron_run_log (
    id BIGSERIAL PRIMARY KEY,
    task_name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms INTEGER,
    status TEXT NOT NULL CHECK (status IN ('success', 'error', 'panic', 'timeout')),
    error_message TEXT,
    sql_text TEXT
);

CREATE INDEX IF NOT EXISTS idx_cron_run_log_task ON cron_run_log (task_name, started_at DESC);

-- Register cleanup via existing prune_log_tables mechanism (appends to the function)
