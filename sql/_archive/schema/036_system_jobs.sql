-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 036_system_jobs.sql: Admin system job tracking (backups, restarts, upgrades).
CREATE TABLE IF NOT EXISTS system_jobs (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    job_type    TEXT NOT NULL CHECK (job_type IN ('backup','restart')),
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','complete','failed')),
    result_path TEXT,
    size_bytes  BIGINT,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS system_jobs_type_idx ON system_jobs(job_type, created_at DESC);
