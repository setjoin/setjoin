-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V032: Upgrade history + auto-update config for the Go hot upgrade system
CREATE TABLE IF NOT EXISTS upgrade_history (
    id BIGSERIAL PRIMARY KEY,
    from_version TEXT NOT NULL,
    to_version TEXT NOT NULL,
    binary_sha256 TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL CHECK (mode IN ('hot_reload', 'full_restart')),
    ddl_classification TEXT NOT NULL CHECK (ddl_classification IN ('additive_only', 'has_breaking')),
    breaking_changes JSONB DEFAULT '[]',
    new_migrations TEXT[] DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'rolled_back')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    downtime_ms INTEGER DEFAULT 0,
    error_message TEXT,
    previous_binary_path TEXT
);

CREATE INDEX IF NOT EXISTS idx_upgrade_history_started ON upgrade_history (started_at DESC);

INSERT INTO system_config (key, value) VALUES
    ('auto_update.enabled', 'false'),
    ('auto_update.channel', '"stable"'),
    ('auto_update.check_interval', '"daily"'),
    ('auto_update.source_path', '"/opt/mailserver/releases"'),
    ('auto_update.auto_apply_safe', 'false'),
    ('auto_update.notify_admin', 'true'),
    ('auto_update.require_confirm_breaking', 'true')
ON CONFLICT (key) DO NOTHING;

INSERT INTO system_config (key, value) VALUES
    ('maintenance_window.mode', '"manual"'),
    ('maintenance_window.day_of_week', '"sunday"'),
    ('maintenance_window.start_time', '"03:00"'),
    ('maintenance_window.end_time', '"05:00"'),
    ('maintenance_window.timezone', '"UTC"'),
    ('maintenance_window.max_connections', '5'),
    ('maintenance_window.idle_duration', '"10m"'),
    ('maintenance_window.max_wait', '"2h"')
ON CONFLICT (key) DO NOTHING;
