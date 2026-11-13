-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V000: Bootstrap schema_migrations table for tracking applied migrations.
-- Must run before any other migration. All subsequent Vxxx migrations
-- should INSERT their version into this table at the end.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backfill: record all existing migrations as applied.
-- Bump this number when adding new migrations.
INSERT INTO schema_migrations (version) VALUES
    (65)  -- total current migration count
ON CONFLICT (version) DO NOTHING;
