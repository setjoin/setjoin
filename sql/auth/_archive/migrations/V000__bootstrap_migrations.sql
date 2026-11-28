-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V000: Bootstrap schema_migrations table for tracking applied migrations.
-- TRIAGE FENCE (D-AUTHSERVER-SQL--ARCHIVE-007, 2026-09): the INSERT below
-- forges schema_migrations version 8. On an unbaselined database it would
-- silently mark migration 8 as applied and skip it; nothing in the repo loads
-- archived migrations (verified at triage) and replay on a baselined database
-- is a no-op via ON CONFLICT — but NEVER load this file by hand or wire it
-- into any migration runner: migration-state writes belong exclusively to the
-- live collapse baseline (ARCH-007) and its migration tooling.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES (8) ON CONFLICT (version) DO NOTHING;
