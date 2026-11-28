-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V066: Enable pg_stat_statements for PostgreSQL query observability.
-- Tracks query execution stats per normalized query: calls, mean_time,
-- total_time, rows, shared block hits/reads, WAL records.
-- Low overhead (<1% CPU with default track=top). Consumer: /admin/system slow-queries page is pending implementation.

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
