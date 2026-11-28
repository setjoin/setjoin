-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V055__missing_indexes.sql
-- Adds missing indexes identified in audit: auth_event_log lookups,
-- event_attendees dedup, and identity_sync_log dashboard queries.

-- ============================================================================
-- 2a — auth_event_log indexes for spray detection and threat dashboard
-- ============================================================================

-- Index for lookup by email (non-authenticated login-failure queries, threat dashboard)
CREATE INDEX IF NOT EXISTS auth_event_log_email_idx ON auth_event_log(email)
  WHERE email IS NOT NULL;

-- Index for IP-based threat scans (spray detection, tarpit, geo queries)
CREATE INDEX IF NOT EXISTS auth_event_log_ip_idx ON auth_event_log(ip_address)
  WHERE ip_address IS NOT NULL;

-- ============================================================================
-- 2b — event_attendees case-insensitive unique constraint
-- ============================================================================

-- Prevent duplicate attendees for the same event (RFC 5545 iTIP requirement).
-- Uses lower(email) for case-insensitive comparison.
CREATE UNIQUE INDEX IF NOT EXISTS event_attendees_event_email_uniq
  ON event_attendees(event_id, lower(email));

-- ============================================================================
-- 2c — identity_sync_log indexes for admin dashboard queries
-- ============================================================================

-- Time-range queries (sync history dashboard, "last N syncs")
CREATE INDEX IF NOT EXISTS identity_sync_log_time_idx ON identity_sync_log(sync_at DESC);

-- Filtered by source with time ordering (per-provider sync status page)
CREATE INDEX IF NOT EXISTS identity_sync_log_source_idx ON identity_sync_log(source, sync_at DESC);
