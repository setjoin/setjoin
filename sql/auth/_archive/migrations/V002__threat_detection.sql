-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V002: Threat detection — Phase 32.
-- Adds auth_attempts, auth_lockouts, ip_rules, threat_feed_blocks,
-- device_registry, and audit_log tables with reducers and pg_cron jobs.
\i ../schema/008_auth_attempts.sql
\i ../schema/009_auth_lockouts.sql
\i ../schema/010_ip_rules.sql
\i ../schema/011_threat_feed_blocks.sql
\i ../schema/012_device_registry.sql
\i ../schema/013_audit_log.sql
\i ../schema/014_feature_toggles_extend.sql
\i ../schema/015_rate_limit_counters.sql
\i ../reducers/detect_spray.sql
\i ../reducers/lockout_escalate.sql
\i ../reducers/prune_lockouts.sql
\i ../reducers/rotate_audit_partitions.sql

-- Schedule partition rotation on the 25th of each month
-- to ensure next-month partitions for auth_attempts and audit_log exist.
-- [pg_cron→Go cron worker] SELECT cron.schedule('rotate-auth-partitions', '0 0 25 * *',
--   $$ SELECT rotate_audit_partitions(); $$);

-- Schedule lockout pruning every 5 minutes.
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-auth-lockouts', '*/5 * * * *',
--   $$ SELECT prune_old_lockouts(); $$);
