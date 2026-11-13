-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Extensions required by the schema.
CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- fuzzy text search
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid(), sha256()
-- [pg_cron→Go cron worker] CREATE EXTENSION IF NOT EXISTS pg_cron;   -- scheduled jobs

-- Deferred FK: domains.catch_all_mailbox_id → mailboxes.id
-- Added after both tables exist.
ALTER TABLE domains
  ADD CONSTRAINT domains_catch_all_fk
  FOREIGN KEY (catch_all_mailbox_id) REFERENCES mailboxes(id) ON DELETE SET NULL;

-- Deferred FK: users.avatar_sha256 → blobs.sha256
-- Added after blobs table exists (users is created in 003, blobs in 007).
ALTER TABLE users
  ADD CONSTRAINT users_avatar_fk
  FOREIGN KEY (avatar_sha256) REFERENCES blobs(sha256) ON DELETE SET NULL;

-- pg_cron jobs (registered after pg_cron extension is loaded).

-- Drain outbound_queue_hot into outbound_queue every 2 seconds.
-- [pg_cron→Go cron worker] SELECT cron.schedule('drain-outbound-hot', '2 seconds',
--   $$
--   WITH drained AS (
--     DELETE FROM outbound_queue_hot
--     RETURNING *
--   )
--   INSERT INTO outbound_queue
--   SELECT * FROM drained
--   ON CONFLICT (id) DO NOTHING;
--   $$
-- );

-- Create next month's message and message_trace partitions on the 25th of each month
-- (creates the *following* month's partition 5+ days in advance to avoid rows landing
-- in the DEFAULT partition before the partition exists).
-- [pg_cron→Go cron worker] SELECT cron.schedule('create-message-partitions', '0 0 25 * *',
--   $job$
--   DO $inner$DECLARE
--     v_next   DATE := date_trunc('month', now() + interval '1 month');
--     v_end    DATE := v_next + interval '1 month';
--     v_suffix TEXT := to_char(v_next, 'YYYY_MM');
--   BEGIN
--     EXECUTE format(
--       'CREATE TABLE IF NOT EXISTS messages_%s PARTITION OF messages
--        FOR VALUES FROM (%L) TO (%L)',
--       v_suffix, v_next, v_end);
--     EXECUTE format(
--       'CREATE TABLE IF NOT EXISTS message_trace_%s PARTITION OF message_trace
--        FOR VALUES FROM (%L) TO (%L)',
--       v_suffix, v_next, v_end);
--     EXECUTE format(
--       'CREATE TABLE IF NOT EXISTS mailbox_audit_log_%s PARTITION OF mailbox_audit_log
--        FOR VALUES FROM (%L) TO (%L)',
--       v_suffix, v_next, v_end);
--   END$inner$;
--   $job$
-- );

-- Prune health_history older than 7 days.
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-health-history', '0 3 * * *',
--   $$ DELETE FROM health_history WHERE checked_at < now() - interval '7 days'; $$
-- );

-- Reset daily sending quotas at midnight.
-- [pg_cron→Go cron worker] SELECT cron.schedule('reset-sending-quotas', '0 0 * * *',
--   $$
--   UPDATE mailboxes
--   SET sending_sent_today = 0, sending_quota_reset_at = CURRENT_DATE
--   WHERE sending_quota_reset_at < CURRENT_DATE;
--   $$
-- );

-- Delete orphaned blobs (ref_count = 0) — MinIO cleanup handled by gateway on next startup.
-- [pg_cron→Go cron worker] SELECT cron.schedule('mark-orphaned-blobs', '0 4 * * *',
--   $$ UPDATE blobs SET content_type = 'application/x-orphaned'
--      WHERE ref_count <= 0 AND content_type != 'application/x-orphaned'; $$
-- );

-- Prune expired greylisting entries older than 30 days.
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-greylist', '0 5 * * *',
--   $$ DELETE FROM greylist WHERE last_seen < now() - interval '30 days' AND NOT whitelisted; $$
-- );

-- Retry deferred outbound queue items (exponential backoff: 5m, 15m, 1h, 4h, 24h).
-- [pg_cron→Go cron worker] SELECT cron.schedule('retry-outbound-queue', '* * * * *',
--   $$
--   UPDATE outbound_queue SET status = 'pending'
--   WHERE status = 'deferred'
--     AND next_attempt_at <= now()
--     AND attempt_count < 20;
--   $$
-- );
