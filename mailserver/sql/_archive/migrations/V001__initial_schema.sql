-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V001: Initial schema — apply all schema files in dependency order.
-- Run with: flyway migrate  OR  psql -f V001__initial_schema.sql

-- Extensions first
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- pg_cron is optional — Go cron worker handles scheduling.
-- Uncomment if you prefer pg_cron over the built-in Go cron worker.
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

\i ../schema/001_domains.sql
\i ../schema/002_departments.sql
\i ../schema/003_users.sql
\i ../schema/004_mailboxes.sql
\i ../schema/005_folders.sql
\i ../schema/006_messages.sql
\i ../schema/007_blobs_attachments.sql
\i ../schema/008_aliases_groups.sql
\i ../schema/009_rules.sql
\i ../schema/010_calendar.sql
\i ../schema/011_contacts.sql
\i ../schema/012_tasks.sql
\i ../schema/013_queues.sql
\i ../schema/014_system.sql
\i ../schema/015_compliance.sql
\i ../schema/016_identity_sync.sql
\i ../schema/017_unlogged.sql
\i ../schema/018_fk_and_extensions.sql
\i ../schema/020_vacation.sql
\i ../schema/021_greylist.sql
\i ../schema/022_rate_limit.sql
\i ../schema/023_dkim.sql
\i ../schema/024_dlp.sql
\i ../schema/025_calendar_resources.sql
\i ../schema/026_storage_dr_scans.sql
\i ../schema/019_tags.sql
\i ../schema/030_message_tags.sql
\i ../schema/031_snooze.sql

-- Reducers
\i ../reducers/build_jmap_get_response.sql
\i ../reducers/utils.sql
\i ../reducers/utils_tags.sql
\i ../reducers/rule_engine.sql
\i ../reducers/retention.sql
\i ../reducers/journal.sql
\i ../reducers/deliver.sql
\i ../reducers/send.sql
\i ../reducers/startup_recovery.sql
\i ../reducers/health_check.sql
\i ../reducers/jmap_mailbox.sql
\i ../reducers/jmap_email.sql
\i ../reducers/jmap_email_submission.sql
\i ../reducers/jmap_thread.sql
\i ../reducers/jmap_calendar.sql
\i ../reducers/jmap_contact.sql
\i ../reducers/deliver_group_vacation.sql
\i ../reducers/rule_engine_or.sql
\i ../reducers/jmap_task.sql
\i ../reducers/calendar_freebusy.sql
\i ../reducers/calendar_itip.sql
\i ../reducers/calendar_finalize_create_bookings.sql
\i ../reducers/calendar_finalize_create_invites.sql
\i ../reducers/import_export.sql
\i ../reducers/ensure_admin.sql
\i ../reducers/directory_browse.sql
\i ../reducers/org_chart.sql
\i ../reducers/auth_policy.sql
\i ../schema/036_pg_search.sql
\i ../schema/036_dlp_patterns.sql
\i ../schema/044_cleanup_jobs.sql

-- Seed initial partitions for the current month and next month
DO $$DECLARE
  v_months DATE[] := ARRAY[
    date_trunc('month', now())::DATE,
    date_trunc('month', now() + interval '1 month')::DATE
  ];
  v_start DATE;
  v_end   DATE;
  v_suffix TEXT;
BEGIN
  FOREACH v_start IN ARRAY v_months LOOP
    v_end   := v_start + interval '1 month';
    v_suffix := to_char(v_start, 'YYYY_MM');
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS messages_%s PARTITION OF messages
       FOR VALUES FROM (%L) TO (%L)', v_suffix, v_start, v_end);
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS message_trace_%s PARTITION OF message_trace
       FOR VALUES FROM (%L) TO (%L)', v_suffix, v_start, v_end);
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS mailbox_audit_log_%s PARTITION OF mailbox_audit_log
       FOR VALUES FROM (%L) TO (%L)', v_suffix, v_start, v_end);
  END LOOP;
END$$;

-- Default system config values
INSERT INTO system_config (key, value, description) VALUES
  ('spam_threshold',             '"5.0"',       'Spam score above which messages go to Spam tag'),
  ('identity_source',            '"local"',     'Identity provider: local | ad | ldap'),
  ('auth_grace_hours',           '"4"',         'Hours to keep JWT valid if AD is unreachable'),
  ('max_message_bytes',          '"157286400"', 'Maximum inbound message size in bytes (150 MB)'),
  ('setup_complete',             '"false"',     'Set to true after first-run wizard completes'),
  ('default_quota_bytes',        '"53687091200"', 'Default storage quota per new mailbox (50 GB)'),
  ('default_sending_quota_day',  '"500"',       'Default daily sending limit per new mailbox'),
  ('alert_email_addresses',      '""',          'Comma-separated admin emails for health alerts'),
  ('alert_min_consecutive',      '"3"',         'Consecutive health check failures before alerting'),
  ('hc_replication_lag_warn_sec',    '"30"',   'Replication lag warn threshold (seconds)'),
  ('hc_replication_lag_error_sec',   '"60"',   'Replication lag error threshold (seconds)'),
  ('hc_outbound_queue_warn',         '"100"',  'Outbound queue depth warn threshold (messages)'),
  ('hc_outbound_queue_error',        '"500"',  'Outbound queue depth error threshold (messages)'),
  ('hc_outbound_queue_age_warn_min', '"15"',   'Oldest queue item age warn threshold (minutes)'),
  ('hc_outbound_queue_age_error_min','"60"',   'Oldest queue item age error threshold (minutes)'),
  ('hc_db_size_warn_gb',             '"80"',   'Database size warn threshold (GB)'),
  ('hc_db_size_error_gb',            '"100"',  'Database size error threshold (GB)'),
  ('hc_auth_fail_warn',              '"50"',   'Auth failure rate warn threshold (failed attempts per 5-minute window)'),
  ('hc_auth_fail_error',             '"200"',  'Auth failure rate error threshold (failed attempts per 5-minute window)'),
  ('hc_dkim_expiry_warn_days',       '"30"',   'DKIM key expiry warn threshold (days)'),
  ('hc_dkim_expiry_error_days',      '"7"',    'DKIM key expiry error threshold (days)'),
  ('hc_crash_window_min',            '"10"',   'Crash event detection window (minutes)'),
  ('hc_consec_fail_window_min',      '"20"',   'Consecutive failure escalation window (minutes)'),
  ('tls_mode',                        '"none"', 'TLS mode: none | static | autocert'),
  ('tls_autocert_domains',            '""',     'Comma-separated Let''s Encrypt domains'),
  ('tls_autocert_challenge',          '"tls-alpn-01"', 'Challenge: tls-alpn-01 (port 443) | http-01 (port 80)'),
  ('tls_autocert_email',              '""',     'Let''s Encrypt notification email'),
  ('tls_auto_renew',                  '"true"', 'Auto-renew Let''s Encrypt certificates'),
  ('ad_sync_enabled',               '"false"', 'Enable automatic AD user sync'),
  ('ad_sync_domain',                 '""',     'Active Directory domain name'),
  ('ad_sync_bind_dn',                '""',     'AD service account DN'),
  ('ad_sync_password_enc',           '""',     'AD service account password (AES-256-GCM encrypted)'),
  ('ad_sync_interval_min',           '"15"',   'AD sync interval in minutes'),
  ('ad_sync_ldap_host',              '""',     'AD LDAP host override (auto-discovered from DNS if empty)'),
  ('ad_sync_auto_create_depts',      '"false"', 'Auto-create departments from AD'),
  ('ad_sync_proxy_as_aliases',       '"false"', 'Sync proxyAddresses as email aliases'),
  ('enable_totp_reset',              '"true"', 'Allow TOTP-based password reset'),
  ('enable_sms_reset',              '"false"', 'Allow SMS-based password reset'),
  ('password_min_length',           '"8"',     'Minimum password length'),
  ('password_require_uppercase',    '"true"',  'Require at least one uppercase letter'),
  ('password_require_lowercase',    '"true"',  'Require at least one lowercase letter'),
  ('password_require_digit',        '"true"',  'Require at least one digit'),
  ('password_require_special',      '"true"',  'Require at least one special character'),
  ('mfa_enforcement_mode',          '"required"', 'MFA mode: optional | required'),
  ('trusted_proxy_ips',             '["127.0.0.1","::1"]', 'Comma-separated trusted proxy IPs/CIDRs for X-Forwarded-For')
ON CONFLICT (key) DO NOTHING;
\i ../schema/045_rbac.sql
\i ../schema/046_calendar_recurrence.sql
\i ../schema/041_smime_certs.sql
\i ../schema/037_deploy_steps.sql
\i ../schema/038_mta_sts_cache.sql
\i ../schema/039_blob_cleanup.sql
\i ../schema/011_timezone_notify.sql
\i ../schema/034_dmarc_reports.sql
