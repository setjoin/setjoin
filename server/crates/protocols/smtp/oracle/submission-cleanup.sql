-- Disposable gofree_e2e_smtp5 only. Fixed IDs 9501xxx.
BEGIN;
SET LOCAL session_replication_role='replica';
DELETE FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9501021 AND 9501023;
DELETE FROM audit_log WHERE user_id BETWEEN 9501011 AND 9501015;
COMMIT;
DELETE FROM auth_event_log WHERE user_id BETWEEN 9501011 AND 9501015 OR email LIKE '%@smtp5.test';
DELETE FROM auth_attempts WHERE target_username LIKE '%@smtp5.test';
DELETE FROM login_events WHERE user_id BETWEEN 9501011 AND 9501015 OR (user_id IS NULL AND client='smtp' AND source_ip='127.0.0.1');
DELETE FROM auth_lockouts WHERE lockout_key LIKE '%smtp5.test%' OR lockout_key='ip:127.0.0.1';
DELETE FROM device_registry WHERE user_id BETWEEN 9501011 AND 9501015;
DELETE FROM threat_feed_blocks WHERE source='smtp5';
DELETE FROM ip_rules WHERE description='smtp5';
DELETE FROM conditional_access_policies WHERE id=9501900;
DELETE FROM rate_limit_counters WHERE key LIKE 'ip:127.0.0.1%' OR key LIKE 'acct:%smtp5.test' OR key='acct:' OR key LIKE 'auth:smtp:%';
DELETE FROM app_passwords WHERE user_id BETWEEN 9501011 AND 9501015;
DELETE FROM guest_accounts WHERE user_id BETWEEN 9501011 AND 9501015;
DELETE FROM outbound_queue WHERE mailbox_id BETWEEN 9501021 AND 9501023 OR from_addr LIKE '%@smtp5.test';
BEGIN;
SET LOCAL session_replication_role='replica';
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t
   ON t.table_schema=c.table_schema AND t.table_name=c.table_name AND t.table_type='BASE TABLE'
   WHERE c.table_schema='public' AND c.column_name='mailbox_id' AND c.table_name NOT IN ('mailboxes','messages','outbound_queue')
 LOOP EXECUTE format('DELETE FROM %I WHERE mailbox_id BETWEEN 9501021 AND 9501023',r.table_name); END LOOP;
END $$;
DELETE FROM messages WHERE mailbox_id BETWEEN 9501021 AND 9501023;
DELETE FROM aliases WHERE mailbox_id BETWEEN 9501021 AND 9501023;
DELETE FROM mailboxes WHERE id BETWEEN 9501021 AND 9501023;
DELETE FROM users WHERE id BETWEEN 9501011 AND 9501015;
DELETE FROM domains WHERE id=9501001;
COMMIT;
