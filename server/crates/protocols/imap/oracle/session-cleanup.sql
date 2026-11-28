-- Disposable gofree_e2e_imap3 only (#345). Fixed divergent IDs 9345xxx. The audit log is
-- append-only (trigger BZ017), so only that one DELETE runs with triggers off; FK cascades stay on.
SET session_replication_role = replica;
DELETE FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9345021 AND 9345029;
RESET session_replication_role;
DELETE FROM jmap_changes_journal WHERE mailbox_id BETWEEN 9345021 AND 9345029;
DELETE FROM orphaned_message_blobs WHERE raw_ref LIKE 'imap3/%';
DELETE FROM messages WHERE mailbox_id BETWEEN 9345021 AND 9345029;
DELETE FROM user_imap_settings WHERE user_id BETWEEN 9345011 AND 9345019;
DELETE FROM app_passwords WHERE user_id BETWEEN 9345011 AND 9345019;
DELETE FROM tags WHERE mailbox_id BETWEEN 9345021 AND 9345029;
DELETE FROM mailboxes WHERE id BETWEEN 9345021 AND 9345029;
DELETE FROM users WHERE id BETWEEN 9345011 AND 9345019;
DELETE FROM domains WHERE id = 9345001;
DELETE FROM auth_event_log WHERE email LIKE '%@imap3.test';
UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.imap_membership_uid';
