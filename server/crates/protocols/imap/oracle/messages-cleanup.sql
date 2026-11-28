-- Disposable gofree_e2e_imap2 only. Fixed divergent IDs 9344xxx. The audit log is
-- append-only (trigger BZ017), so only that one DELETE runs with triggers off; FK cascades stay on.
SET session_replication_role = replica;
DELETE FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9344021 AND 9344029;
RESET session_replication_role;
DELETE FROM messages WHERE mailbox_id BETWEEN 9344021 AND 9344029;
DELETE FROM app_passwords WHERE user_id BETWEEN 9344011 AND 9344019;
DELETE FROM tags WHERE mailbox_id BETWEEN 9344021 AND 9344029;
DELETE FROM mailboxes WHERE id BETWEEN 9344021 AND 9344029;
DELETE FROM users WHERE id BETWEEN 9344011 AND 9344019;
DELETE FROM domains WHERE id = 9344001;
UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.imap_membership_uid';
