-- V086: audit records outlive their principals — drop the users FKs from the
-- append-only audit tables.
--
-- The FKs were ON DELETE SET NULL, which is doubly wrong: (1) SET NULL is an
-- UPDATE, and the append-only guard (correctly) blocks it — so deleting any
-- user who had EVER acted 500'd the admin user-delete after the mailbox
-- cascade was fixed; (2) even if it worked, nulling user_id would erase WHO
-- performed the audited action — the one thing an audit line must preserve.
-- user_id stays as a plain historical value; the row names a principal that
-- existed when the event happened.

ALTER TABLE audit_log         DROP CONSTRAINT IF EXISTS audit_log_user_id_fkey;
ALTER TABLE admin_audit_log   DROP CONSTRAINT IF EXISTS admin_audit_log_user_id_fkey;
ALTER TABLE mailbox_audit_log DROP CONSTRAINT IF EXISTS mailbox_audit_log_actor_user_id_fkey;

INSERT INTO schema_migrations (version, applied_at) VALUES (86, now()) ON CONFLICT DO NOTHING;
