-- V084: message_retention_tags rows are PRUNING BOOKKEEPING ("this message is
-- governed by policy N, prunes at expires_at") — not holds. Litigation hold has
-- its own guard (trg_messages_hold_check). The plain FK made that bookkeeping
-- BLOCK message deletion: admin user-delete 500'd for any user whose mailbox
-- had ever received a retention-tagged message (i.e. every user, via the
-- welcome email + default global policy). Cascade the bookkeeping with the
-- message; holds still block through their trigger.
ALTER TABLE message_retention_tags
  DROP CONSTRAINT message_retention_tags_message_id_received_at_fkey;
ALTER TABLE message_retention_tags
  ADD CONSTRAINT message_retention_tags_message_id_received_at_fkey
  FOREIGN KEY (message_id, received_at)
  REFERENCES messages (id, received_at) ON DELETE CASCADE;

INSERT INTO schema_migrations (version, applied_at) VALUES (84, now()) ON CONFLICT DO NOTHING;
