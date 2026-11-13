-- Frozen Go's admin MailboxesHandler.Delete transaction (worker credential):
-- aliases, attachments, messages, folders, then the mailbox, in this order and
-- one transaction. The domain-scope predicate rides in the same statements
-- (R3); a scoped actor outside the mailbox's domain changes nothing and gets
-- false. A missing mailbox is a no-op that still answers true, as Go's 204.
CREATE OR REPLACE FUNCTION rust_admin_mailbox_delete(
 p_mailbox bigint,p_domain_scope bigint
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 IF COALESCE(p_domain_scope,0)>0 AND NOT EXISTS (
  SELECT 1 FROM mailboxes WHERE id=p_mailbox AND domain_id=p_domain_scope) THEN
  RETURN false;
 END IF;
 DELETE FROM aliases WHERE mailbox_id=p_mailbox;
 DELETE FROM message_attachments WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id=p_mailbox);
 DELETE FROM messages WHERE mailbox_id=p_mailbox;
 DELETE FROM folders WHERE mailbox_id=p_mailbox;
 DELETE FROM mailboxes WHERE id=p_mailbox AND (COALESCE(p_domain_scope,0)=0 OR domain_id=p_domain_scope);
 RETURN true;
END;
$$;
