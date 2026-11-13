-- Frozen Go's admin user Delete transaction (admin_users.go) on the worker
-- credential: reach (domain scope, then OU narrowing), delete protection check,
-- the user.deleted publication, then the cascade in Go's statement order.
-- Returns {status,detail|queued}; the adapter rolls back every non-204 status.
-- admin_protection_check errors propagate (adapter audits the denial).
CREATE OR REPLACE FUNCTION rust_admin_user_delete(
 p_actor bigint,p_id bigint,p_domain_scope bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_domain bigint; v_queued boolean;
BEGIN
 IF p_domain_scope>0 THEN
  SELECT domain_id INTO v_domain FROM users WHERE id=p_id AND domain_id=p_domain_scope;
  IF NOT FOUND THEN
   RETURN jsonb_build_object('status',404,'detail','user not found');
  END IF;
 END IF;
 IF NOT admin_can_manage(p_actor,p_id) THEN
  RETURN jsonb_build_object('status',404,'detail','user not found');
 END IF;
 PERFORM admin_protection_check(p_actor,p_id,'delete',NULL);
 v_queued:=webhook_user_deleted_publish(p_actor,p_id);
 DELETE FROM admin_role_assignments WHERE user_id=p_id;
 DELETE FROM aliases WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id=p_id);
 DELETE FROM message_attachments WHERE message_id IN (
  SELECT id FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id=p_id));
 DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id=p_id);
 DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id=p_id);
 DELETE FROM mailboxes WHERE user_id=p_id;
 DELETE FROM sessions WHERE user_id=p_id;
 DELETE FROM users WHERE id=p_id;
 RETURN jsonb_build_object('status',204,'queued',v_queued);
END;
$$;
