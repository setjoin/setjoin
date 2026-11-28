-- Frozen Go's admin DeleteFolder: delete the paired tag (errors ignored, as
-- Go's `_, _ =`), then the folder. Absent folders still succeed (Go's 204).
CREATE OR REPLACE FUNCTION rust_admin_folder_delete(
 p_mailbox bigint,p_domain_scope bigint,p_folder bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_domain bigint;
BEGIN
 IF COALESCE(p_domain_scope,0)>0 THEN
  SELECT domain_id INTO v_domain FROM mailboxes WHERE id=p_mailbox;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','mailbox not found'); END IF;
  IF v_domain<>p_domain_scope THEN RETURN jsonb_build_object('status',403,'detail','access denied: mailbox not in domain scope'); END IF;
 END IF;
 BEGIN
  DELETE FROM tags WHERE mailbox_id=p_mailbox AND name=(
   SELECT name FROM folders WHERE id=p_folder AND mailbox_id=p_mailbox);
 EXCEPTION WHEN OTHERS THEN NULL;
 END;
 DELETE FROM folders WHERE id=p_folder AND mailbox_id=p_mailbox;
 RETURN jsonb_build_object('status',204);
END;
$$;
