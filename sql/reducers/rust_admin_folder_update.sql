-- Frozen Go's admin UpdateFolder: rename the paired tag FIRST (its subquery
-- reads the old folder name; a failure only warns in Go, so it is swallowed),
-- then rename the folder and rewrite the last path segment. A folder that
-- does not exist is still a success, as Go's 204. Returns {status,detail}.
CREATE OR REPLACE FUNCTION rust_admin_folder_update(
 p_mailbox bigint,p_domain_scope bigint,p_folder bigint,p_name text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_domain bigint;
BEGIN
 IF COALESCE(p_domain_scope,0)>0 THEN
  SELECT domain_id INTO v_domain FROM mailboxes WHERE id=p_mailbox;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','mailbox not found'); END IF;
  IF v_domain<>p_domain_scope THEN RETURN jsonb_build_object('status',403,'detail','access denied: mailbox not in domain scope'); END IF;
 END IF;
 BEGIN
  UPDATE tags SET name=p_name WHERE mailbox_id=p_mailbox AND name=(
   SELECT name FROM folders WHERE id=p_folder AND mailbox_id=p_mailbox);
 EXCEPTION WHEN OTHERS THEN NULL;
 END;
 UPDATE folders SET name=p_name,path=regexp_replace(path,'[^/]+$',p_name)
  WHERE id=p_folder AND mailbox_id=p_mailbox;
 RETURN jsonb_build_object('status',204);
END;
$$;
