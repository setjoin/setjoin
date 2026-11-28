-- Frozen Go's admin CreateFolder: parent path lookup, folder INSERT, and the
-- best-effort paired tag INSERT (Go warns and carries on when it fails, so the
-- failure is swallowed here). Returns {status,detail|id}: 201, 400 (parent
-- folder not found) or 403/404 when the scoped actor cannot reach the mailbox.
-- The folder INSERT's own errors propagate (Go answers 500).
CREATE OR REPLACE FUNCTION rust_admin_folder_create(
 p_mailbox bigint,p_domain_scope bigint,p_parent bigint,p_name text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_domain bigint; v_parent_path text; v_path text; v_id bigint;
BEGIN
 IF COALESCE(p_domain_scope,0)>0 THEN
  SELECT domain_id INTO v_domain FROM mailboxes WHERE id=p_mailbox;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','mailbox not found'); END IF;
  IF v_domain<>p_domain_scope THEN RETURN jsonb_build_object('status',403,'detail','access denied: mailbox not in domain scope'); END IF;
 END IF;
 IF p_parent IS NOT NULL AND p_parent>0 THEN
  SELECT path INTO v_parent_path FROM folders WHERE id=p_parent AND mailbox_id=p_mailbox;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',400,'detail','parent folder not found'); END IF;
 END IF;
 v_path:=CASE WHEN COALESCE(v_parent_path,'')<>'' THEN v_parent_path||'/'||p_name ELSE p_name END;
 INSERT INTO folders(mailbox_id,parent_id,name,path) VALUES(p_mailbox,p_parent,p_name,v_path) RETURNING id INTO v_id;
 BEGIN
  INSERT INTO tags(mailbox_id,parent_id,name,tag_type,sort_order,imap_expose)
  VALUES(p_mailbox,p_parent,p_name,'user',100,TRUE) ON CONFLICT (mailbox_id,name) DO NOTHING;
 EXCEPTION WHEN OTHERS THEN NULL;
 END;
 RETURN jsonb_build_object('status',201,'id',v_id);
END;
$$;
