SELECT jsonb_build_object(
 'messages', (SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT mailbox_id,message_id,subject,from_addr,from_name,to_addrs,cc_addrs,bcc_addrs,body_text,body_html,size_bytes,raw_ref,spf_result,dkim_result,dmarc_result,spam_score,spam_headers,crypto_type,is_read,is_draft,is_deleted
  FROM messages WHERE mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY mailbox_id,message_id) x),
 'mailboxes',(SELECT jsonb_agg(to_jsonb(x)) FROM (SELECT id,used_bytes,jmap_email_state,jmap_tag_state FROM mailboxes WHERE id BETWEEN 9348021 AND 9348023 ORDER BY id) x),
 'tags',(SELECT jsonb_agg(to_jsonb(x)) FROM (SELECT mailbox_id,name,total_count,unread_count,imap_uid_next,jmap_state FROM tags WHERE mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY mailbox_id,name) x),
 'journal',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (SELECT mailbox_id,state_seq,op,datatype FROM jmap_changes_journal WHERE mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY mailbox_id,state_seq) x),
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (SELECT mailbox_id,actor_user_id,action FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY id) x)
)::text;
