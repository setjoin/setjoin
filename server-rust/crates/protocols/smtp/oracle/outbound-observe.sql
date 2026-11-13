SELECT json_build_object(
 'queue', COALESCE((SELECT json_agg(x ORDER BY id) FROM (SELECT id,status,attempt_count,last_error,delivered_at IS NOT NULL AS delivered,
 CASE WHEN status IN ('deferred','bounced') THEN round(extract(epoch FROM next_attempt_at-now())/60)::int ELSE NULL END AS backoff_minutes
 FROM outbound_queue WHERE message_id LIKE '%smtp3.test%') x),'[]'::json),
 'attempts',COALESCE((SELECT json_agg(x ORDER BY recipient_email,attempt_number) FROM (SELECT message_pk,mailbox_id,recipient_email,mx_host,attempt_number,smtp_code,smtp_text,outcome,tls FROM delivery_attempts WHERE mailbox_id BETWEEN 9348021 AND 9348023) x),'[]'::json),
 'traces',COALESCE((SELECT json_agg(x ORDER BY event,rcpt_addr) FROM (SELECT message_id,event,from_addr,rcpt_addr,remote_host,details FROM message_trace WHERE message_id LIKE '%smtp3.test%') x),'[]'::json),
 'audit_count',(SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9348021 AND 9348023),
 'mailbox_states',(SELECT json_agg(json_build_array(id,jmap_email_state,jmap_mailbox_state) ORDER BY id) FROM mailboxes WHERE id BETWEEN 9348021 AND 9348023)
);
