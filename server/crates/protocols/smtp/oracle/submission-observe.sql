SELECT jsonb_build_object(
 'messages',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT mailbox_id,message_id,subject,from_addr,from_name,to_addrs,cc_addrs,bcc_addrs,in_reply_to,body_text,body_html,size_bytes,raw_ref,has_attachments,is_draft,is_read
  FROM messages WHERE mailbox_id BETWEEN 9501021 AND 9501023 ORDER BY mailbox_id,message_id,id) x),
 'queue',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT message_id,from_addr,rcpt_addrs,raw_ref,status,mailbox_id FROM outbound_queue WHERE from_addr LIKE '%@smtp5.test' ORDER BY id) x),
 'auth_events',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT user_id,event,provider,email,host(ip_address) AS ip,details FROM auth_event_log WHERE user_id BETWEEN 9501011 AND 9501015 OR email LIKE '%@smtp5.test' ORDER BY id) x),
 'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT host(source_ip) AS ip,target_username,protocol,outcome,geo_country FROM auth_attempts WHERE target_username LIKE '%@smtp5.test' ORDER BY id) x),
 'signins',(SELECT coalesce(jsonb_agg(to_jsonb(x)-'id'-'occurred_at'),'[]'::jsonb) FROM login_events x WHERE user_id BETWEEN 9501011 AND 9501015 OR (user_id IS NULL AND client='smtp' AND source_ip='127.0.0.1')),
 'lockouts',(SELECT coalesce(jsonb_agg(jsonb_build_object('key',lockout_key,'failed_count',failed_count,'escalation_level',escalation_level) ORDER BY lockout_key),'[]'::jsonb) FROM auth_lockouts WHERE lockout_key LIKE '%smtp5.test%' OR lockout_key='ip:127.0.0.1'),
 'rate',(SELECT coalesce(jsonb_agg(jsonb_build_object('key',key,'count',count) ORDER BY key),'[]'::jsonb) FROM rate_limit_counters WHERE key LIKE 'ip:127.0.0.1%' OR key LIKE 'acct:%smtp5.test' OR key LIKE 'auth:smtp:%'),
 'devices',(SELECT coalesce(jsonb_agg(jsonb_build_object('user',user_id,'ip_prefix',ip_prefix,'country',country,'auth_count',auth_count) ORDER BY device_hash),'[]'::jsonb) FROM device_registry WHERE user_id BETWEEN 9501011 AND 9501015),
 'audit',(SELECT coalesce(jsonb_agg(jsonb_build_object('user',user_id,'event',event_type) ORDER BY id),'[]'::jsonb) FROM audit_log WHERE user_id BETWEEN 9501011 AND 9501015),
 'mailbox_audit',(SELECT coalesce(jsonb_agg(jsonb_build_object('mailbox',mailbox_id,'actor',actor_user_id,'action',action) ORDER BY id),'[]'::jsonb) FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9501021 AND 9501023)
)::text;
