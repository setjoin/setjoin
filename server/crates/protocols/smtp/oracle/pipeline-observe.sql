SELECT jsonb_build_object(
 'quarantine',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT m.mailbox_id,m.message_id,q.original_tag,q.reason,q.reason_type,q.virus_name
  FROM quarantined_messages q JOIN messages m ON m.id=q.message_id AND m.mailbox_id=q.mailbox_id
  WHERE m.mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY m.mailbox_id,m.message_id,q.reason) x),
 'locations',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT m.mailbox_id,m.message_id,t.name FROM messages m
  JOIN message_tags mt ON mt.message_id=m.id AND mt.received_at=m.received_at
  JOIN tags t ON t.id=mt.tag_id AND t.mailbox_id=m.mailbox_id
  WHERE m.mailbox_id BETWEEN 9348021 AND 9348023 AND t.exclusive_group='location'
  ORDER BY m.mailbox_id,m.message_id,t.name) x),
 'held',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT h.group_id,h.raw_ref,h.envelope,h.deliver_params-'p_sent_at' AS params,a.consumer_type,a.status
  FROM held_inbound_messages h JOIN approval_requests a ON a.id=h.approval_request_id
  WHERE h.group_id=9348041 ORDER BY h.raw_ref) x),
 'harvest',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT owner_user_id,email,cert_pem,fingerprint,not_before::text,not_after::text,source
  FROM recipient_smime_certs WHERE owner_user_id BETWEEN 9348011 AND 9348013 ORDER BY owner_user_id,email,fingerprint) x),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
  SELECT c.mailbox_id,e.uid,e.title,e.description,e.location,e.start_at::text,e.end_at::text,e.all_day,e.timezone,e.status,e.organizer_email,e.rrule,e.exdate,e.recurrence_override
  FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id
  WHERE c.mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY c.mailbox_id,e.uid,e.start_at) x)
)::text;
