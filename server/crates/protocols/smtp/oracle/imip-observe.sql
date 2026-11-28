SELECT jsonb_build_object(
 'attendees',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
 SELECT c.mailbox_id,e.uid,e.recurrence_override,a.email,a.name,a.role,a.status,a.rsvp
 FROM event_attendees a JOIN calendar_events e ON e.id=a.event_id JOIN calendars c ON c.id=e.calendar_id
 WHERE c.mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY c.mailbox_id,e.uid,e.recurrence_override,a.email) x),
 'states',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
 SELECT c.mailbox_id,c.name,c.jmap_state,e.uid,e.sequence,e.jmap_state AS event_state,e.is_meeting,e.organizer_email,e.recurrence_override,e.exdate
 FROM calendars c LEFT JOIN calendar_events e ON e.calendar_id=c.id
 WHERE c.mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY c.mailbox_id,e.uid,e.recurrence_override) x),
 'rates',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
 SELECT key,count,blocked_until IS NOT NULL AS blocked FROM rate_limit_counters WHERE key IN ('itip:recipient:9348011','itip:recipient:9348012','itip:recipient:9348013') ORDER BY key) x)
)::text;
