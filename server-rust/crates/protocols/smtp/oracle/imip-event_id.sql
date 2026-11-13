SELECT jsonb_build_object('uid',e.uid,'mailbox',c.mailbox_id,'recurrence',e.recurrence_override)::text FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE e.id=$1;
