SELECT jsonb_build_object('mailbox',mailbox_id,'name',name)::text FROM calendars WHERE id=$1;
