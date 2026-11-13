SELECT jsonb_build_object(
 'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM (SELECT remote_ip::text,state,bytes_received FROM smtp_sessions WHERE remote_ip='127.0.0.1' ORDER BY id) x),
 'counter',(SELECT count FROM rate_limit_counters WHERE key='smtp:conn:127.0.0.1')
)::text;
