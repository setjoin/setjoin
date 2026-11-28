SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]')::text FROM (
 SELECT ip::text,sender,recipient,pass_count FROM greylist
 WHERE recipient LIKE '%@smtp1.test' OR recipient LIKE '%@smtp1-other.test'
 ORDER BY ip,sender,recipient
) x;
