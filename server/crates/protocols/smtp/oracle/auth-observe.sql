SELECT coalesce(jsonb_agg(to_jsonb(r)),'[]'::jsonb)::text FROM (
 SELECT domain,report_uri,total_count,count_none,count_pass,count_fail,count_temperror,count_permperror,policy_domain,policy_pct
 FROM dmarc_reports WHERE domain='smtp2.test' OR domain LIKE '%.smtp2.test' ORDER BY domain,report_uri
) r;
