SELECT sc.id, sc.user_id, u.email, sc.field,
       COALESCE(sc.local_value, ''), COALESCE(sc.remote_value, ''),
       to_char(sc.detected_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')
       || CASE WHEN date_part('microseconds', sc.detected_at AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN ''
               ELSE regexp_replace(to_char(sc.detected_at AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'
FROM sync_conflicts sc JOIN users u ON u.id = sc.user_id
WHERE sc.resolved_at IS NULL
  AND sc.source = 'ad'
  AND (admin_org_wide_grant($1, '{users.read,identity.write,access.policy_read,access.policy_write}'::text[])
       OR admin_can_reach_perm($1, sc.user_id, '{users.read,identity.write,access.policy_read,access.policy_write}'::text[]))
ORDER BY sc.detected_at DESC LIMIT 200
