WITH resolved AS (
UPDATE sync_conflicts sc
SET resolved_at = now(), resolution = $4
WHERE sc.resolved_at IS NULL AND sc.source = 'ad'
  AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''
  AND (admin_org_wide_grant($2, '{identity.write}'::text[])
       OR admin_can_reach_perm($2, sc.user_id, '{identity.write}'::text[]))
RETURNING 1)
SELECT count(*)::bigint FROM resolved
