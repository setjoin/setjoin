WITH removed AS (
DELETE FROM field_policy
WHERE user_id = $4 AND field = $5
  AND $1::bigint > 0 AND $3::text <> ''
  AND public.admin_can_reach_perm($2, $4, '{identity.write}'::text[])
RETURNING 1)
SELECT count(*)::bigint FROM removed
