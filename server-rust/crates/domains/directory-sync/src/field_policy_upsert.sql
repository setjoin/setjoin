WITH written AS (
INSERT INTO field_policy (user_id, field, policy)
SELECT $4, $5, $6
WHERE $1::bigint > 0 AND $3::text <> ''
  AND public.admin_can_reach_perm($2, $4, '{identity.write}'::text[])
ON CONFLICT (user_id, field) DO UPDATE SET policy = $6, set_at = now()
RETURNING 1)
SELECT count(*)::bigint FROM written
