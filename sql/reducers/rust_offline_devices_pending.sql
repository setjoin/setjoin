-- rust_offline_devices_pending(p_actor): the approval queue of offline_devices_pending()
-- confined to the devices of users inside the caller's reach for mam.read.
-- Owner-approved security fix 2026-11-05 (#440): frozen Go listed every domain's pending
-- devices to any mam.read holder. Same rows, same order and same JSON as the Go reducer
-- for an organization-wide admin; admin_can_reach_perm is the permission-aware reach rule
-- (domain from the stored owner, OU and scope-set narrowing), so a domain-scoped admin
-- sees only its own domain. STABLE, read-only.
CREATE OR REPLACE FUNCTION rust_offline_devices_pending(p_actor bigint) RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id', d.id, 'user_id', d.user_id, 'platform', d.platform,
        'device_name', d.device_name, 'offline_approval', d.offline_approval,
        'last_seen_at', d.last_seen_at
      ) ORDER BY d.last_seen_at DESC), '[]'::jsonb)
      FROM user_devices d
     WHERE d.offline_approval = 'pending'
       AND d.platform IN ('desktop','ios','android')
       AND d.fingerprint_hash IS NOT NULL
       AND admin_can_reach_perm(p_actor, d.user_id, ARRAY['mam.read']);
$$ LANGUAGE sql STABLE;
