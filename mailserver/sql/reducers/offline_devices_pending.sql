-- offline_devices_pending.sql
-- Admin list of NATIVE devices awaiting offline approval (JSONB array). Offline
-- is native-only post-pivot, so the platform filter is desktop/ios/android (a
-- plain-browser 'web' row never registers an offline device — §6.0); the
-- fingerprint is the guard-core native device identity. Org/admin read (handler
-- RBAC); returns the fields the admin device queue needs.
CREATE OR REPLACE FUNCTION offline_devices_pending() RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id', d.id, 'user_id', d.user_id, 'platform', d.platform,
        'device_name', d.device_name, 'offline_approval', d.offline_approval,
        'last_seen_at', d.last_seen_at
      ) ORDER BY d.last_seen_at DESC), '[]'::jsonb)
      FROM user_devices d
     WHERE d.offline_approval = 'pending'
       AND d.platform IN ('desktop','ios','android')
       AND d.fingerprint_hash IS NOT NULL;
$$ LANGUAGE sql STABLE;
