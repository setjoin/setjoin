-- Compatibility entry point retained for pre-V209 gateways. Existing policy
-- rows keep their V209 QoS fields; newly created rows receive the migration's
-- conservative defaults. All mutation/audit/notify authority remains in v2.
CREATE OR REPLACE FUNCTION offline_policy_set(
    p_actor_user_id BIGINT,
    p_id BIGINT,
    p_name TEXT,
    p_scope_type TEXT,
    p_scope_id BIGINT,
    p_enabled BOOLEAN,
    p_max_offline_days INT,
    p_require_approval BOOLEAN,
    p_wipe_on_logout TEXT,
    p_priority INT
) RETURNS BIGINT AS $$
DECLARE
    v_background_sync_allowed BOOLEAN := true;
    v_automatic_network_max TEXT := 'unmetered';
    v_attachment_prefetch_max TEXT := 'never';
    v_opportunistic_requires_charging BOOLEAN := true;
    v_connectivity_sync_mode TEXT := 'off';
BEGIN
    IF p_id IS NOT NULL THEN
        SELECT background_sync_allowed, automatic_network_max,
               attachment_prefetch_max, opportunistic_requires_charging,
               connectivity_sync_mode
          INTO v_background_sync_allowed, v_automatic_network_max,
               v_attachment_prefetch_max, v_opportunistic_requires_charging,
               v_connectivity_sync_mode
          FROM offline_policies
         WHERE id=p_id
         FOR UPDATE;
    END IF;

    RETURN offline_policy_set_v2(
        p_actor_user_id,p_id,p_name,p_scope_type,p_scope_id,p_enabled,
        p_max_offline_days,p_require_approval,p_wipe_on_logout,p_priority,
        COALESCE(v_background_sync_allowed,true),
        COALESCE(v_automatic_network_max,'unmetered'),
        COALESCE(v_attachment_prefetch_max,'never'),
        COALESCE(v_opportunistic_requires_charging,true),
        COALESCE(v_connectivity_sync_mode,'off'));
END;
$$ LANGUAGE plpgsql VOLATILE;
