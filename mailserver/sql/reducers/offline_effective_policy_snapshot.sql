-- Internal authoritative offline-policy projection shared by the JMAP session,
-- user preference response, and authorized admin preview. Callers must not
-- reproduce precedence or enum-intersection logic in Go/TypeScript.
CREATE OR REPLACE FUNCTION offline_effective_policy_snapshot(
    p_mailbox_id BIGINT,
    p_device_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_user_id BIGINT;
    v_master BOOLEAN;
    v_connectivity BOOLEAN;
    v_policy_id BIGINT;
    v_scope_type TEXT;
    v_policy_enabled BOOLEAN;
    v_policy_max INT;
    v_require_approval BOOLEAN;
    v_wipe_on_logout TEXT;
    v_background_allowed BOOLEAN;
    v_network_max TEXT;
    v_attachment_max TEXT;
    v_requires_charging BOOLEAN;
    v_mode TEXT;
    v_opt_in BOOLEAN;
    v_approval TEXT;
    v_window INT;
    v_device_background BOOLEAN;
    v_network_requested TEXT;
    v_attachment_requested TEXT;
    v_allowed BOOLEAN;
    v_max_days INT;
    v_effective_network TEXT;
    v_effective_attachment TEXT;
    v_source JSONB;
BEGIN
    SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
    IF v_user_id IS NULL THEN
        RETURN jsonb_build_object(
            'allowed', false,
            'approvalState', 'pending',
            'maxOfflineDays', 0,
            'wipeOnLogout', 'admin_default',
            'requireApproval', true,
            'syncQoS', jsonb_build_object(
                'schemaVersion', 1,
                'mode', 'off',
                'backgroundAllowed', false,
                'requested', jsonb_build_object(
                    'automaticNetwork', 'never',
                    'attachmentPrefetch', 'never'),
                'effective', jsonb_build_object(
                    'automaticNetwork', 'never',
                    'attachmentPrefetch', 'never',
                    'opportunisticRequiresCharging', true),
                'sources', jsonb_build_object()));
    END IF;

    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.offline_mail'), false),
           COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.connectivity_aware_sync'), false)
      INTO v_master, v_connectivity;

    -- Total order: user > group > global, priority DESC, stable id ASC.
    -- The ugm_self RLS policy admits only v_user_id's memberships when this
    -- invoker-rights resolver runs on the scoped app pool; tests use superuser.
    SELECT id, scope_type, enabled, max_offline_days, require_approval,
           wipe_on_logout, background_sync_allowed, automatic_network_max,
           attachment_prefetch_max, opportunistic_requires_charging,
           connectivity_sync_mode
      INTO v_policy_id, v_scope_type, v_policy_enabled, v_policy_max,
           v_require_approval, v_wipe_on_logout, v_background_allowed,
           v_network_max, v_attachment_max, v_requires_charging, v_mode
      FROM offline_policies
     WHERE scope_type='global'
        OR (scope_type='user' AND scope_id=v_user_id)
        OR (scope_type='group' AND scope_id IN (
              SELECT group_id FROM user_group_members WHERE user_id=v_user_id))
     ORDER BY CASE scope_type WHEN 'user' THEN 2 WHEN 'group' THEN 1 ELSE 0 END DESC,
              priority DESC,
              id ASC
     LIMIT 1;

    v_policy_enabled := COALESCE(v_policy_enabled, false);
    v_policy_max := COALESCE(v_policy_max, 0);
    v_require_approval := COALESCE(v_require_approval, true);
    v_wipe_on_logout := COALESCE(v_wipe_on_logout, 'admin_default');
    v_background_allowed := COALESCE(v_background_allowed, false);
    v_network_max := COALESCE(v_network_max, 'never');
    v_attachment_max := COALESCE(v_attachment_max, 'never');
    v_requires_charging := COALESCE(v_requires_charging, true);
    v_mode := COALESCE(v_mode, 'off');

    -- R1: the device is read only through the authenticated mailbox owner.
    SELECT offline_opt_in, offline_approval, offline_window_days,
           background_sync_enabled, automatic_network_pref,
           attachment_prefetch_pref
      INTO v_opt_in, v_approval, v_window, v_device_background,
           v_network_requested, v_attachment_requested
      FROM user_devices
     WHERE id=p_device_id AND user_id=v_user_id;

    v_opt_in := COALESCE(v_opt_in, false);
    v_approval := COALESCE(v_approval, 'pending');
    v_device_background := COALESCE(v_device_background, false);
    v_network_requested := COALESCE(v_network_requested, 'never');
    v_attachment_requested := COALESCE(v_attachment_requested, 'never');

    v_allowed := v_master AND v_policy_enabled AND v_opt_in
                 AND (NOT v_require_approval OR v_approval='approved')
                 AND v_approval NOT IN ('revoked','denied');
    v_max_days := LEAST(COALESCE(v_window, v_policy_max), v_policy_max);
    v_max_days := COALESCE(v_max_days, 0);

    -- Network/prefetch ceilings describe what the server will permit. They do
    -- not absorb the user's background toggle: an explicit foreground action
    -- may run while automatic work remains disabled. backgroundAllowed below
    -- is the separate automatic-work admission signal.
    IF NOT (v_allowed AND v_connectivity) THEN
        v_effective_network := 'never';
        v_effective_attachment := 'never';
    ELSE
        v_effective_network := CASE LEAST(
            CASE v_network_requested WHEN 'any' THEN 2 WHEN 'unmetered' THEN 1 ELSE 0 END,
            CASE v_network_max WHEN 'any' THEN 2 WHEN 'unmetered' THEN 1 ELSE 0 END)
          WHEN 2 THEN 'any' WHEN 1 THEN 'unmetered' ELSE 'never' END;
        v_effective_attachment := CASE LEAST(
            CASE v_attachment_requested WHEN 'always' THEN 2 WHEN 'unmetered' THEN 1 ELSE 0 END,
            CASE v_attachment_max WHEN 'always' THEN 2 WHEN 'unmetered' THEN 1 ELSE 0 END)
          WHEN 2 THEN 'always' WHEN 1 THEN 'unmetered' ELSE 'never' END;
    END IF;

    v_source := CASE WHEN v_policy_id IS NULL THEN jsonb_build_object()
      ELSE jsonb_build_object('policyId', v_policy_id::TEXT, 'scope', v_scope_type)
      END;

    RETURN jsonb_build_object(
        'allowed', v_allowed,
        'approvalState', v_approval,
        'maxOfflineDays', v_max_days,
        'wipeOnLogout', v_wipe_on_logout,
        'requireApproval', v_require_approval,
        'syncQoS', jsonb_build_object(
            'schemaVersion', 1,
            'mode', CASE WHEN v_connectivity THEN v_mode ELSE 'off' END,
            'backgroundAllowed',
                v_allowed AND v_connectivity AND v_background_allowed
                AND v_device_background AND v_mode <> 'off',
            'requested', jsonb_build_object(
                'automaticNetwork', v_network_requested,
                'attachmentPrefetch', v_attachment_requested),
            'effective', jsonb_build_object(
                'automaticNetwork', v_effective_network,
                'attachmentPrefetch', v_effective_attachment,
                'opportunisticRequiresCharging', v_requires_charging),
            'sources', jsonb_build_object(
                'automaticNetwork', v_source,
                'attachmentPrefetch', v_source)));
END;
$$ LANGUAGE plpgsql STABLE;
