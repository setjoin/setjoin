-- Canonical user-device preference mutation. Identity is server-derived; the
-- ownership predicate is part of the single UPDATE (R3, no check-then-write).
CREATE OR REPLACE FUNCTION offline_device_set_preferences(
    p_mailbox_id BIGINT,
    p_device_id BIGINT,
    p_opt_in BOOLEAN,
    p_window_days INT,
    p_background_sync_enabled BOOLEAN,
    p_automatic_network_pref TEXT,
    p_attachment_prefetch_pref TEXT
) RETURNS VOID AS $$
DECLARE
    v_user_id BIGINT;
    v_cap INT;
BEGIN
    IF p_automatic_network_pref IS NULL OR p_automatic_network_pref NOT IN ('never','unmetered','any')
       OR p_attachment_prefetch_pref IS NULL OR p_attachment_prefetch_pref NOT IN ('never','unmetered','always')
       OR p_opt_in IS NULL OR p_background_sync_enabled IS NULL
       OR p_window_days IS NULL OR p_window_days<0 THEN
        RAISE EXCEPTION 'invalid offline device preferences'
          USING ERRCODE='BZ099', HINT='{"type":"bad_device_preferences"}';
    END IF;
    SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'device not found for mailbox'
          USING ERRCODE='BZ100', HINT='{"type":"not_found"}';
    END IF;
    -- Match the effective-policy precedence exactly. A lower-scope fallback is
    -- not a second ceiling once a user/group winner exists. The ugm_self RLS
    -- policy admits only v_user_id's memberships on the app pool; tests run as
    -- superuser. This query is the persistence clamp, while the snapshot repeats
    -- the same winner for runtime projection.
    SELECT max_offline_days INTO v_cap
      FROM offline_policies
     WHERE scope_type='global'
        OR (scope_type='user' AND scope_id=v_user_id)
        OR (scope_type='group' AND scope_id IN (
              SELECT group_id FROM user_group_members WHERE user_id=v_user_id))
     ORDER BY CASE scope_type WHEN 'user' THEN 2 WHEN 'group' THEN 1 ELSE 0 END DESC,
              priority DESC,
              id ASC
     LIMIT 1;
    v_cap := COALESCE(v_cap,0);

    UPDATE user_devices SET
      offline_opt_in=p_opt_in,
      offline_window_days=LEAST(p_window_days,v_cap),
      background_sync_enabled=p_background_sync_enabled,
      automatic_network_pref=p_automatic_network_pref,
      attachment_prefetch_pref=p_attachment_prefetch_pref
    WHERE id=p_device_id AND user_id=v_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'device % not found for user', p_device_id
          USING ERRCODE='BZ100',
            HINT=jsonb_build_object('type','not_found','id',p_device_id)::TEXT;
    END IF;

    -- WP3 audit coverage: user-device preference change — routine tier, so the
    -- row lands only at audit_policy level 'full' (audit_write's gate) and the
    -- lean default keeps preference churn out of the admin log.
    PERFORM audit_write(
        v_user_id, 'offline_device_set_preferences', 'device', p_device_id,
        NULL,
        jsonb_build_object('offline_opt_in', p_opt_in,
                           'offline_window_days', LEAST(p_window_days, v_cap),
                           'background_sync_enabled', p_background_sync_enabled,
                           'automatic_network_pref', p_automatic_network_pref,
                           'attachment_prefetch_pref', p_attachment_prefetch_pref),
        NULL, NULL, 'routine');

    PERFORM app_notify('tag:'||p_mailbox_id,'{"type":"capsChanged"}');
END;
$$ LANGUAGE plpgsql VOLATILE;
