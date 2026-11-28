-- Canonical connectivity-aware offline policy upsert. The legacy ten-argument
-- offline_policy_set wrapper supplies conservative defaults for these fields.
CREATE OR REPLACE FUNCTION offline_policy_set_v2(
    p_actor_user_id BIGINT,
    p_id BIGINT,
    p_name TEXT,
    p_scope_type TEXT,
    p_scope_id BIGINT,
    p_enabled BOOLEAN,
    p_max_offline_days INT,
    p_require_approval BOOLEAN,
    p_wipe_on_logout TEXT,
    p_priority INT,
    p_background_sync_allowed BOOLEAN,
    p_automatic_network_max TEXT,
    p_attachment_prefetch_max TEXT,
    p_opportunistic_requires_charging BOOLEAN,
    p_connectivity_sync_mode TEXT
) RETURNS BIGINT AS $$
DECLARE
    v_id BIGINT;
    v_mailbox_id BIGINT;
    v_before JSONB;
    v_after JSONB;
BEGIN
    IF p_scope_type IS NULL OR p_scope_type NOT IN ('global','group','user')
       OR (p_scope_type='global' AND p_scope_id IS NOT NULL)
       OR (p_scope_type<>'global' AND p_scope_id IS NULL) THEN
        RAISE EXCEPTION 'invalid offline policy scope'
          USING ERRCODE='BZ099',
            HINT=jsonb_build_object('type','bad_scope','value',p_scope_type)::TEXT;
    END IF;
    IF p_wipe_on_logout IS NULL OR p_wipe_on_logout NOT IN ('always','admin_default','never') THEN
        RAISE EXCEPTION 'invalid wipe_on_logout %', p_wipe_on_logout
          USING ERRCODE='BZ099',
            HINT=jsonb_build_object('type','bad_wipe_on_logout','value',p_wipe_on_logout)::TEXT;
    END IF;
    IF p_automatic_network_max IS NULL OR p_automatic_network_max NOT IN ('never','unmetered','any') THEN
        RAISE EXCEPTION 'invalid automatic network policy'
          USING ERRCODE='BZ099',
            HINT=jsonb_build_object('type','bad_automatic_network','value',p_automatic_network_max)::TEXT;
    END IF;
    IF p_attachment_prefetch_max IS NULL OR p_attachment_prefetch_max NOT IN ('never','unmetered','always') THEN
        RAISE EXCEPTION 'invalid attachment prefetch policy'
          USING ERRCODE='BZ099',
            HINT=jsonb_build_object('type','bad_attachment_prefetch','value',p_attachment_prefetch_max)::TEXT;
    END IF;
    IF p_connectivity_sync_mode IS NULL OR p_connectivity_sync_mode NOT IN ('off','observe','execute') THEN
        RAISE EXCEPTION 'invalid connectivity sync mode'
          USING ERRCODE='BZ099',
            HINT=jsonb_build_object('type','bad_connectivity_sync_mode','value',p_connectivity_sync_mode)::TEXT;
    END IF;
    IF p_name IS NULL OR btrim(p_name)='' OR p_priority IS NULL
       OR p_max_offline_days IS NULL OR p_max_offline_days<0
       OR p_enabled IS NULL OR p_require_approval IS NULL
       OR p_background_sync_allowed IS NULL OR p_opportunistic_requires_charging IS NULL THEN
        RAISE EXCEPTION 'invalid offline policy value'
          USING ERRCODE='BZ099', HINT='{"type":"bad_policy_value"}';
    END IF;

    IF p_id IS NULL THEN
        INSERT INTO offline_policies(
          name,scope_type,scope_id,enabled,max_offline_days,require_approval,
          wipe_on_logout,priority,background_sync_allowed,automatic_network_max,
          attachment_prefetch_max,opportunistic_requires_charging,connectivity_sync_mode)
        VALUES(
          p_name,p_scope_type,p_scope_id,p_enabled,p_max_offline_days,p_require_approval,
          p_wipe_on_logout,p_priority,p_background_sync_allowed,p_automatic_network_max,
          p_attachment_prefetch_max,p_opportunistic_requires_charging,p_connectivity_sync_mode)
        RETURNING id INTO v_id;
    ELSE
        SELECT to_jsonb(p) INTO v_before
          FROM offline_policies p WHERE p.id=p_id FOR UPDATE;
        IF v_before IS NULL THEN
            RAISE EXCEPTION 'offline policy % not found', p_id
              USING ERRCODE='BZ099',
                HINT=jsonb_build_object('type','not_found','id',p_id)::TEXT;
        END IF;
        UPDATE offline_policies SET
          name=p_name,scope_type=p_scope_type,scope_id=p_scope_id,enabled=p_enabled,
          max_offline_days=p_max_offline_days,require_approval=p_require_approval,
          wipe_on_logout=p_wipe_on_logout,priority=p_priority,
          background_sync_allowed=p_background_sync_allowed,
          automatic_network_max=p_automatic_network_max,
          attachment_prefetch_max=p_attachment_prefetch_max,
          opportunistic_requires_charging=p_opportunistic_requires_charging,
          connectivity_sync_mode=p_connectivity_sync_mode,updated_at=now()
        WHERE id=p_id RETURNING id INTO v_id;
    END IF;

    SELECT to_jsonb(p) INTO v_after FROM offline_policies p WHERE p.id=v_id;
    PERFORM audit_write(p_actor_user_id,'offline_policy_set','offline_policy',v_id,
      v_before,v_after,NULL,NULL,'core');

    IF p_scope_type='user' THEN
        SELECT id INTO v_mailbox_id FROM mailboxes
         WHERE user_id=p_scope_id ORDER BY is_primary DESC,id LIMIT 1;
    END IF;
    PERFORM app_notify(COALESCE('tag:'||v_mailbox_id::TEXT,'caps:offline'),
      '{"type":"capsChanged"}');
    RETURN v_id;
END;
$$ LANGUAGE plpgsql VOLATILE;
