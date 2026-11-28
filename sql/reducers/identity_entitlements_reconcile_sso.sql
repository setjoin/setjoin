CREATE OR REPLACE FUNCTION identity_entitlements_reconcile_sso(
    p_user_id BIGINT,
    p_provider_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_link user_identity_links%ROWTYPE;
    v_mailbox_id BIGINT;
    v_count INTEGER;
BEGIN
    SELECT * INTO v_source FROM identity_sources
     WHERE provider_key=p_provider_key AND state='active' FOR SHARE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('reconciled',false,'reason','source_unbound');
    END IF;
    SELECT * INTO v_link FROM user_identity_links
     WHERE user_id=p_user_id AND source_id=v_source.id AND state='active'
       AND 'authenticate'=ANY(purposes) FOR SHARE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('reconciled',false,'reason','link_missing');
    END IF;
    SELECT id INTO v_mailbox_id FROM mailboxes
     WHERE user_id=p_user_id AND is_primary ORDER BY id LIMIT 1;
    UPDATE identity_entitlement_grants
       SET revoked_at=statement_timestamp(),updated_at=statement_timestamp()
     WHERE user_id=p_user_id AND source_id=v_source.id
       AND link_id=v_link.id AND revoked_at IS NULL;
    INSERT INTO identity_entitlement_grants(
        user_id,target_kind,target_id,entitlement_kind,entitlement_id,
        provenance_kind,source_id,link_id,source_object,generation
    )
    SELECT p_user_id,'mailbox',v_mailbox_id,'distribution_group',p.group_id,
           'source',v_source.id,v_link.id,
           p_provider_key||':distribution_group:'||p.group_id::text,
           v_source.generation
      FROM sso_distribution_group_provenance p
     WHERE p.provider_key=p_provider_key AND p.mailbox_id=v_mailbox_id
       AND v_mailbox_id IS NOT NULL;
    INSERT INTO identity_entitlement_grants(
        user_id,target_kind,target_id,entitlement_kind,entitlement_id,
        provenance_kind,source_id,link_id,source_object,generation
    )
    SELECT p_user_id,'person',p_user_id,'admin_role_group',a.role_group_id,
           'source',v_source.id,v_link.id,
           p_provider_key||':admin_role_group:'||a.role_group_id::text,
           v_source.generation
      FROM sso_admin_role_provenance p
      JOIN admin_role_assignments a ON a.id=p.assignment_id
     WHERE p.provider_key=p_provider_key AND a.user_id=p_user_id;
    GET DIAGNOSTICS v_count=ROW_COUNT;
    INSERT INTO identity_link_events(
        user_id,source_id,link_id,action,reason,metadata
    ) VALUES(
        p_user_id,v_source.id,v_link.id,'entitlements_reconciled',
        'source-scoped SSO entitlement reconciliation',
        jsonb_build_object('providerKey',p_provider_key)
    );
    RETURN jsonb_build_object('reconciled',true,'roleGrantCount',v_count);
END;
$$;
SELECT apply_worker_ownership(
    'identity_entitlements_reconcile_sso(bigint,text)'::regprocedure
);
