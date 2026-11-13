-- #340: frozen applyGroupMappingsAtomic; the first-grant provenance gap is
-- fixed (#530). No principal is selected from a request-owned identity.
CREATE OR REPLACE FUNCTION rust_identity_rp_map(
    p_user_id bigint,p_provider_key text,p_groups jsonb,p_mappings jsonb,p_allow_super boolean
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_mailbox_id bigint;v_mapping jsonb;v_group bigint;v_department bigint;v_exclude_super boolean;
BEGIN
    IF p_groups IS NULL OR jsonb_array_length(p_mappings)=0 THEN RETURN; END IF;
    SELECT id INTO v_mailbox_id FROM mailboxes WHERE user_id=p_user_id AND is_primary ORDER BY id LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO primary mailbox unavailable' USING ERRCODE='BZ228',HINT='{"type":"identity_source_invalid"}';
    END IF;
    WITH removed AS (
        DELETE FROM sso_distribution_group_provenance WHERE provider_key=p_provider_key AND mailbox_id=v_mailbox_id
        RETURNING group_id,mailbox_id
    ) DELETE FROM distribution_group_members dgm USING removed r
      WHERE dgm.group_id=r.group_id AND dgm.mailbox_id=r.mailbox_id AND dgm.mailbox_id=v_mailbox_id AND dgm.source='sso'
      AND NOT EXISTS(SELECT 1 FROM sso_distribution_group_provenance p WHERE p.group_id=dgm.group_id AND p.mailbox_id=dgm.mailbox_id AND p.provider_key<>p_provider_key)
      AND NOT EXISTS(SELECT 1 FROM sso_distribution_group_legacy_inventory legacy WHERE legacy.group_id=dgm.group_id AND legacy.mailbox_id=dgm.mailbox_id);
    SELECT p_allow_super AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_mappings) m WHERE m->>'admin_role'='super_admin' AND p_groups ? (m->>'idp_group')) INTO v_exclude_super;
    WITH removed AS (
        DELETE FROM sso_admin_role_provenance p USING admin_role_assignments ara
        WHERE p.provider_key=p_provider_key AND p.assignment_id=ara.id AND ara.user_id=p_user_id AND NOT(ara.role_group_id=1 AND v_exclude_super)
        RETURNING p.assignment_id
    ) DELETE FROM admin_role_assignments ara USING removed r
      WHERE ara.id=r.assignment_id AND ara.user_id=p_user_id AND ara.granted_by IS NULL
      AND NOT EXISTS(SELECT 1 FROM sso_admin_role_provenance p WHERE p.assignment_id=ara.id AND p.provider_key<>p_provider_key)
      AND NOT EXISTS(SELECT 1 FROM sso_admin_role_legacy_inventory legacy WHERE legacy.assignment_id=ara.id);
    FOR v_mapping IN SELECT value FROM jsonb_array_elements(p_mappings) LOOP
        IF NOT(p_groups ? (v_mapping->>'idp_group')) THEN CONTINUE; END IF;
        IF v_mapping->>'distribution_group_id' IS NOT NULL THEN
            -- Two statements: the provenance row must see the membership this
            -- callback just inserted. Frozen Go's single data-modifying CTE did
            -- not, so a first grant carried membership without provenance and a
            -- later IdP-driven removal could not attribute or revoke it
            -- (owner-approved security fix #530).
            INSERT INTO distribution_group_members(group_id,mailbox_id,source)
            VALUES((v_mapping->>'distribution_group_id')::bigint,v_mailbox_id,'sso') ON CONFLICT DO NOTHING;
            INSERT INTO sso_distribution_group_provenance(provider_key,group_id,mailbox_id)
            SELECT p_provider_key,group_id,mailbox_id FROM distribution_group_members
            WHERE group_id=(v_mapping->>'distribution_group_id')::bigint AND mailbox_id=v_mailbox_id ON CONFLICT DO NOTHING;
        END IF;
        IF v_mapping->>'admin_role' IS NOT NULL AND NOT(v_mapping->>'admin_role'='super_admin' AND NOT p_allow_super) THEN
            v_group:=CASE v_mapping->>'admin_role' WHEN 'super_admin' THEN 1 WHEN 'user_admin' THEN 2 WHEN 'auditor' THEN 4 WHEN 'read_only' THEN 8 ELSE 0 END;
            IF v_group>0 THEN
                WITH inserted AS (
                    INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES(p_user_id,v_group,NULL)
                    ON CONFLICT(user_id,role_group_id) DO NOTHING RETURNING id
                ), effective AS (
                    SELECT id FROM inserted UNION ALL SELECT id FROM admin_role_assignments WHERE user_id=p_user_id AND role_group_id=v_group LIMIT 1
                ) INSERT INTO sso_admin_role_provenance(provider_key,assignment_id) SELECT p_provider_key,id FROM effective ON CONFLICT DO NOTHING;
            END IF;
        END IF;
        IF v_mapping->>'department_id' IS NOT NULL THEN v_department:=(v_mapping->>'department_id')::bigint; END IF;
    END LOOP;
    IF v_department IS NOT NULL THEN UPDATE users SET department_id=v_department WHERE id=p_user_id; END IF;
END;
$$;
