-- Frozen Go listSpaces transaction: provision and project under one user scope.
CREATE OR REPLACE FUNCTION drive_rust_list_spaces(p_user_id BIGINT)
RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE v_name TEXT; v_out JSONB;
BEGIN
  SELECT display_name INTO STRICT v_name FROM users WHERE id=p_user_id;
  PERFORM drive_space_create(p_user_id,v_name,'regular',true);
  SELECT coalesce(jsonb_agg(item ORDER BY is_personal DESC,name),'[]'::jsonb)
    INTO v_out FROM (
      SELECT s.is_personal,s.name,
        jsonb_build_object('id',s.id,'name',s.name,'isPersonal',s.is_personal,
          'classification',s.classification,'role',drive_space_access_role(p_user_id,s.id),
          'usedBytes',s.used_bytes,'changeSeq',s.change_seq,'aclMode',s.acl_mode,'aclEpoch',g.epoch,
          'rootCapabilities',ARRAY(SELECT c FROM unnest(drive_acl_capability_catalog()) c
             WHERE drive_runtime_has_space_root_capability(p_user_id,s.id,c)),
          'accessGovernanceEnabled',coalesce((SELECT enabled FROM feature_toggles
             WHERE key='feature.drive_access_governance'),false))
        || CASE WHEN s.quota_bytes IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('quotaBytes',s.quota_bytes) END AS item
      FROM drive_spaces s JOIN drive_acl_generations g ON g.space_id=s.id
      WHERE s.chat_channel_id IS NULL AND s.meeting_id IS NULL
        AND drive_user_has_space_access(p_user_id,s.id)
    ) t;
  RETURN v_out;
END;
$$;
