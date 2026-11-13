-- scim_remove_group_members: remove only source-owned SCIM memberships.

CREATE OR REPLACE FUNCTION scim_remove_group_members(
  p_source_id           BIGINT,
  p_expected_generation BIGINT,
  p_group_external_id   TEXT,
  p_member_external_ids TEXT[]
) RETURNS VOID AS $$
DECLARE
  v_group_id BIGINT;
BEGIN
  PERFORM 1 FROM identity_sources
   WHERE id=p_source_id
     AND kind='scim'
     AND state='active'
     AND generation=p_expected_generation
   FOR SHARE;
  IF NOT FOUND THEN
    IF EXISTS (SELECT 1 FROM identity_sources WHERE id=p_source_id
               AND kind='scim' AND state='active') THEN
      RAISE EXCEPTION 'identity source generation is stale'
        USING ERRCODE='BZ229',
              HINT=jsonb_build_object('type','identity_source_generation_stale')::TEXT;
    END IF;
    RAISE EXCEPTION 'SCIM source is not active'
      USING ERRCODE='BZ224',
            HINT=jsonb_build_object('type','identity_source_inactive')::TEXT;
  END IF;

  SELECT id INTO v_group_id
    FROM distribution_groups
   WHERE scim_source_id=p_source_id
     AND scim_external_id=p_group_external_id;

  IF v_group_id IS NULL THEN
    RAISE EXCEPTION 'SCIM group was not found for this source'
      USING ERRCODE = 'BZ002',
            HINT = jsonb_build_object('type','not_found')::TEXT;
  END IF;

  DELETE FROM distribution_group_members dgm
   USING mailboxes mb, users u, user_identity_links l
   WHERE dgm.group_id=v_group_id
     AND dgm.source='scim'
     AND mb.id=dgm.mailbox_id
     AND u.id=mb.user_id
     AND l.user_id=u.id
     AND l.source_id=p_source_id
     AND l.external_subject=ANY(COALESCE(p_member_external_ids, ARRAY[]::TEXT[]))
     AND 'provision'=ANY(l.purposes);
END;
$$ LANGUAGE plpgsql;
