-- scim_apply_group_members: Set-replace SCIM-sourced memberships for a group.
-- In a single transaction:
--   1. DELETE existing SCIM-sourced members not in the new list
--   2. INSERT new members not already present
-- This ensures the IdP owns the full member list for SCIM-sourced memberships.
-- Members are identified by their scim_external_id.

CREATE OR REPLACE FUNCTION scim_apply_group_members(
  p_source_id            BIGINT,
  p_expected_generation BIGINT,
  p_group_external_id   TEXT,
  p_member_external_ids TEXT[],
  p_replace             BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
DECLARE
  v_group_id BIGINT;
  v_requested_count BIGINT;
  v_resolved_count BIGINT;
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

  SELECT id INTO v_group_id FROM distribution_groups
    WHERE scim_source_id = p_source_id
      AND scim_external_id = p_group_external_id;

  IF v_group_id IS NULL THEN
    RAISE EXCEPTION 'Group not found for external_id: %', p_group_external_id
      USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'not_found', 'external_id', p_group_external_id)::TEXT;
  END IF;

  SELECT count(DISTINCT external_id)
    INTO v_requested_count
    FROM unnest(COALESCE(p_member_external_ids, ARRAY[]::TEXT[])) AS external_id;

  SELECT count(DISTINCT l.external_subject)
    INTO v_resolved_count
    FROM user_identity_links l
    JOIN users u ON u.id=l.user_id
   WHERE l.source_id=p_source_id
     AND l.external_subject=ANY(COALESCE(p_member_external_ids, ARRAY[]::TEXT[]))
     AND l.state='active'
     AND 'provision'=ANY(l.purposes)
     AND NOT is_guest_account(u.id);

  IF v_resolved_count <> v_requested_count THEN
    RAISE EXCEPTION 'One or more SCIM group members are not managed by this source'
      USING ERRCODE = 'BZ002',
            HINT = jsonb_build_object('type','not_found')::TEXT;
  END IF;

  -- Replace owns only this source's SCIM membership rows. Manual and SSO rows
  -- remain untouched.
  IF p_replace THEN
    DELETE FROM distribution_group_members dgm
    WHERE dgm.group_id = v_group_id
      AND dgm.source = 'scim'
      AND dgm.mailbox_id NOT IN (
        SELECT mb.id
          FROM user_identity_links l
          JOIN users u ON u.id=l.user_id
          JOIN mailboxes mb ON mb.user_id=u.id AND mb.is_primary
         WHERE l.source_id=p_source_id
           AND l.external_subject=ANY(COALESCE(p_member_external_ids, ARRAY[]::TEXT[]))
           AND l.state='active'
           AND 'provision'=ANY(l.purposes)
           AND NOT is_guest_account(u.id)
      );
  END IF;

  -- Insert new members from this source only.
  INSERT INTO distribution_group_members (group_id, mailbox_id, source)
  SELECT v_group_id, mb.id, 'scim'
  FROM user_identity_links l
  JOIN users u ON u.id=l.user_id
  JOIN mailboxes mb ON mb.user_id=u.id AND mb.is_primary
  WHERE l.source_id=p_source_id
    AND l.external_subject=ANY(COALESCE(p_member_external_ids, ARRAY[]::TEXT[]))
    AND l.state='active'
    AND 'provision'=ANY(l.purposes)
    AND NOT is_guest_account(u.id)
    AND NOT EXISTS (
      SELECT 1 FROM distribution_group_members dgm2
      WHERE dgm2.group_id = v_group_id AND dgm2.mailbox_id = mb.id
    );
END;
$$ LANGUAGE plpgsql;
