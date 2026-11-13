-- scim_delete_group: Deprovision a distribution group by its id.
-- Deletes the group row then its backing mailbox (the FK points group->mailbox, so
-- the group row must go first). Members cascade via distribution_group_members FK.
-- Returns TRUE if a group was deleted, FALSE if none existed (caller emits 404).
-- No jmap_*_state bump / no pg_notify: distribution-group mailboxes are not JMAP
-- owner objects (the create path scim_upsert_group doesn't notify either).

CREATE OR REPLACE FUNCTION scim_delete_group(
  p_source_id BIGINT,
  p_expected_generation BIGINT,
  p_group_id BIGINT
) RETURNS BOOLEAN AS $$
DECLARE
  v_mailbox_id BIGINT;
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

  SELECT mailbox_id INTO v_mailbox_id
    FROM distribution_groups
   WHERE id=p_group_id AND scim_source_id=p_source_id;
  IF v_mailbox_id IS NULL THEN
    RETURN FALSE;
  END IF;
  DELETE FROM distribution_groups
   WHERE id=p_group_id AND scim_source_id=p_source_id;    -- members cascade via FK
  DELETE FROM mailboxes WHERE id = v_mailbox_id;           -- drop orphaned address + routing
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
