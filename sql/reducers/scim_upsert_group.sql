-- scim_upsert_group: Create or update a distribution group from SCIM provisioning.
-- Matches on (source_id, scim_external_id) for source-bound idempotent upsert.
-- Creates a personal-type mailbox + distribution_groups row (the satellite row is the sole group signal).
-- Returns the group ID (distribution_groups.id).

CREATE OR REPLACE FUNCTION scim_upsert_group(
  p_source_id    BIGINT,
  p_expected_generation BIGINT,
  p_external_id  TEXT,
  p_display_name TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_group_id     BIGINT;
  v_mailbox_id   BIGINT;
  v_domain_name  TEXT;
  v_domain_id    BIGINT;
  v_email        TEXT;
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
        USING ERRCODE = 'BZ229',
              HINT = jsonb_build_object('type','identity_source_generation_stale')::TEXT;
    END IF;
    RAISE EXCEPTION 'SCIM source is not active'
      USING ERRCODE = 'BZ224',
            HINT = jsonb_build_object('type','identity_source_inactive')::TEXT;
  END IF;

  -- Match existing group only inside the authenticated source.
  SELECT id INTO v_group_id FROM distribution_groups
    WHERE scim_source_id = p_source_id
      AND scim_external_id = p_external_id;

  IF v_group_id IS NOT NULL THEN
    -- Update display name via mailbox join
    SELECT mailbox_id INTO v_mailbox_id FROM distribution_groups WHERE id = v_group_id;
    UPDATE mailboxes SET display_name = p_display_name, updated_at = now()
      WHERE id = v_mailbox_id;
    RETURN v_group_id;
  END IF;

  -- Derive email address for the group: externalId@primary-domain
  SELECT name, id INTO v_domain_name, v_domain_id FROM domains
    WHERE is_primary = TRUE LIMIT 1;

  IF v_domain_name IS NULL THEN
    SELECT name, id INTO v_domain_name, v_domain_id FROM domains
      WHERE is_local = TRUE LIMIT 1;
  END IF;

  IF v_domain_name IS NULL THEN
    RAISE EXCEPTION 'No domain configured for group provisioning'
      USING ERRCODE = 'BZ001', HINT = jsonb_build_object('type', 'no_domain')::TEXT;
  END IF;

  -- Sanitize external_id for use as email local-part
  v_email := regexp_replace(lower(p_external_id), '[^a-z0-9_.-]', '_', 'g');
  IF v_email = '' THEN
    v_email := 'scim-group';
  END IF;
  v_email := left(v_email, 40) || '-s' || p_source_id::TEXT || '@' || v_domain_name;

  -- Create mailbox for the group (personal type; distribution_groups row is the sole group signal)
  INSERT INTO mailboxes (domain_id, email, display_name, is_primary)
  VALUES (v_domain_id, v_email, p_display_name, FALSE)
  RETURNING id INTO v_mailbox_id;

  -- Create distribution_groups row
  INSERT INTO distribution_groups (mailbox_id, scim_source_id, scim_external_id)
  VALUES (v_mailbox_id, p_source_id, p_external_id)
  RETURNING id INTO v_group_id;

  RETURN v_group_id;
END;
$$ LANGUAGE plpgsql;
