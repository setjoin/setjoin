-- scim_upsert_user: Create or update a user from SCIM provisioning.
-- Matches on scim_external_id for idempotent upsert.
-- Returns the user ID.
--
-- Thin caller of provision_account() (the ONE provisioning seam): this reducer
-- only resolves the SCIM-specific bits — department-by-name and manager-by-
-- external-id — then hands the user + primary-mailbox lifecycle (domain resolve,
-- username derive, NOT NULL columns, primary mailbox) to provision_account so
-- the schema-correct INSERTs live in exactly one place.

CREATE OR REPLACE FUNCTION scim_upsert_user(
  p_external_id    TEXT,
  p_email          TEXT,
  p_display_name   TEXT,
  p_first_name     TEXT,
  p_last_name      TEXT,
  p_job_title      TEXT,
  p_phone          TEXT,
  p_department     TEXT,
  p_manager_external_id TEXT,
  p_active         BOOL,
  p_is_admin       BOOL
) RETURNS BIGINT AS $$
DECLARE
  v_department_id BIGINT;
  v_manager_id    BIGINT;
  v_result        JSONB;
  v_user_id       BIGINT;
BEGIN
  -- Resolve department by name (case-insensitive)
  IF p_department IS NOT NULL AND p_department != '' THEN
    SELECT id INTO v_department_id FROM departments WHERE name ILIKE p_department LIMIT 1;
  END IF;

  -- Resolve manager by SCIM external ID
  IF p_manager_external_id IS NOT NULL AND p_manager_external_id != '' THEN
    SELECT id INTO v_manager_id FROM users WHERE scim_external_id = p_manager_external_id LIMIT 1;
  END IF;

  -- Provision the person + primary mailbox via the single seam. Idempotent by
  -- scim_external_id (falls back to email) — matching the prior behaviour.
  v_result := provision_account(
    p_email            => p_email,
    p_display_name     => p_display_name,
    p_is_local_admin   => p_is_admin,
    p_enabled          => p_active,
    p_sync_source      => 'scim',
    p_first_name       => p_first_name,
    p_last_name        => p_last_name,
    p_job_title        => p_job_title,
    p_phone            => p_phone,
    p_department_id    => v_department_id,
    p_scim_external_id => p_external_id
  );

  v_user_id := (v_result->>'user_id')::BIGINT;

  -- Manager is SCIM-specific (resolved by external id above); set it directly.
  -- provision_account uses COALESCE so a NULL manager from here never clobbers.
  IF v_manager_id IS NOT NULL THEN
    UPDATE users SET manager_id = v_manager_id WHERE id = v_user_id;
  END IF;

  RETURN v_user_id;
END;
$$ LANGUAGE plpgsql;
