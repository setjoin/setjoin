CREATE OR REPLACE FUNCTION ensure_default_admin(p_email TEXT, p_password_hash TEXT) RETURNS JSONB AS $$
DECLARE
  v_domain_name TEXT;
  v_domain_id   BIGINT;
  v_user_id     BIGINT;
  v_role_group_id BIGINT;
BEGIN
  -- Serialize every first-boot actor before inspecting users. This reducer is
  -- reachable only through the local operator CLI, but the database remains the
  -- authority if two SSH sessions or installer retries race.
  PERFORM pg_advisory_xact_lock(1936025198, 1);

  IF EXISTS (SELECT 1 FROM users) THEN
    RETURN jsonb_build_object('admin_created', FALSE, 'reason', 'setup already completed');
  END IF;

  v_domain_name := split_part(p_email, '@', 2);

  IF v_domain_name = '' THEN
    RAISE EXCEPTION 'ensure_admin: invalid email %, cannot extract domain', p_email;
  END IF;

  SELECT id INTO v_domain_id FROM domains WHERE name = v_domain_name;

  IF v_domain_id IS NULL THEN
    INSERT INTO domains (name, is_primary, is_local)
    VALUES (v_domain_name, TRUE, TRUE)
    RETURNING id INTO v_domain_id;
  END IF;

  INSERT INTO users (username, domain_id, email, display_name, password_hash, is_local_admin)
  VALUES (
    split_part(p_email, '@', 1),
    v_domain_id,
    p_email,
    'Administrator',
    p_password_hash,
    TRUE
  )
  RETURNING id INTO v_user_id;

  IF NOT EXISTS (SELECT 1 FROM mailboxes WHERE user_id = v_user_id AND is_primary) THEN
    INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
    VALUES (v_user_id, v_domain_id, p_email, 'Administrator', 'personal', TRUE);
  END IF;

  -- The first-boot administrator must receive authority through the governed
  -- RBAC axis. users.is_admin/is_local_admin are not authorization grants.
  SELECT id
    INTO v_role_group_id
    FROM admin_role_groups
   WHERE name = 'Super Admin'
     AND is_builtin = TRUE;

  IF v_role_group_id IS NULL THEN
    RAISE EXCEPTION 'ensure_admin: built-in Super Admin role is missing';
  END IF;

  INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
  VALUES (v_user_id, v_role_group_id, v_user_id)
  ON CONFLICT (user_id, role_group_id) DO NOTHING;

  RETURN jsonb_build_object(
    'admin_created', TRUE,
    'email', p_email,
    'user_id', v_user_id,
    'domain', v_domain_name
  );
END;
$$ LANGUAGE plpgsql;
