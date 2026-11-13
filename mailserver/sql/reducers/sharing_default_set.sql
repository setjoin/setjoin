-- sharing_default_set.sql — upsert one sharing_defaults rule (spec
-- 2026-06-27-sharing-delegation-design.md §4; D3 owner-scope × audience ×
-- level, D7 domain-scoped admin authority, D8 audit).
--
-- AUTH LADDER (enforced HERE, not only at the gateway — §8):
--   owner_scope='user' → p_actor = p_owner_ref (self-default, D5), OR a
--     sharing.manage admin whose domain scope covers the owner (§7 override).
--   org/ou/group      → sharing.manage required (BZ116). Domain scoping (D7):
--     a domain-scoped admin may only target their own domain — org rows by
--     owner_ref, group rows via the group mailbox's domain. OU rows carry no
--     domain (departments have no domain_id), so they are gated on the perm
--     alone. ponytail: OU↔domain mapping lands with a departments.domain_id.
--
-- Errors: BZ116 (actor not authorized) · BZ117 (invalid scope/audience/level
-- combination or unknown ref). Returns the row id.
CREATE OR REPLACE FUNCTION sharing_default_set(
  p_actor_user_id BIGINT,
  p_resource      TEXT,
  p_owner_scope   TEXT,
  p_owner_ref     BIGINT,
  p_audience      TEXT,
  p_audience_ref  BIGINT,
  p_level         TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_perms        TEXT[];
  v_scope        BIGINT;
  v_is_admin     BOOLEAN := FALSE;
  v_target_dom   BIGINT;
  v_before       JSONB;
  v_id           BIGINT;
  v_owner_mb     BIGINT;
  v_owner_cal    BIGINT;
BEGIN
  -- ── validation (BZ117) ────────────────────────────────────────────────────
  IF p_resource IS DISTINCT FROM 'calendar' THEN
    RAISE EXCEPTION 'Only calendar defaults are supported'
      USING ERRCODE = 'BZ117',
            HINT = jsonb_build_object('type','sharing_invalid_scope','resource',COALESCE(p_resource,''))::TEXT;
  END IF;
  IF p_owner_scope IS NULL OR p_owner_scope NOT IN ('org','ou','group','user')
     OR p_audience IS NULL OR p_audience NOT IN ('everyone','ou','group')
     OR p_level IS NULL OR p_level NOT IN ('none','freebusy','read')
     OR p_owner_ref IS NULL OR p_audience_ref IS NULL THEN
    RAISE EXCEPTION 'Invalid sharing-default scope/audience/level'
      USING ERRCODE = 'BZ117',
            HINT = jsonb_build_object('type','sharing_invalid_scope')::TEXT;
  END IF;

  -- owner_ref must exist for its scope
  IF NOT (CASE p_owner_scope
           WHEN 'org'   THEN EXISTS (SELECT 1 FROM domains             WHERE id = p_owner_ref)
           WHEN 'ou'    THEN EXISTS (SELECT 1 FROM departments         WHERE id = p_owner_ref)
           WHEN 'group' THEN EXISTS (SELECT 1 FROM distribution_groups WHERE id = p_owner_ref)
           WHEN 'user'  THEN EXISTS (SELECT 1 FROM users               WHERE id = p_owner_ref)
         END) THEN
    RAISE EXCEPTION 'Unknown owner_ref for scope %', p_owner_scope
      USING ERRCODE = 'BZ117',
            HINT = jsonb_build_object('type','sharing_invalid_scope','owner_scope',p_owner_scope)::TEXT;
  END IF;

  -- audience_ref must exist for its audience
  IF NOT (CASE p_audience
           WHEN 'everyone' THEN EXISTS (SELECT 1 FROM domains             WHERE id = p_audience_ref)
           WHEN 'ou'       THEN EXISTS (SELECT 1 FROM departments         WHERE id = p_audience_ref)
           WHEN 'group'    THEN EXISTS (SELECT 1 FROM distribution_groups WHERE id = p_audience_ref)
         END) THEN
    RAISE EXCEPTION 'Unknown audience_ref for audience %', p_audience
      USING ERRCODE = 'BZ117',
            HINT = jsonb_build_object('type','sharing_invalid_scope','audience',p_audience)::TEXT;
  END IF;

  -- ── auth ladder (BZ116) ───────────────────────────────────────────────────
  IF NOT (p_owner_scope = 'user' AND p_owner_ref = p_actor_user_id) THEN
    SELECT ea.perms, ea.scope INTO v_perms, v_scope
      FROM admin_effective_authority(p_actor_user_id) ea;
    v_is_admin := 'sharing.manage' = ANY(COALESCE(v_perms, '{}'));
    IF NOT v_is_admin THEN
      RAISE EXCEPTION 'sharing.manage required to set a non-self sharing default'
        USING ERRCODE = 'BZ116',
              HINT = jsonb_build_object('type','sharing_forbidden','owner_scope',p_owner_scope)::TEXT;
    END IF;
    -- D7: domain-scoped admin only inside their domain (where derivable).
    IF v_scope IS NOT NULL THEN
      v_target_dom := CASE p_owner_scope
        WHEN 'org'   THEN p_owner_ref
        WHEN 'user'  THEN (SELECT domain_id FROM users WHERE id = p_owner_ref)
        WHEN 'group' THEN (SELECT m.domain_id FROM distribution_groups g
                             JOIN mailboxes m ON m.id = g.mailbox_id WHERE g.id = p_owner_ref)
        ELSE NULL  -- ou: no domain axis (see header)
      END;
      IF v_target_dom IS NOT NULL AND v_target_dom <> v_scope THEN
        RAISE EXCEPTION 'Sharing default target is outside your domain scope'
          USING ERRCODE = 'BZ116',
                HINT = jsonb_build_object('type','sharing_forbidden','domain_id',v_target_dom)::TEXT;
      END IF;
    END IF;
  END IF;

  -- ── upsert ────────────────────────────────────────────────────────────────
  SELECT to_jsonb(sd) INTO v_before FROM sharing_defaults sd
   WHERE resource = p_resource AND owner_scope = p_owner_scope AND owner_ref = p_owner_ref
     AND audience = p_audience AND audience_ref = p_audience_ref;

  INSERT INTO sharing_defaults (resource, owner_scope, owner_ref, audience, audience_ref, level, created_by)
  VALUES (p_resource, p_owner_scope, p_owner_ref, p_audience, p_audience_ref, p_level, p_actor_user_id)
  ON CONFLICT (resource, owner_scope, owner_ref, audience, audience_ref)
  DO UPDATE SET level = EXCLUDED.level, updated_at = now()
  RETURNING id INTO v_id;

  -- D8: one immutable audit row, tier core.
  PERFORM audit_write(
    p_actor_user_id, 'sharing_default_set', 'sharing_default', v_id,
    v_before,
    jsonb_build_object('resource',p_resource,'owner_scope',p_owner_scope,'owner_ref',p_owner_ref,
                       'audience',p_audience,'audience_ref',p_audience_ref,'level',p_level),
    NULL, NULL, 'core');

  -- User-visible change for a user-scope row: bump the owner's primary
  -- calendar state so shared-calendar viewers refetch (mirrors
  -- jmap_calendar_share_set's 'calendar_shared' bump+push).
  -- ponytail: org/ou/group rows skip the bump — a mass per-member state write;
  -- viewers pick the new default up on their next fetch.
  IF p_owner_scope = 'user' THEN
    SELECT m.id INTO v_owner_mb FROM mailboxes m
     WHERE m.user_id = p_owner_ref AND m.is_primary
     ORDER BY m.id LIMIT 1;
    IF v_owner_mb IS NOT NULL THEN
      SELECT c.id INTO v_owner_cal FROM calendars c
       WHERE c.mailbox_id = v_owner_mb
       ORDER BY c.is_default DESC, c.id LIMIT 1;
      IF v_owner_cal IS NOT NULL THEN
        PERFORM notify_calendar_state(v_owner_mb, NULL, v_owner_cal, 'calendar_shared');
      END IF;
    END IF;
  END IF;

  RETURN v_id;
END;
$$ LANGUAGE plpgsql;
