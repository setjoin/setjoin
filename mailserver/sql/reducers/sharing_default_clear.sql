-- sharing_default_clear.sql — delete one sharing_defaults rule by id (spec
-- 2026-06-27-sharing-delegation-design.md §4 / D8). Counterpart of
-- sharing_default_set; same auth ladder (BZ116) + D7 domain scoping.
--
-- Errors: BZ114 (row not found — 404-indistinguishable) · BZ116 (actor not
-- authorized).
CREATE OR REPLACE FUNCTION sharing_default_clear(
  p_actor_user_id BIGINT,
  p_id            BIGINT
) RETURNS VOID AS $$
DECLARE
  v_row        sharing_defaults%ROWTYPE;
  v_perms      TEXT[];
  v_scope      BIGINT;
  v_target_dom BIGINT;
  v_owner_mb   BIGINT;
  v_owner_cal  BIGINT;
BEGIN
  SELECT * INTO v_row FROM sharing_defaults WHERE id = p_id;
  IF v_row.id IS NULL THEN
    RAISE EXCEPTION 'Sharing default not found'
      USING ERRCODE = 'BZ114',
            HINT = jsonb_build_object('type','sharing_default_not_found','id',p_id)::TEXT;
  END IF;

  -- Auth ladder (mirrors sharing_default_set): self user-scope, else
  -- sharing.manage within domain scope (D7; ou rows carry no domain axis).
  IF NOT (v_row.owner_scope = 'user' AND v_row.owner_ref = p_actor_user_id) THEN
    SELECT ea.perms, ea.scope INTO v_perms, v_scope
      FROM admin_effective_authority(p_actor_user_id) ea;
    IF NOT ('sharing.manage' = ANY(COALESCE(v_perms, '{}'))) THEN
      RAISE EXCEPTION 'sharing.manage required to clear a non-self sharing default'
        USING ERRCODE = 'BZ116',
              HINT = jsonb_build_object('type','sharing_forbidden','id',p_id)::TEXT;
    END IF;
    IF v_scope IS NOT NULL THEN
      v_target_dom := CASE v_row.owner_scope
        WHEN 'org'   THEN v_row.owner_ref
        WHEN 'user'  THEN (SELECT domain_id FROM users WHERE id = v_row.owner_ref)
        WHEN 'group' THEN (SELECT m.domain_id FROM distribution_groups g
                             JOIN mailboxes m ON m.id = g.mailbox_id WHERE g.id = v_row.owner_ref)
        ELSE NULL
      END;
      IF v_target_dom IS NOT NULL AND v_target_dom <> v_scope THEN
        RAISE EXCEPTION 'Sharing default target is outside your domain scope'
          USING ERRCODE = 'BZ116',
                HINT = jsonb_build_object('type','sharing_forbidden','domain_id',v_target_dom)::TEXT;
      END IF;
    END IF;
  END IF;

  DELETE FROM sharing_defaults WHERE id = p_id;

  -- D8: one immutable audit row, tier core.
  PERFORM audit_write(
    p_actor_user_id, 'sharing_default_cleared', 'sharing_default', p_id,
    to_jsonb(v_row), NULL,
    NULL, NULL, 'core');

  -- User-visible change for a user-scope row (mirrors sharing_default_set).
  IF v_row.owner_scope = 'user' THEN
    SELECT m.id INTO v_owner_mb FROM mailboxes m
     WHERE m.user_id = v_row.owner_ref AND m.is_primary
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
END;
$$ LANGUAGE plpgsql;
