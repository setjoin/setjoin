-- task_lists.sql — shared/team task list containers + explicit membership
-- (plan 2026-07-08-shared-team-task-lists.md, Phase 1). Every reducer here
-- takes p_user_id (the authenticated viewer, never trusted from req.* beyond
-- the JWT claim) and uses it in every statement (R1/R3) — the app-level
-- membership-predicate posture ARCH-006 prescribes for this cross-mailbox
-- surface (identical shape to sharing_default_set's p_actor_user_id family).
--
-- Error codes: BZ130 = not owner / not a member (404-indistinguishable, no
-- membership oracle — the BZ118/BZ123 pattern); BZ131 = invalid arguments
-- (empty name, unresolvable member email, roster cap, cannot remove owner).

-- task_list_role: owner-or-member probe. STABLE; the R1 predicate every
-- list-scoped statement embeds. NULL = no relationship (callers raise BZ130 —
-- 404-indistinguishable from nonexistence, no membership oracle).
CREATE OR REPLACE FUNCTION task_list_role(p_list_id BIGINT, p_user_id BIGINT)
RETURNS TEXT AS $$
  SELECT CASE
    WHEN EXISTS (SELECT 1 FROM task_lists WHERE id = p_list_id AND owner_user_id = p_user_id) THEN 'owner'
    WHEN EXISTS (SELECT 1 FROM task_list_members WHERE list_id = p_list_id AND user_id = p_user_id) THEN
      (SELECT role FROM task_list_members WHERE list_id = p_list_id AND user_id = p_user_id)
    END;
$$ LANGUAGE sql STABLE;

-- task_list_create: INSERT the list + the owner's own ('owner') member row (one
-- txn) — the owner is always in the roster, so fan-out/read predicates need no
-- owner special case. Does NOT call the seam: creation is only visible to the
-- owner until they add a member; their next TaskList/get sees it directly.
CREATE OR REPLACE FUNCTION task_list_create(
  p_user_id BIGINT,
  p_name    TEXT,
  p_color   TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NULLIF(btrim(COALESCE(p_name, '')), '') IS NULL THEN
    RAISE EXCEPTION 'task list name is required'
      USING ERRCODE = 'BZ131', HINT = '{"type":"invalidArguments","detail":"name is required"}';
  END IF;
  IF length(p_name) > 200 THEN
    RAISE EXCEPTION 'task list name too long'
      USING ERRCODE = 'BZ131', HINT = '{"type":"invalidArguments","detail":"name exceeds 200 chars"}';
  END IF;

  INSERT INTO task_lists (owner_user_id, name, color)
  VALUES (p_user_id, p_name, p_color)
  RETURNING id INTO v_id;

  INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id)
  VALUES (v_id, p_user_id, 'owner', p_user_id);

  RETURN jsonb_build_object('id', v_id::TEXT, 'name', p_name, 'color', p_color, 'state', '0');
END;
$$ LANGUAGE plpgsql;

-- task_list_update: rename/recolor. R3 — ownership in the same WHERE as the
-- mutation (no TOCTOU). 0 rows updated → BZ130 (no oracle: a foreign id and a
-- non-owner caller look identical).
CREATE OR REPLACE FUNCTION task_list_update(
  p_user_id BIGINT,
  p_list_id BIGINT,
  p_patch   JSONB
) RETURNS JSONB AS $$
DECLARE
  v_row task_lists%ROWTYPE;
BEGIN
  IF p_patch ? 'name' AND NULLIF(btrim(COALESCE(p_patch->>'name', '')), '') IS NULL THEN
    RAISE EXCEPTION 'task list name is required'
      USING ERRCODE = 'BZ131', HINT = '{"type":"invalidArguments","detail":"name is required"}';
  END IF;

  UPDATE task_lists SET
    name  = COALESCE(NULLIF(p_patch->>'name', ''), name),
    color = CASE WHEN p_patch ? 'color' THEN p_patch->>'color' ELSE color END,
    updated_at = now()
  WHERE id = p_list_id AND owner_user_id = p_user_id
  RETURNING * INTO v_row;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;

  PERFORM notify_task_list_state(p_list_id, 'list_updated');

  RETURN jsonb_build_object('id', v_row.id::TEXT, 'name', v_row.name, 'color', v_row.color,
                            'state', v_row.state_seq::TEXT);
END;
$$ LANGUAGE plpgsql;

-- task_list_delete: seam-push FIRST (members must hear it before the list is
-- gone), then delete (R3 ownership in the WHERE). tasks.list_id goes NULL via
-- the FK's ON DELETE SET NULL — re-personalized into their creators' mailboxes.
CREATE OR REPLACE FUNCTION task_list_delete(
  p_user_id BIGINT,
  p_list_id BIGINT
) RETURNS VOID AS $$
DECLARE
  v_deleted BIGINT;
BEGIN
  PERFORM 1 FROM task_lists WHERE id = p_list_id AND owner_user_id = p_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;

  PERFORM notify_task_list_state(p_list_id, 'list_deleted');

  DELETE FROM task_lists WHERE id = p_list_id AND owner_user_id = p_user_id
  RETURNING id INTO v_deleted;
  IF v_deleted IS NULL THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;
END;
$$ LANGUAGE plpgsql;

-- task_list_add_member: owner-only. Resolves the member's email via the shared
-- resolve_identity seam (enabled internal users only) — unresolvable → BZ131.
-- Idempotent on an existing member (returns the roster, no error). Roster is
-- capped at 200 (ponytail: raise it when a real org hits the cap — nothing in
-- Phase 1 needs a bigger number; a future admin-facing team list will).
CREATE OR REPLACE FUNCTION task_list_add_member(
  p_user_id      BIGINT,
  p_list_id      BIGINT,
  p_member_email TEXT
) RETURNS JSONB AS $$
DECLARE
  v_member_id BIGINT;
BEGIN
  IF task_list_role(p_list_id, p_user_id) IS DISTINCT FROM 'owner' THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;

  SELECT user_id INTO v_member_id FROM resolve_identity(p_member_email);
  IF v_member_id IS NULL THEN
    RAISE EXCEPTION 'member email % does not resolve to an internal user', p_member_email
      USING ERRCODE = 'BZ131', HINT = '{"type":"invalidArguments","detail":"not an internal user"}';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM task_list_members WHERE list_id = p_list_id AND user_id = v_member_id) THEN
    IF (SELECT count(*) FROM task_list_members WHERE list_id = p_list_id) >= 200 THEN
      RAISE EXCEPTION 'task list roster is full'
        USING ERRCODE = 'BZ131', HINT = '{"type":"invalidArguments","detail":"roster limit of 200 members reached"}';
    END IF;
    INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id)
    VALUES (p_list_id, v_member_id, 'member', p_user_id);
    PERFORM notify_task_list_state(p_list_id, 'member_added');
  END IF;

  RETURN task_list_get_roster(p_user_id, p_list_id);
END;
$$ LANGUAGE plpgsql;

-- task_list_remove_member: owner may remove anyone-but-the-owner-row; a member
-- may remove THEMSELVES (leave). The owner row can never be removed (BZ131 —
-- a list always keeps its owner; deleting the list is the only way to end it).
-- Seam-push BEFORE the DELETE so the leaver still gets the event.
CREATE OR REPLACE FUNCTION task_list_remove_member(
  p_user_id        BIGINT,
  p_list_id        BIGINT,
  p_member_user_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_role      TEXT;
  v_target_role TEXT;
  v_roster    JSONB;
BEGIN
  v_role := task_list_role(p_list_id, p_user_id);
  IF v_role IS NULL THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;

  IF v_role != 'owner' AND p_user_id != p_member_user_id THEN
    RAISE EXCEPTION 'only the owner may remove another member'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;

  SELECT role INTO v_target_role FROM task_list_members
  WHERE list_id = p_list_id AND user_id = p_member_user_id;
  IF v_target_role = 'owner' THEN
    RAISE EXCEPTION 'cannot remove the list owner'
      USING ERRCODE = 'BZ131', HINT = '{"type":"invalidArguments","detail":"cannot remove the owner"}';
  END IF;

  -- A member removing THEMSELVES (leave) loses their own roster row in the
  -- DELETE below, and task_list_get_roster is caller-scoped (R1): after the
  -- delete the leaver has no owner-or-member relationship left and the read
  -- would deny (BZ130) — so the leaver's view is captured while they are
  -- still a member. The owner removes someone else and keeps the post-delete
  -- roster (the removed member is gone from the returned array, as before).
  IF v_role IS DISTINCT FROM 'owner' THEN
    v_roster := task_list_get_roster(p_user_id, p_list_id);
  END IF;

  PERFORM notify_task_list_state(p_list_id, 'member_removed');

  DELETE FROM task_list_members WHERE list_id = p_list_id AND user_id = p_member_user_id;

  IF v_role = 'owner' THEN
    v_roster := task_list_get_roster(p_user_id, p_list_id);
  END IF;
  RETURN v_roster;
END;
$$ LANGUAGE plpgsql;

-- task_list_get_roster: the {userId,email,displayName,role} roster for one
-- list — shared by add_member/remove_member's return value and task_list_get.
-- R1: p_user_id (the authenticated caller, threaded from task_lists.go) scopes
-- the read twice — task_list_role gates it (NULL relationship → BZ130, the
-- 404-indistinguishable denial every other list-scoped read here uses) AND
-- the caller identity sits in the roster WHERE itself, so a caller without an
-- owner-or-member relationship can never project another list's roster no
-- matter how this helper is reached. The remove_member leave path captures
-- the roster BEFORE its DELETE for exactly this reason (a departing member's
-- own row is what the WHERE predicate keys on).
CREATE OR REPLACE FUNCTION task_list_get_roster(p_user_id BIGINT, p_list_id BIGINT)
RETURNS JSONB AS $$
DECLARE
  v_roster JSONB;
BEGIN
  IF task_list_role(p_list_id, p_user_id) IS NULL THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ130', HINT = '{"type":"notFound"}';
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'userId', m.user_id::TEXT, 'email', u.email,
      'displayName', u.display_name, 'role', m.role
    ) ORDER BY m.role, u.email), '[]'::JSONB)
  INTO v_roster
  FROM task_list_members m JOIN users u ON u.id = m.user_id
  WHERE m.list_id = p_list_id
    AND (EXISTS (SELECT 1 FROM task_lists l
                 WHERE l.id = p_list_id AND l.owner_user_id = p_user_id)
      OR EXISTS (SELECT 1 FROM task_list_members vm
                 WHERE vm.list_id = p_list_id AND vm.user_id = p_user_id));
  RETURN v_roster;
END;
$$ LANGUAGE plpgsql STABLE;

-- task_list_get: every list p_user_id owns or is a member of, with per-list
-- roster + open-task count.
CREATE OR REPLACE FUNCTION task_list_get(p_user_id BIGINT)
RETURNS JSONB AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'id', l.id::TEXT, 'name', l.name, 'color', l.color,
      'state', l.state_seq::TEXT,
      'role', task_list_role(l.id, p_user_id),
      'memberCount', (SELECT count(*) FROM task_list_members m2 WHERE m2.list_id = l.id),
      'openCount', (SELECT count(*) FROM tasks t
                    WHERE t.list_id = l.id AND t.status IN ('needs-action', 'in-progress')),
      'members', task_list_get_roster(p_user_id, l.id)
    ) ORDER BY l.name), '[]'::JSONB)
  FROM task_lists l
  WHERE l.owner_user_id = p_user_id
     OR EXISTS (SELECT 1 FROM task_list_members m WHERE m.list_id = l.id AND m.user_id = p_user_id);
$$ LANGUAGE sql STABLE;
