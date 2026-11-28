-- Frozen Go's DepartmentsHandler.AssignUser after the edge validation: the reach check
-- on the target user, the department existence and OU-scope checks and the users
-- UPDATE, as one transaction. Returns {status,detail}: 204 (also for an unknown user
-- the actor can reach), 403 or 400 (department not found). A non-positive department
-- clears the assignment.
CREATE OR REPLACE FUNCTION rust_admin_department_assign_user(
 p_actor bigint,p_user bigint,p_dept bigint,p_grant_domain bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_reach boolean; v_ok boolean; v_dept bigint;
BEGIN
 SELECT admin_can_reach_perm(p_actor,p_user,ARRAY['users.create']) INTO v_reach; -- #510: reach through a users.create grant only
 IF v_reach IS NOT TRUE THEN
  RETURN jsonb_build_object('status',403,'detail','target user not within your administrative scope');
 END IF;
 IF p_dept IS NOT NULL AND p_dept > 0 THEN
  IF NOT EXISTS(SELECT 1 FROM departments WHERE id = p_dept) THEN
   RETURN jsonb_build_object('status',400,'detail','department not found');
  END IF;
  SELECT admin_scope_within(p_actor,'ou',p_dept,p_grant_domain) INTO v_ok;
  IF v_ok IS NOT TRUE THEN
   RETURN jsonb_build_object('status',403,'detail','target department not within your administrative scope');
  END IF;
  v_dept := p_dept;
 END IF;
 UPDATE users SET department_id = v_dept WHERE id = p_user;
 RETURN jsonb_build_object('status',204);
END;
$$;
