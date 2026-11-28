-- F10 Rust parity: Go's priority read plus INSERT, in one data transaction.
-- Frozen Go writes the policy audit separately, best effort, after commit.
-- Policies are global; a live authenticated approvals.manage grant is the
-- same-statement ownership/authority fence even on an owner credential.
CREATE OR REPLACE FUNCTION rust_approval_policy_create(p_actor bigint, p_body jsonb)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
  v_priority integer;
  v_id bigint;
BEGIN
  SELECT COALESCE(MAX(p.priority),0) INTO v_priority
    FROM approval_policies p
   WHERE p.consumer_type=p_body->>'consumerType'
     AND EXISTS (SELECT 1 FROM public.admin_role_assignments a
       JOIN public.admin_role_groups g ON g.id=a.role_group_id
       WHERE a.user_id=p_actor AND (a.expires_at IS NULL OR a.expires_at>now())
         AND public.admin_assignment_active(a.eligible,a.activated_until)
         AND 'approvals.manage'=ANY(g.permissions));
  INSERT INTO approval_policies
    (consumer_type,name,enabled,priority,conditions,requires_approval,approver_spec)
  SELECT p_body->>'consumerType',p_body->>'name',
         COALESCE((p_body->>'enabled')::boolean,false),v_priority+1,
         p_body->'conditions',COALESCE((p_body->>'requiresApproval')::boolean,false),
         p_body->'approverSpec'
   WHERE EXISTS (SELECT 1 FROM public.admin_role_assignments a
       JOIN public.admin_role_groups g ON g.id=a.role_group_id
       WHERE a.user_id=p_actor AND (a.expires_at IS NULL OR a.expires_at>now())
         AND public.admin_assignment_active(a.eligible,a.activated_until)
         AND 'approvals.manage'=ANY(g.permissions))
  RETURNING id INTO v_id;
  IF v_id IS NULL THEN
    RAISE EXCEPTION 'approvals.manage required' USING ERRCODE='42501';
  END IF;
  RETURN v_id;
END;
$$;
