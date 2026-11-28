-- Frozen-Go policy delete; live authority stays in the mutation predicate.
CREATE OR REPLACE FUNCTION rust_approval_policy_delete(p_actor bigint,p_id bigint)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_count bigint;
BEGIN
 DELETE FROM approval_policies WHERE id=p_id AND EXISTS (SELECT 1 FROM public.admin_role_assignments a
      JOIN public.admin_role_groups g ON g.id=a.role_group_id
      WHERE a.user_id=p_actor AND (a.expires_at IS NULL OR a.expires_at>now())
        AND public.admin_assignment_active(a.eligible,a.activated_until)
        AND 'approvals.manage'=ANY(g.permissions));
 GET DIAGNOSTICS v_count=ROW_COUNT;
 RETURN v_count;
END;
$$;
