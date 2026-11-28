-- Go's two-pass reorder, scoped by consumer and current governed authority.
CREATE OR REPLACE FUNCTION rust_approval_policy_reorder(p_actor bigint,p_body jsonb)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_id bigint; v_ord bigint;
BEGIN
 FOR v_id,v_ord IN SELECT value::text::bigint,ordinality FROM jsonb_array_elements(COALESCE(NULLIF(p_body->'orderedIds','null'::jsonb),'[]')) WITH ORDINALITY LOOP
  UPDATE approval_policies SET priority=-v_ord
   WHERE id=v_id AND consumer_type=p_body->>'consumerType' AND EXISTS (SELECT 1 FROM public.admin_role_assignments a
      JOIN public.admin_role_groups g ON g.id=a.role_group_id
      WHERE a.user_id=p_actor AND (a.expires_at IS NULL OR a.expires_at>now())
        AND public.admin_assignment_active(a.eligible,a.activated_until)
        AND 'approvals.manage'=ANY(g.permissions));
 END LOOP;
 FOR v_id,v_ord IN SELECT value::text::bigint,ordinality FROM jsonb_array_elements(COALESCE(NULLIF(p_body->'orderedIds','null'::jsonb),'[]')) WITH ORDINALITY LOOP
  UPDATE approval_policies SET priority=v_ord,updated_at=now()
   WHERE id=v_id AND consumer_type=p_body->>'consumerType' AND EXISTS (SELECT 1 FROM public.admin_role_assignments a
      JOIN public.admin_role_groups g ON g.id=a.role_group_id
      WHERE a.user_id=p_actor AND (a.expires_at IS NULL OR a.expires_at>now())
        AND public.admin_assignment_active(a.eligible,a.activated_until)
        AND 'approvals.manage'=ANY(g.permissions));
 END LOOP;
 RETURN 1;
END;
$$;
