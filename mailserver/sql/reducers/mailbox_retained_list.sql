-- Mailbox Lifecycle & Retention authority: bounded retained-mailbox inventory.

CREATE OR REPLACE FUNCTION mailbox_retained_list(
  p_actor bigint,
  p_domain_scope bigint DEFAULT 0,
  p_limit integer DEFAULT 200
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_limit integer:=LEAST(GREATEST(COALESCE(p_limit,200),1),500);
BEGIN
  IF NOT EXISTS(
    SELECT 1 FROM admin_role_assignments a
    WHERE a.user_id=p_actor
      AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
  ) THEN
    RAISE EXCEPTION 'retained mailbox inventory is unavailable' USING ERRCODE='BZ302';
  END IF;

  RETURN COALESCE((
    SELECT jsonb_agg(item ORDER BY retained_at DESC,mailbox_id DESC)
    FROM (
      SELECT l.retained_at,l.mailbox_id,jsonb_build_object(
        'mailboxId',l.mailbox_id::text,
        'email',m.email,
        'displayName',m.display_name,
        'generation',l.generation::text,
        'access',l.access_state,
        'delivery',l.delivery_state,
        'retainedAt',l.retained_at,
        'retentionUntil',l.retention_until,
        'addresses',COALESCE((
          SELECT jsonb_agg(c.normalized_address ORDER BY c.normalized_address)
          FROM mailbox_address_claims c
          WHERE c.mailbox_id=m.id AND c.claim_state='retained'
        ),'[]'::jsonb),
        'pendingEffects',(
          SELECT count(*) FROM mailbox_lifecycle_effects e
          WHERE e.mailbox_id=m.id AND e.state IN ('pending','claimed','failed')
        ),
        'purge',(
          SELECT jsonb_build_object(
            'purgeRequestId',p.id::text,'state',p.state,
            'eligibleAt',p.eligible_at,'approvalRequestId',p.approval_request_id::text,
            'approvedBy',CASE WHEN p.approved_by IS NULL THEN NULL ELSE p.approved_by::text END,
            'attempts',p.attempts,'blockers',p.blocker_snapshot
          )
          FROM mailbox_purge_requests p
          WHERE p.mailbox_id=m.id
          ORDER BY p.requested_at DESC LIMIT 1
        )
      ) item
      FROM mailbox_lifecycle l
      JOIN mailboxes m ON m.id=l.mailbox_id
      WHERE l.binding_state='retained'
        AND (p_domain_scope=0 OR m.domain_id=p_domain_scope)
        AND (
          EXISTS(SELECT 1 FROM admin_role_assignments a
            WHERE a.user_id=p_actor AND a.role_group_id=1
              AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp()))
          OR p_domain_scope<>0
        )
      ORDER BY l.retained_at DESC,l.mailbox_id DESC
      LIMIT v_limit
    ) rows
  ),'[]'::jsonb);
END $$;

ALTER FUNCTION mailbox_retained_list(bigint,bigint,integer) OWNER TO setjoin_worker;
