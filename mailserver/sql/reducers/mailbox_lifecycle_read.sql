-- Mailbox Lifecycle & Retention authority: mailbox_lifecycle_read.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_read(p_mailbox_id bigint)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT jsonb_build_object(
    'mailboxId',l.mailbox_id::text,'binding',l.binding_state,
    'access',l.access_state,'delivery',l.delivery_state,
    'boundUserId',CASE WHEN l.bound_user_id IS NULL THEN NULL ELSE l.bound_user_id::text END,
    'generation',l.generation::text,'policyGeneration',l.policy_generation::text,
    'retainedAt',l.retained_at,'retentionUntil',l.retention_until,
    'redirectAddress',l.redirect_address,'reason',l.reason,
    'updatedAt',l.updated_at)
  FROM mailbox_lifecycle l WHERE l.mailbox_id=p_mailbox_id
$$;

ALTER FUNCTION mailbox_lifecycle_read(bigint) OWNER TO setjoin_worker;
