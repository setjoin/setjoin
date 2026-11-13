CREATE OR REPLACE FUNCTION identity_mailbox_invariant_snapshot(p_user_id bigint)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT jsonb_build_object(
    'userId',p_user_id::text,
    'mailboxes',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'id',m.id::text,'email',lower(m.email),'primary',m.is_primary,'type',m.type
    ) ORDER BY m.id) FROM mailboxes m WHERE m.user_id=p_user_id),'[]'::jsonb),
    'addressClaims',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'address',c.normalized_address,'mailboxId',c.mailbox_id::text,'state',c.claim_state
    ) ORDER BY c.normalized_address,c.mailbox_id) FROM mailbox_address_claims c
      JOIN mailboxes m ON m.id=c.mailbox_id WHERE m.user_id=p_user_id),'[]'::jsonb)
  )
$$;

ALTER FUNCTION identity_mailbox_invariant_snapshot(bigint) OWNER TO setjoin_worker;
