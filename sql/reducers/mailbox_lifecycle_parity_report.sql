-- Mailbox Lifecycle & Retention shadow parity. This report is read-only and
-- bounded: exact counts plus at most 25 opaque mailbox/address examples.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_parity_report()
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
WITH expected_addresses AS (
  SELECT lower(email) address,id mailbox_id,'primary' kind FROM mailboxes
  UNION ALL
  SELECT lower(email),mailbox_id,'alias' FROM aliases
), unique_addresses AS (
  SELECT address,min(mailbox_id) mailbox_id,min(kind) kind
  FROM expected_addresses GROUP BY address HAVING count(DISTINCT mailbox_id)=1
), problems AS (
  SELECT 'missing_lifecycle' kind,m.id::text sample
  FROM mailboxes m LEFT JOIN mailbox_lifecycle l ON l.mailbox_id=m.id
  WHERE l.mailbox_id IS NULL
  UNION ALL
  SELECT 'legacy_state_mismatch',m.id::text
  FROM mailboxes m JOIN mailbox_lifecycle l ON l.mailbox_id=m.id
  WHERE NOT mailbox_lifecycle_enabled() AND (
    l.access_state<>CASE WHEN m.enabled THEN 'active' ELSE 'suspended' END OR
    l.delivery_state<>CASE WHEN m.receive_enabled THEN 'accepting' ELSE 'rejecting' END OR
    l.binding_state<>CASE WHEN m.user_id IS NULL THEN 'shared' ELSE 'bound' END OR
    l.bound_user_id IS DISTINCT FROM m.user_id)
  UNION ALL
  SELECT 'missing_or_wrong_address_claim',encode(digest(u.address,'sha256'),'hex')
  FROM unique_addresses u LEFT JOIN mailbox_address_claims c ON c.normalized_address=u.address
  WHERE c.normalized_address IS NULL OR c.mailbox_id<>u.mailbox_id OR c.address_kind<>u.kind OR c.claim_state='released'
  UNION ALL
  SELECT 'unexpected_address_claim',encode(digest(c.normalized_address,'sha256'),'hex')
  FROM mailbox_address_claims c LEFT JOIN expected_addresses e
    ON e.address=c.normalized_address AND e.mailbox_id=c.mailbox_id
  WHERE c.claim_state<>'released' AND e.address IS NULL
  UNION ALL
  SELECT 'recorded_conflict',encode(digest(normalized_address,'sha256'),'hex')
  FROM mailbox_lifecycle_conflicts WHERE resolved_at IS NULL
), counts AS (
  SELECT kind,count(*) count FROM problems GROUP BY kind
)
SELECT jsonb_build_object(
  'schemaVersion',1,
  'featureEnabled',mailbox_lifecycle_enabled(),
  'eligible',NOT EXISTS(SELECT 1 FROM problems),
  'mailboxes',(SELECT count(*) FROM mailboxes),
  'lifecycleRows',(SELECT count(*) FROM mailbox_lifecycle),
  'addressClaims',(SELECT count(*) FROM mailbox_address_claims WHERE claim_state<>'released'),
  'problems',COALESCE((SELECT jsonb_object_agg(kind,count ORDER BY kind) FROM counts),'{}'::jsonb),
  'samples',COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',kind,'opaque',sample) ORDER BY kind,sample)
    FROM (SELECT kind,sample FROM problems ORDER BY kind,sample LIMIT 25) s),'[]'::jsonb)
)
$$;

ALTER FUNCTION mailbox_lifecycle_parity_report() OWNER TO setjoin_worker;
