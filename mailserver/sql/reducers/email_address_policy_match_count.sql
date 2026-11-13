-- email_address_policy_match_count: COUNT of policy-enabled recipients matching
-- the given conditions (same predicate as the apply matcher; conditions are the
-- INPUT here, not a policy row). Powers the admin "matches N recipients" badge.
CREATE OR REPLACE FUNCTION email_address_policy_match_count(
  p_dept TEXT[], p_domain_ids BIGINT[], p_mtype TEXT[], p_ad_ou TEXT[]
) RETURNS INTEGER LANGUAGE sql STABLE AS $$
  SELECT count(*)::int
    FROM mailboxes m
    JOIN users u ON u.id = m.user_id
    LEFT JOIN departments d ON d.id = u.department_id
   WHERE m.is_primary AND u.address_policy_enabled
     AND (p_dept       IS NULL OR d.name = ANY(p_dept))
     AND (p_domain_ids IS NULL OR m.domain_id = ANY(p_domain_ids))
     AND (p_mtype      IS NULL OR mailbox_effective_type(m.id) = ANY(p_mtype))
     AND (p_ad_ou      IS NULL OR d.ldap_ou = ANY(p_ad_ou));
$$;
