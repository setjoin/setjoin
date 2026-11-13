-- smime_journal_cert.sql — SP1 Phase 3: the two domain lookups the
-- EmailSubmission/set encrypt pass uses to enforce encrypt-to-journal.
--
-- EXCEPTION to "one reducer per file": both functions are tiny lookups for the
-- SAME feature (the journal-cert enforcement surface) and share no other home —
-- grouped here the way deliver_group_vacation.sql groups its related reducers.

-- journaling_required_for_domain: TRUE iff an ENABLED journaling_policies row
-- matches the domain (its own row OR the deployment-wide NULL-domain fallback)
-- in the outbound direction ('outbound' or 'both'). This mirrors the precedence
-- journal_if_policy_matches() applies for outbound mail: when a policy WOULD
-- journal this send, the journal copy must also be encryptable.
CREATE OR REPLACE FUNCTION journaling_required_for_domain(p_domain_id BIGINT)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM journaling_policies
    WHERE enabled = TRUE
      AND direction IN ('outbound', 'both')
      AND (domain_id = p_domain_id OR domain_id IS NULL)
  );
$$ LANGUAGE sql STABLE;

-- journal_cert_pem_for_domain: the currently-valid journal cert PEM for the
-- domain, or NULL if none. A domain-specific row wins over the deployment-wide
-- (NULL-domain) row; among same-scope rows the latest-expiring wins. Validity is
-- now() ∈ [not_before, not_after] (open-ended bounds treated as infinite). NULL
-- return = "no usable journal cert" → the caller fails closed.
CREATE OR REPLACE FUNCTION journal_cert_pem_for_domain(p_domain_id BIGINT)
RETURNS TEXT AS $$
  SELECT cert_pem FROM smime_journal_certs
  WHERE (domain_id = p_domain_id OR domain_id IS NULL)
    AND now() BETWEEN COALESCE(not_before, '-infinity'::timestamptz)
                  AND COALESCE(not_after,  'infinity'::timestamptz)
  ORDER BY (domain_id IS NOT NULL) DESC, not_after DESC NULLS LAST
  LIMIT 1;
$$ LANGUAGE sql STABLE;
