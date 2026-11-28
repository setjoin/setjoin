-- scim_token_lookup: indexed single-candidate SCIM bearer-token lookup.
-- The gateway hashes the presented raw token (lowercase hex SHA-256) and
-- resolves AT MOST ONE candidate row through the partial unique index on
-- scim_tokens.token_lookup_hash (V238), then bcrypt-compares the returned
-- token_hash — the lookup key narrows the candidate, bcrypt remains the
-- verifier. Legacy tokens minted before V238 (token_lookup_hash IS NULL) never
-- match here; they keep verifying through the scim_list_active_tokens()
-- bcrypt-scan fallback until rotated.

CREATE OR REPLACE FUNCTION scim_token_lookup(p_lookup_hash TEXT)
RETURNS TABLE(
  token_id          BIGINT,
  name              TEXT,
  token_hash        TEXT,
  deletion_policy   TEXT,
  attribute_mapping JSONB,
  source_id         BIGINT,
  source_generation BIGINT
) AS $$
  SELECT st.id, st.name, st.token_hash, st.deletion_policy,
         st.attribute_mapping, st.source_id, src.generation
    FROM scim_tokens st
    JOIN identity_sources src ON src.id = st.source_id
   WHERE st.token_lookup_hash = p_lookup_hash
     AND st.revoked_at IS NULL
     AND src.kind = 'scim' AND src.state = 'active'
     AND (st.expires_at IS NULL OR st.expires_at > now())
$$ LANGUAGE sql STABLE;

SELECT apply_worker_ownership(
    'scim_token_lookup(text)'::regprocedure
);
