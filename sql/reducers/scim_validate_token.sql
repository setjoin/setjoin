-- scim_validate_token: Return the active (non-revoked, non-expired) SCIM tokens
-- that lack an indexed lookup key — the legacy pre-V238 rows only. These are the
-- sole rows the gateway still verifies with the bcrypt scan over token_hash
-- values; every V238+ token carries token_lookup_hash and authenticates through
-- the single-row scim_token_lookup() path. The scan therefore shrinks to zero
-- rows as legacy tokens rotate, without breaking any provisioned token.

DROP FUNCTION IF EXISTS scim_list_active_tokens();
CREATE OR REPLACE FUNCTION scim_list_active_tokens()
RETURNS TABLE(
  token_id          BIGINT,
  name              TEXT,
  token_hash        TEXT,
  deletion_policy   TEXT,
  attribute_mapping JSONB,
  source_id         BIGINT,
  source_generation BIGINT
) AS $$
BEGIN
  RETURN QUERY
    SELECT st.id, st.name, st.token_hash, st.deletion_policy,
           st.attribute_mapping, st.source_id, src.generation
    FROM scim_tokens st
    JOIN identity_sources src ON src.id=st.source_id
    WHERE st.revoked_at IS NULL
      AND st.token_lookup_hash IS NULL
      AND src.kind='scim' AND src.state='active'
      AND (st.expires_at IS NULL OR st.expires_at > now())
    ORDER BY st.id;
END;
$$ LANGUAGE plpgsql STABLE;

-- scim_record_token_usage: Update last_used_at for a SCIM token.
CREATE OR REPLACE FUNCTION scim_record_token_usage(p_token_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE scim_tokens SET last_used_at = now() WHERE id = p_token_id;
END;
$$ LANGUAGE plpgsql;

-- (scim_validate_token removed: dead code. Production SCIM auth uses
-- scim_list_active_tokens() + a bcrypt compare in Go (scim/server.go), then
-- scim_record_token_usage. The deleted function did a plaintext token_hash equality
-- check — a divergent, bcrypt-bypassing model that only invited a future caller to
-- wire the insecure path. Its sole reference was its own pgTAP assertion.)
