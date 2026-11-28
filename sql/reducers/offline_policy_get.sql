-- offline_policy_get.sql
-- Admin read of one offline_policies row as JSONB. Org table; handler RBAC.
CREATE OR REPLACE FUNCTION offline_policy_get(p_id BIGINT) RETURNS JSONB AS $$
    SELECT to_jsonb(p) FROM offline_policies p WHERE p.id = p_id;
$$ LANGUAGE sql STABLE;
