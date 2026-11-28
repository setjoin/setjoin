-- offline_policy_list.sql
-- Admin read of all offline_policies rows as a JSONB array (priority DESC,
-- highest-priority first to match the resolver's ordering). Org table.
CREATE OR REPLACE FUNCTION offline_policy_list() RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.priority DESC), '[]'::jsonb)
      FROM offline_policies p;
$$ LANGUAGE sql STABLE;
