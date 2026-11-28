-- Frozen Go's MDMHandler.ReorderPolicies: one UPDATE per listed id in list order,
-- the first id taking the highest priority (cardinality, then one lower per id),
-- as one transaction. Unknown ids update nothing and a repeated id is written
-- twice, the later position winning. No audit row and no notify, as in Go.
CREATE OR REPLACE FUNCTION rust_mdm_policy_reorder(p_ids bigint[])
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 FOR i IN 1..COALESCE(cardinality(p_ids), 0) LOOP
  UPDATE mdm_policies SET priority = cardinality(p_ids) - i + 1, updated_at = now() WHERE id = p_ids[i];
 END LOOP;
 RETURN jsonb_build_object('status', 200);
END;
$$;
