-- RunPrune ignores pgx Rows.Err: a function execution error rolls back all
-- pruning but returns HTTP 200 [] in Go. Preserve that at the reducer boundary.
CREATE OR REPLACE FUNCTION rust_compliance_log_prune(p_actor bigint)
RETURNS TABLE(pruned_table text,rows_deleted integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 IF p_actor<=0 OR p_actor IS NULL THEN RETURN; END IF;
 RETURN QUERY SELECT p.pruned_table,p.rows_deleted FROM prune_log_tables() p;
EXCEPTION WHEN OTHERS THEN
 RETURN;
END;
$$;
