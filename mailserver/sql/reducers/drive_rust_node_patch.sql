-- Frozen Go patchNode composes these existing mutations in one transaction.
CREATE OR REPLACE FUNCTION drive_rust_node_patch(
  p_user_id BIGINT, p_node_id BIGINT,
  p_rename BOOLEAN, p_new_name TEXT, p_move BOOLEAN, p_new_parent_id BIGINT
) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  IF p_rename THEN
    PERFORM drive_node_rename(p_user_id,p_node_id,p_new_name);
  END IF;
  IF p_move THEN
    PERFORM drive_node_move(p_user_id,p_node_id,p_new_parent_id);
  END IF;
END;
$$;
