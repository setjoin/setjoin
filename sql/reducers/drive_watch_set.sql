-- mailserver/sql/reducers/drive_watch_set.sql
-- journal, no audit (spec §6.2). Any member may watch a node they can see;
-- editor+ is not required (mirrors drive_watches_own_write's RLS shape).
CREATE OR REPLACE FUNCTION drive_watch_set(
  p_user_id BIGINT, p_node_id BIGINT, p_ops TEXT[] DEFAULT NULL
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_op TEXT;
BEGIN
  SELECT space_id INTO v_space FROM drive_nodes WHERE id = p_node_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  IF NOT public.drive_runtime_has_node_capability(p_user_id,p_node_id,'read_metadata') THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF p_ops IS NOT NULL THEN
    FOREACH v_op IN ARRAY p_ops LOOP
      IF v_op NOT IN ('create','update','move','rename','trash','restore','destroy',
                      'member','space','branch','lock') THEN
        RAISE EXCEPTION 'unknown watch op class %', v_op USING ERRCODE='BZ141',
          HINT='{"type":"invalidArguments","detail":"unknown watch op class"}';
      END IF;
    END LOOP;
  END IF;
  INSERT INTO drive_watches (node_id, user_id, ops) VALUES (p_node_id, p_user_id, p_ops)
  ON CONFLICT (node_id, user_id) DO UPDATE SET ops = EXCLUDED.ops;
END;
$$ LANGUAGE plpgsql;
