-- mailserver/sql/reducers/drive_watch_remove.sql
CREATE OR REPLACE FUNCTION drive_watch_remove(
  p_user_id BIGINT, p_node_id BIGINT
) RETURNS VOID AS $$
BEGIN
  DELETE FROM drive_watches WHERE node_id = p_node_id AND user_id = p_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'watch not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"watch not found"}';
  END IF;
END;
$$ LANGUAGE plpgsql;
