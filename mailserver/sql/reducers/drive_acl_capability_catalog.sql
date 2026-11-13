CREATE OR REPLACE FUNCTION drive_acl_capability_catalog()
RETURNS TEXT[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT ARRAY[
    'traverse', 'list_children', 'read_metadata', 'preview', 'download',
    'create_child', 'modify_content', 'rename', 'move', 'delete',
    'manage_acl', 'view_audit'
  ]::text[]
$$;
SELECT apply_worker_ownership('drive_acl_capability_catalog()'::regprocedure);
