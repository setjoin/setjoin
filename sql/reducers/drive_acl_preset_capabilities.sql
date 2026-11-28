CREATE OR REPLACE FUNCTION drive_acl_preset_capabilities(p_preset TEXT)
RETURNS TEXT[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT CASE p_preset
    WHEN 'viewer' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download'
    ]::text[]
    WHEN 'contributor' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content'
    ]::text[]
    WHEN 'editor' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete'
    ]::text[]
    WHEN 'folder_manager' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete',
      'manage_acl','view_audit'
    ]::text[]
    ELSE NULL
  END
$$;
SELECT apply_worker_ownership('drive_acl_preset_capabilities(TEXT)'::regprocedure);
