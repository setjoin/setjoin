CREATE OR REPLACE FUNCTION office_file_family(p_name text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path=pg_catalog,public AS $$
  SELECT CASE
    WHEN lower(p_name) ~ '\.(doc|docx|odt|rtf)$' THEN 'word'
    WHEN lower(p_name) ~ '\.(xls|xlsx|ods|csv)$' THEN 'sheet'
    WHEN lower(p_name) ~ '\.(ppt|pptx|odp)$' THEN 'presentation'
  END
$$;
SELECT apply_worker_ownership('office_file_family(text)'::regprocedure);
