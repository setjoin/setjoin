-- rust_identity_client_version.sql — optional client_versions lookup for /api/v1/version.
-- The active mailserver schema omits the legacy client_versions table; conformance tests
-- create and drop it dynamically. Checking to_regclass keeps the typed SQL contract valid
-- against the canonical schema while preserving Go's up_to_date fallback when absent.

CREATE OR REPLACE FUNCTION rust_identity_client_version_latest(
  p_platform text,
  p_app text
) RETURNS TABLE(
  version text,
  sha256 text,
  release_notes text,
  file_path text,
  release_date timestamptz
)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF to_regclass('public.client_versions') IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY EXECUTE
    'SELECT version, sha256, COALESCE(release_notes, ''''), COALESCE(file_path, ''''), release_date
       FROM public.client_versions
      WHERE platform = $1 AND app = $2
      ORDER BY string_to_array(version, ''.'')::int[] DESC
      LIMIT 1'
    USING p_platform, p_app;
END;
$$;
