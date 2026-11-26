-- system_has_users.sql — Wave 1.8C (V288, #546d)
-- Narrow pure-boolean first-boot setup predicate for the public `/` -> `/setup`
-- check (crates/domains/static/src/website.rs, bins/gateway/src/catchall.rs).
-- Under V288 FORCE RLS on public.users, unscoped setjoin_app sees 0 rows in
-- users; this worker-owned SECURITY DEFINER helper returns ONLY a single
-- boolean (EXISTS (SELECT 1 FROM public.users)) without disclosing any user row
-- or count.
CREATE OR REPLACE FUNCTION system_has_users()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM public.users);
END;
$$;

SELECT public.apply_worker_ownership('public.system_has_users()'::regprocedure);

COMMENT ON FUNCTION public.system_has_users() IS
  'First-boot setup check (Wave 1.8C, V288): pure-boolean SECURITY DEFINER '
  'helper owned by setjoin_worker so public `/` -> `/setup` detection works '
  'under FORCE RLS on public.users without disclosing any user row or count.';
