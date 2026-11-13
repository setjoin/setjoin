-- V193__drive_space_owner_self_seed.sql
-- Preserve the owner self-seed window while Drive space discovery delegates to
-- the canonical STABLE access function.  INSERT ... RETURNING evaluates the
-- SELECT policy in the inserting statement's snapshot, so that function cannot
-- see the new row until the statement completes.  The direct owner predicate
-- is deliberately narrow and matches the INSERT policy; membership remains the
-- durable authority after drive_space_create seeds the manager row.

DROP POLICY IF EXISTS drive_spaces_read ON public.drive_spaces;
CREATE POLICY drive_spaces_read ON public.drive_spaces FOR SELECT TO public
  USING (
    owner_user_id = (
      SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
    OR public.drive_user_has_space_access(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      id
    )
  );

INSERT INTO public.schema_migrations (version, applied_at) VALUES (193, now())
ON CONFLICT(version) DO NOTHING;
