-- V191__drive_acl_compatibility_grants.sql
-- ACL-mode calls to the historical ?folder= member endpoint are represented
-- as scoped grants, never as whole-space membership.  The source tag keeps
-- later cleanup and audit deterministic without changing effective-access
-- semantics.

ALTER TABLE public.drive_acl_grants
  DROP CONSTRAINT drive_acl_grants_source_check,
  ADD CONSTRAINT drive_acl_grants_source_check CHECK (
    source IN ('direct','group','legacy_folder_admin','approval','emergency',
               'compat_folder_member')
  );

CREATE UNIQUE INDEX drive_acl_grants_compat_folder_active_uniq
  ON public.drive_acl_grants(node_id,subject_user_id)
  WHERE source='compat_folder_member' AND state='active';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (191, now())
ON CONFLICT(version) DO NOTHING;
