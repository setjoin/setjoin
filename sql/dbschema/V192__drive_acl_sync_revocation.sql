-- V192__drive_acl_sync_revocation.sql
-- A7 gives managed clients an opaque access-invalidation cursor and makes
-- export revocation explicit.  The monotonic bigint remains server-internal;
-- clients persist only scan_token.

ALTER TABLE public.drive_access_invalidations
  ADD COLUMN scan_token uuid NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX drive_access_invalidations_scan_token_uniq
  ON public.drive_access_invalidations(scan_token);

ALTER TABLE public.drive_export_grants
  ADD COLUMN revoked_at timestamptz,
  ADD COLUMN revoked_reason text,
  ADD CONSTRAINT drive_export_grants_revocation_shape CHECK (
    (revoked_at IS NULL AND revoked_reason IS NULL)
    OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL
        AND octet_length(revoked_reason) BETWEEN 1 AND 200)
  );
CREATE INDEX drive_export_grants_live_idx
  ON public.drive_export_grants(grantee,space_id,expires_at)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (192, now())
ON CONFLICT(version) DO NOTHING;
