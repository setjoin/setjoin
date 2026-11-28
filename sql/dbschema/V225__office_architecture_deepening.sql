-- V225: crash-resumable managed Office execution and revision-bound qualification.
-- Expand-only. All affected product behavior remains default OFF.

ALTER TABLE public.office_app_operations
  ADD COLUMN lease_expires_at timestamptz,
  ADD COLUMN last_heartbeat_at timestamptz;

-- V224 had no reclaim protocol. Any active row present during the upgrade is
-- deliberately made reclaimable; the new executor must inventory host effects.
UPDATE public.office_app_operations
   SET lease_expires_at=statement_timestamp()-interval '1 second',
       last_heartbeat_at=COALESCE(claimed_at,updated_at)
 WHERE state IN ('claimed','preflight','pulling','verifying','staging','starting',
                 'qualifying','disabling_launches','draining','blocked_drain',
                 'rolling_back','paused_recoverable');

ALTER TABLE public.office_app_operations
  ADD CONSTRAINT office_app_operations_lease_shape_check CHECK (
    (state='requested' AND executor_id IS NULL AND lease_id IS NULL
      AND lease_expires_at IS NULL AND last_heartbeat_at IS NULL)
    OR state IN ('connected_inactive','rolled_back','retention_pending','removed',
                 'failed_terminal','cancelled')
    OR (executor_id IS NOT NULL AND lease_id IS NOT NULL
      AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL
      AND lease_expires_at>last_heartbeat_at)
  );

ALTER TABLE public.office_app_revisions
  ADD COLUMN created_by_operation_id uuid
    REFERENCES public.office_app_operations(id) ON DELETE RESTRICT,
  ADD CONSTRAINT office_app_revisions_operation_unique UNIQUE(created_by_operation_id);

ALTER TABLE public.office_provider_qualifications
  ADD COLUMN app_revision_id uuid
    REFERENCES public.office_app_revisions(id) ON DELETE RESTRICT;

ALTER TABLE public.office_app_revisions DROP CONSTRAINT office_app_revisions_state_check;
ALTER TABLE public.office_app_revisions ADD CONSTRAINT office_app_revisions_state_check
  CHECK (state IN ('absent','staged','installed_inactive','qualified','active','previous',
                   'retention_pending','removed','failed'));

DROP INDEX public.office_app_operations_one_active_uniq;
CREATE UNIQUE INDEX office_app_operations_one_active_uniq
  ON public.office_app_operations(app_id)
  WHERE state IN ('requested','claimed','preflight','pulling','verifying','staging',
                  'starting','qualifying','disabling_launches','draining',
                  'blocked_drain','rolling_back','paused_recoverable');

INSERT INTO public.schema_migrations(version,applied_at) VALUES (225,now())
ON CONFLICT (version) DO NOTHING;
