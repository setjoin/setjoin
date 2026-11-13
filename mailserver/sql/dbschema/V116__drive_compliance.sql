-- V116: Drive compliance (P5) — drive.export/drive.share approval consumers,
-- single-use export grants (G2 decide-time TTL), WORM-applied bookkeeping (G1).
-- Spec: docs/superpowers/specs/2026-07-09-drive-v1-spec.md §2.3, §3.4, §6.4.
-- Plan: docs/superpowers/plans/archive/2026-07-09-drive-P5-compliance-worm.md

-- 1. Extend the consumer_type CHECKs (the V110 drop/re-add recipe; 'drive.share'
--    was the anticipated seam — V070__approval_engine.sql:8).
ALTER TABLE public.approval_policies DROP CONSTRAINT approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies ADD CONSTRAINT approval_policies_consumer_type_check
  CHECK (consumer_type IN ('rbac.jit_activation','mail.external_send','mail.group_moderation',
                           'hr.leave','hr.expense','drive.export','drive.share'));
ALTER TABLE public.approval_requests DROP CONSTRAINT approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_consumer_type_check
  CHECK (consumer_type IN ('rbac.jit_activation','mail.external_send','mail.group_moderation',
                           'hr.leave','hr.expense','drive.export','drive.share'));

-- 2. Export grants — minted ONLY by drive_export_request (direct-allow) or
--    drive_export_approval_decide (approval path, expires_at anchored at DECIDE
--    time — G2). token_hash = sha256 hex of the one-time token; plaintext never stored.
CREATE TABLE public.drive_export_grants (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id   bigint      NOT NULL REFERENCES public.drive_file_versions(id),
    space_id     bigint      NOT NULL REFERENCES public.drive_spaces(id),
    grantee      bigint      NOT NULL REFERENCES public.users(id),
    action       text        NOT NULL CHECK (action IN ('download','print')),
    token_hash   text        NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    approval_id  bigint      REFERENCES public.approval_requests(id),  -- NULL = policy short-circuit
    minted_by    bigint      NOT NULL REFERENCES public.users(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz                                           -- single-use
);
CREATE INDEX drive_export_grants_grantee_idx ON public.drive_export_grants (grantee, expires_at);

ALTER TABLE public.drive_export_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_export_grants FORCE  ROW LEVEL SECURITY;
-- SELECT: grantee only. INSERT: minted_by = current user (the direct-allow path;
-- the approval-decide mint rides the SECURITY DEFINER wrapper). UPDATE: grantee
-- only (the consume flip; the reducer's WHERE restricts to consumed_at NULL->now()).
-- DELETE: none — the maintenance sweep prunes on the BYPASSRLS worker pool.
CREATE POLICY drive_export_grants_grantee_read ON public.drive_export_grants
  FOR SELECT TO public
  USING (grantee = (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint));
CREATE POLICY drive_export_grants_mint ON public.drive_export_grants
  FOR INSERT TO public
  WITH CHECK (minted_by = (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint));
CREATE POLICY drive_export_grants_consume ON public.drive_export_grants
  FOR UPDATE TO public
  USING (grantee = (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint))
  WITH CHECK (grantee = (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint));

-- 3. WORM bookkeeping (G1 wormPending is DERIVED, no queue table): retain_until
--    is the reducer-set TARGET; worm_applied_until is what storage CONFIRMED.
--    Pending <=> retain_until IS NOT NULL AND (worm_applied_until IS NULL OR
--    worm_applied_until < retain_until). Written only on the worker pool.
ALTER TABLE public.drive_chunks ADD COLUMN worm_applied_until timestamptz;
CREATE INDEX drive_chunks_worm_pending_idx ON public.drive_chunks (scope_key)
  WHERE retain_until IS NOT NULL
    AND (worm_applied_until IS NULL OR worm_applied_until < retain_until);

INSERT INTO schema_migrations (version, applied_at) VALUES (116, now())
ON CONFLICT (version) DO NOTHING;
