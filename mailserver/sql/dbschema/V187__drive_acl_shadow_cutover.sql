-- V187__drive_acl_shadow_cutover.sql
-- Bounded, metadata-only legacy/canonical comparison and explicit cutover
-- evidence. No space changes mode in this migration.

CREATE TABLE public.drive_acl_shadow_state (
  space_id          bigint PRIMARY KEY REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  started_at        timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  comparisons       bigint NOT NULL DEFAULT 0 CHECK (comparisons>=0),
  matches           bigint NOT NULL DEFAULT 0 CHECK (matches>=0),
  widenings         bigint NOT NULL DEFAULT 0 CHECK (widenings>=0),
  narrowings        bigint NOT NULL DEFAULT 0 CHECK (narrowings>=0),
  last_compared_at  timestamptz,
  CONSTRAINT drive_acl_shadow_window CHECK (
    expires_at>started_at AND expires_at<=started_at+interval '28 days'
  )
);

CREATE TABLE public.drive_acl_shadow_mismatches (
  space_id          bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  user_id           bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  node_id           bigint NOT NULL REFERENCES public.drive_nodes(id) ON DELETE CASCADE,
  mismatch_kind     text NOT NULL CHECK (mismatch_kind IN ('widening','narrowing','both')),
  legacy_digest     text NOT NULL CHECK (legacy_digest~'^[0-9a-f]{64}$'),
  canonical_digest  text NOT NULL CHECK (canonical_digest~'^[0-9a-f]{64}$'),
  occurrence_count  bigint NOT NULL DEFAULT 1 CHECK (occurrence_count>0),
  first_seen_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at      timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,
  classification    text CHECK (classification IN (
    'legacy_defect','canonical_defect','fixture_defect','reviewed_semantic_change'
  )),
  classified_by     bigint REFERENCES public.users(id) ON DELETE SET NULL,
  classified_at     timestamptz,
  classification_reason text CHECK (
    classification_reason IS NULL OR length(classification_reason) BETWEEN 8 AND 1000
  ),
  PRIMARY KEY(space_id,user_id,node_id),
  CONSTRAINT drive_acl_shadow_classification_shape CHECK (
    (classification IS NULL AND classified_by IS NULL AND classified_at IS NULL
       AND classification_reason IS NULL)
    OR (classification IS NOT NULL AND classified_by IS NOT NULL
       AND classified_at IS NOT NULL AND classification_reason IS NOT NULL)
  )
);
CREATE INDEX drive_acl_shadow_mismatches_open_idx
  ON public.drive_acl_shadow_mismatches(space_id,mismatch_kind,last_seen_at)
  WHERE resolved_at IS NULL;

CREATE TABLE public.drive_acl_cutover_evidence (
  space_id              bigint PRIMARY KEY REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  deterministic_passed  boolean NOT NULL,
  ubuntu_passed         boolean NOT NULL,
  zero_open_mismatches  boolean NOT NULL,
  evidence_digest       text NOT NULL CHECK (evidence_digest~'^[0-9a-f]{64}$'),
  recorded_by           bigint NOT NULL REFERENCES public.users(id),
  recorded_at           timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz NOT NULL,
  CHECK (expires_at>recorded_at AND expires_at<=recorded_at+interval '7 days')
);

-- Keep these declarations literal: the RLS coverage guards derive their
-- inventory from migration source and must see every table independently.
ALTER TABLE public.drive_acl_shadow_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_shadow_state FORCE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_shadow_mismatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_shadow_mismatches FORCE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_cutover_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_acl_cutover_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_acl_shadow_state_admin ON public.drive_acl_shadow_state
  FOR SELECT TO public USING(public.drive_has_admin_perm(
    (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),'drive.manage'));
CREATE POLICY drive_acl_shadow_mismatches_admin ON public.drive_acl_shadow_mismatches
  FOR SELECT TO public USING(public.drive_has_admin_perm(
    (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),'drive.manage'));
CREATE POLICY drive_acl_cutover_evidence_admin ON public.drive_acl_cutover_evidence
  FOR SELECT TO public USING(public.drive_has_admin_perm(
    (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),'drive.manage'));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (187, now())
ON CONFLICT(version) DO NOTHING;
