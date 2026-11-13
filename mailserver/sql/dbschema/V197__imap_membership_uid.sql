-- V197__imap_membership_uid.sql
INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.imap_membership_uid',false,
   'Allocate IMAP UID per mailbox membership with guarded backfill. DEFAULT OFF.')
ON CONFLICT(key) DO NOTHING;
-- Expand-only per-folder membership UID authority. Existing IMAP reads remain
-- on messages.imap_uid until feature.imap_membership_uid is enabled and the
-- bounded backfill reports complete.

ALTER TABLE public.message_tags
  ADD COLUMN imap_uid bigint,
  ADD COLUMN imap_modseq bigint NOT NULL DEFAULT 1 CHECK (imap_modseq > 0);

CREATE INDEX message_tags_tag_membership_uid_idx
  ON public.message_tags(tag_id, imap_uid, received_at, message_id);

CREATE TABLE public.imap_membership_uid_ledger (
  tag_id bigint NOT NULL REFERENCES public.tags(id) ON DELETE CASCADE,
  imap_uid bigint NOT NULL CHECK (imap_uid > 0),
  message_id bigint NOT NULL,
  received_at timestamptz NOT NULL,
  active boolean NOT NULL DEFAULT true,
  allocated_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  PRIMARY KEY(tag_id, imap_uid),
  CONSTRAINT imap_membership_uid_ledger_retired_shape
    CHECK ((active AND retired_at IS NULL) OR (NOT active AND retired_at IS NOT NULL))
);

CREATE TABLE public.imap_membership_uid_backfill (
  tag_id bigint PRIMARY KEY REFERENCES public.tags(id) ON DELETE CASCADE,
  processed bigint NOT NULL DEFAULT 0 CHECK (processed >= 0),
  repaired bigint NOT NULL DEFAULT 0 CHECK (repaired >= 0),
  uid_validity_bumped boolean NOT NULL DEFAULT false,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Evidence is mailbox-scoped; allocation remains worker/reducer-only.
ALTER TABLE public.imap_membership_uid_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.imap_membership_uid_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY imap_membership_uid_ledger_read ON public.imap_membership_uid_ledger
  FOR SELECT TO public USING (EXISTS (
    SELECT 1 FROM public.tags t WHERE t.id=tag_id AND t.mailbox_id=
      NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  ));
ALTER TABLE public.imap_membership_uid_backfill ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.imap_membership_uid_backfill FORCE ROW LEVEL SECURITY;
CREATE POLICY imap_membership_uid_backfill_read ON public.imap_membership_uid_backfill
  FOR SELECT TO public USING (EXISTS (
    SELECT 1 FROM public.tags t WHERE t.id=tag_id AND t.mailbox_id=
      NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  ));

INSERT INTO public.schema_migrations(version,applied_at) VALUES (197,now())
ON CONFLICT(version) DO NOTHING;
