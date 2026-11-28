-- Approved source-to-source lifecycle transitions preserve the person and every
-- mailbox identifier while moving provisioning authority to an already-linked,
-- immutable target subject.
ALTER TABLE public.identity_transitions DROP CONSTRAINT identity_transitions_kind_check;
ALTER TABLE public.identity_transitions ADD CONSTRAINT identity_transitions_kind_check
  CHECK(kind IN ('directory_to_local','source_to_source'));
ALTER TABLE public.identity_transitions
  ADD COLUMN target_source_id bigint REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
  ADD COLUMN target_link_id bigint REFERENCES public.user_identity_links(id) ON DELETE RESTRICT,
  ADD COLUMN target_source_generation bigint CHECK(target_source_generation>0),
  ADD COLUMN target_link_generation bigint CHECK(target_link_generation>0),
  ADD COLUMN committed_target_link_generation bigint CHECK(committed_target_link_generation>0),
  ADD CONSTRAINT identity_transition_target_shape CHECK(
    (kind='directory_to_local' AND target_source_id IS NULL AND target_link_id IS NULL
      AND target_source_generation IS NULL AND target_link_generation IS NULL)
    OR (kind='source_to_source' AND target_source_id IS NOT NULL AND target_link_id IS NOT NULL
      AND target_source_generation IS NOT NULL AND target_link_generation IS NOT NULL
      AND target_source_id<>source_id AND target_link_id<>link_id));

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (204, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
