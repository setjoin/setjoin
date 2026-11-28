-- Receipt-backed mailbox SLA policy administration. Existing work rows retain
-- their immutable policy snapshots; only later work adopts a newer generation.
ALTER TABLE public.mail_work_sla_policies
  ADD COLUMN updated_by bigint REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE public.mail_work_operations
  DROP CONSTRAINT mail_work_operations_operation_kind_check;
ALTER TABLE public.mail_work_operations
  ADD CONSTRAINT mail_work_operations_operation_kind_check CHECK(operation_kind IN (
    'work_set','comment_set','comment_edit','outbox_action','sla_policy_set',
    'draft_acquire','draft_renew','draft_save','draft_release','draft_handoff',
    'draft_takeover','draft_submit'
  ));

ALTER TABLE public.mail_work_changes
  DROP CONSTRAINT mail_work_changes_object_kind_check;
ALTER TABLE public.mail_work_changes
  ADD CONSTRAINT mail_work_changes_object_kind_check
  CHECK(object_kind IN ('work','comment','draft','policy','resync'));

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (208, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
