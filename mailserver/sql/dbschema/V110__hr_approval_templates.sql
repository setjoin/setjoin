-- V110: HR leave/expense approval consumers (4th+5th engine consumers).
-- Spec: 2026-06-27-approval-engine-design.md §16 "future consumer" path.
-- Plan: docs/superpowers/plans/archive/2026-07-08-hr-approval-templates.md

-- 1. Extend the consumer_type CHECKs (inline column CHECKs get auto-generated
--    names: <table>_<column>_check).
ALTER TABLE public.approval_policies DROP CONSTRAINT approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies ADD CONSTRAINT approval_policies_consumer_type_check
  CHECK (consumer_type IN ('rbac.jit_activation','mail.external_send','mail.group_moderation','hr.leave','hr.expense'));
ALTER TABLE public.approval_requests DROP CONSTRAINT approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_consumer_type_check
  CHECK (consumer_type IN ('rbac.jit_activation','mail.external_send','mail.group_moderation','hr.leave','hr.expense'));

-- 2. Expense receipts: link table so blobs.ref_count GC sees the reference
--    (mirrors the attachments refcount pattern).
CREATE TABLE public.hr_expense_receipts (
  id                   bigserial   PRIMARY KEY,
  approval_request_id  bigint      NOT NULL REFERENCES public.approval_requests(id) ON DELETE CASCADE,
  line_index           int         NOT NULL,
  blob_sha256          text        NOT NULL REFERENCES public.blobs(sha256),
  filename             text        NOT NULL,
  UNIQUE (approval_request_id, line_index)
);
CREATE INDEX hr_expense_receipts_request_idx ON public.hr_expense_receipts(approval_request_id);

CREATE FUNCTION public.trg_hr_receipt_ref_inc() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN UPDATE public.blobs SET ref_count = ref_count + 1 WHERE sha256 = NEW.blob_sha256; RETURN NEW; END $$;
CREATE FUNCTION public.trg_hr_receipt_ref_dec() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN UPDATE public.blobs SET ref_count = ref_count - 1 WHERE sha256 = OLD.blob_sha256; RETURN OLD; END $$;
CREATE TRIGGER trg_hr_expense_receipts_inc AFTER INSERT ON public.hr_expense_receipts
  FOR EACH ROW EXECUTE FUNCTION public.trg_hr_receipt_ref_inc();
CREATE TRIGGER trg_hr_expense_receipts_dec AFTER DELETE ON public.hr_expense_receipts
  FOR EACH ROW EXECUTE FUNCTION public.trg_hr_receipt_ref_dec();

-- 3. RLS: visibility follows the linked request (held_inbound_messages pattern, V070).
ALTER TABLE public.hr_expense_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hr_expense_receipts FORCE  ROW LEVEL SECURITY;
CREATE POLICY hr_expense_receipts_via_request ON public.hr_expense_receipts
  FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.approval_requests WHERE id = approval_request_id));

-- 4. Toggles (D11, DEFAULT OFF) + routing/validation config.
INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('approval.hr_leave',   false, 'HR leave requests via the approval engine'),
  ('approval.hr_expense', false, 'HR expense reimbursement via the approval engine')
  ON CONFLICT (key) DO NOTHING;
INSERT INTO public.system_config (key, value) VALUES
  ('approval.hr_long_leave_days',    '3'::jsonb),       -- context long_leave = days > this
  ('approval.hr_expense_tier_cents', '500000'::jsonb)   -- context over_tier = total > this (¥5000)
  ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (110, now())
  ON CONFLICT (version) DO NOTHING;
