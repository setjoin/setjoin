-- V105__approval_delegations.sql — QoL #23 out-of-office approval delegation.
--
-- A date-range "entrust": while active, an incoming approval request that resolves
-- to the delegator is rerouted to the delegate at resolution time (the
-- approval_resolve_approver hook, before the approver is snapshotted onto the
-- request). Requests created during the window go to the delegate; already-created
-- ones are untouched — DingTalk/Feishu OOO-entrust semantics. Distinct from the mail
-- vacation auto-reply (vacation_settings): that answers senders, this reassigns
-- approvers.
--
-- DELIBERATE RLS posture — mirrors vacation_settings, NOT approval_requests: the
-- resolution read runs on behalf of the APPROVER (or an engine wrapper), a DIFFERENT
-- user than the requester whose request is being routed. A FORCE-RLS self-policy keyed
-- on app.current_user_id would hide the delegator's row from that path and silently
-- disable the reroute. So NO RLS here — reads/writes are scoped by the p_user_id param
-- in set/get/active_delegate reducers (app-layer R1–R4 by propagation, the model
-- set_vacation.sql documents). See docs/standards/DATABASE_SECURITY.md.
CREATE TABLE public.approval_delegations (
  id                bigserial   PRIMARY KEY,
  delegator_user_id bigint      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  delegate_user_id  bigint      NOT NULL REFERENCES public.users(id),
  starts_at         timestamptz NOT NULL,
  ends_at           timestamptz NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CHECK (ends_at > starts_at),
  CHECK (delegate_user_id <> delegator_user_id)
);

-- The active-delegate lookup filters by delegator_user_id (the resolving approver).
CREATE INDEX approval_delegations_delegator_idx
  ON public.approval_delegations (delegator_user_id);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (105, now())
  ON CONFLICT (version) DO NOTHING;
