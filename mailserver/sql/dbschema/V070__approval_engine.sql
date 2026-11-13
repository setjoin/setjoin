-- V045: Approval engine foundation — policies, requests, held inbound, RLS, toggles, config.
-- Spec: docs/superpowers/specs/2026-06-27-approval-engine-design.md §4.
-- Build sequence step 1 (engine schema); reducers in later tasks.

-- ── Tables (approval_policies FIRST: approval_requests.policy_id FK) ─────────

-- Valid consumer discriminators (typed; CHECK guards typos that would silently no-match).
-- 'rbac.jit_activation' | 'mail.external_send' | 'mail.group_moderation' | (future) 'drive.share'

CREATE TABLE public.approval_policies (
  id                bigserial PRIMARY KEY,
  consumer_type     text        NOT NULL CHECK (consumer_type IN ('rbac.jit_activation','mail.external_send','mail.group_moderation')),
  name              text        NOT NULL,
  enabled           boolean     NOT NULL DEFAULT true,
  priority          integer     NOT NULL,          -- UNIQUE within consumer_type; drag-reorder keeps it distinct
  conditions        jsonb       NOT NULL,          -- match predicate (e.g. {"recipient_external":true,"recipient_domain":"competitor.com"})
  requires_approval boolean     NOT NULL DEFAULT true,
  approver_spec     jsonb       NOT NULL,          -- {"kind":"manager","fallback":[{"kind":"default_admin"}]} | {"kind":"named","user_id":N} | {"kind":"role_group","role_group_id":N}
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (consumer_type, priority)
);

CREATE TABLE public.approval_requests (
  id                 bigserial PRIMARY KEY,
  consumer_type      text        NOT NULL CHECK (consumer_type IN ('rbac.jit_activation','mail.external_send','mail.group_moderation')),
  requester_user_id  bigint      NOT NULL REFERENCES public.users(id),
  subject            text        NOT NULL,
  payload            jsonb       NOT NULL,         -- APPLY data; ONLY the consumer wrapper reads it, never shared decide
  status             text        NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','approved','denied','cancelled','expired','applied','apply_failed','skipped')),
  policy_id          bigint      REFERENCES public.approval_policies(id),  -- winning policy; NULL when approver is caller-supplied (group moderator)
  approver_kind      text        NOT NULL CHECK (approver_kind IN ('user','role_group')),
  approver_ref       bigint      NOT NULL,         -- user_id or admin_role_group_id; snapshotted at create
  decided_by_user_id bigint      REFERENCES public.users(id),
  decided_at         timestamptz,
  decision_comment   text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL          -- the approval window; the expiry sweep acts on this (§8)
);
CREATE INDEX approval_requests_pending_user_idx  ON public.approval_requests (approver_ref) WHERE status='pending' AND approver_kind='user';
CREATE INDEX approval_requests_pending_group_idx ON public.approval_requests (approver_ref) WHERE status='pending' AND approver_kind='role_group';
CREATE INDEX approval_requests_requester_idx     ON public.approval_requests (requester_user_id);
CREATE INDEX approval_requests_expiry_idx        ON public.approval_requests (expires_at) WHERE status='pending';

-- Inbound moderated-group hold: the message + its already-computed Go verdict has no home (§2.5).
CREATE TABLE public.held_inbound_messages (
  id                  bigserial PRIMARY KEY,
  approval_request_id bigint      NOT NULL REFERENCES public.approval_requests(id) ON DELETE CASCADE,
  group_id            bigint      NOT NULL REFERENCES public.distribution_groups(id),
  raw_ref             text        NOT NULL,        -- blob ref to the stored raw message (content-addressed, as attachments are)
  envelope            jsonb       NOT NULL,        -- MAIL FROM / RCPT TO
  deliver_params      jsonb       NOT NULL,        -- the verdict + the other deliver() args, verbatim, to re-invoke on approve
  held_at             timestamptz NOT NULL DEFAULT now()
);

-- ── system_config defaults (idempotent — DO NOTHING preserves admin overrides) ─

INSERT INTO public.system_config (key, value) VALUES
  ('approval.default_approver_user_id', '0'::jsonb),    -- 0 = unset; admin sets a real user id
  ('approval.request_ttl_minutes',      '2880'::jsonb)  -- 48h default approval window
  ON CONFLICT (key) DO NOTHING;

-- ── Feature toggles, DEFAULT OFF (D11) ────────────────────────────────────────

INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('approval.rbac',             false, 'Require approval before JIT admin-role activation'),
  ('approval.mail_external',    false, 'Hold outbound email to external recipients for approval'),
  ('approval.group_moderation', false, 'Require moderator approval for inbound group messages')
  ON CONFLICT (key) DO NOTHING;

-- ── RLS (R4 — FORCE on all three tables) ──────────────────────────────────────
--
-- Auth seam: app.current_user_id GUC (InitPlan form, fail-closed: unset → NULL → no rows).
-- Mirror: app.current_mailbox_id from V003/V004 for the same NULLIF pattern.
-- Go code sets this GUC per-request before calling approval reducers/queries
-- (established here; wired in later tasks).

ALTER TABLE public.approval_requests         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_requests         FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.approval_policies         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_policies         FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.held_inbound_messages     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.held_inbound_messages     FORCE  ROW LEVEL SECURITY;

-- approval_requests: requester sees own; assigned approver (user or role-group member) sees assigned;
-- ponytail: approvals.view perm not yet seeded (Task 13 seeds it);
--           interim admin gate: Super Admin (role_group_id=1) with active assignment.
--           admin_is_super() + admin_assignment_active() are reducers (not available at
--           migration time), so the logic is inlined here verbatim from those functions.
CREATE POLICY approval_requests_row_visibility ON public.approval_requests
  FOR ALL TO public
  USING (
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint) IS NOT NULL
    AND (
      requester_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
      OR (approver_kind = 'user'
          AND approver_ref = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
      OR (approver_kind = 'role_group'
          AND EXISTS (
            SELECT 1 FROM public.admin_role_assignments ara
             WHERE ara.role_group_id = approver_ref
               AND ara.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
               AND (ara.expires_at IS NULL OR ara.expires_at > now())
               -- inline admin_assignment_active: jit toggle OFF or not eligible or window open
               AND (
                 NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
                 OR ara.eligible = false
                 OR (ara.activated_until IS NOT NULL AND ara.activated_until > now())
               )))
      -- inline admin_is_super: active Super Admin (role_group_id=1) assignment
      OR EXISTS (
           SELECT 1 FROM public.admin_role_assignments sa
            WHERE sa.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
              AND sa.role_group_id = 1
              AND (sa.expires_at IS NULL OR sa.expires_at > now())
              AND (
                NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
                OR sa.eligible = false
                OR (sa.activated_until IS NOT NULL AND sa.activated_until > now())
              ))
    )
  );

-- approval_policies: read/write gated to approvals.manage permission.
-- ponytail: approvals.manage perm not yet seeded (Task 13 seeds it);
--           interim gate: Super Admin (inlined admin_is_super logic, see above).
CREATE POLICY approval_policies_admin_only ON public.approval_policies
  FOR ALL TO public
  USING (
    EXISTS (
      SELECT 1 FROM public.admin_role_assignments sa
       WHERE sa.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND sa.role_group_id = 1
         AND (sa.expires_at IS NULL OR sa.expires_at > now())
         AND (
           NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
           OR sa.eligible = false
           OR (sa.activated_until IS NOT NULL AND sa.activated_until > now())
         )
    )
  );

-- held_inbound_messages: visibility follows its linked approval_request (via RLS on that table).
CREATE POLICY held_inbound_messages_via_request ON public.held_inbound_messages
  FOR ALL TO public
  USING (
    EXISTS (SELECT 1 FROM public.approval_requests WHERE id = approval_request_id)
  );

-- ── Schema version ────────────────────────────────────────────────────────────

INSERT INTO public.schema_migrations (version, applied_at) VALUES (70, now())
  ON CONFLICT (version) DO NOTHING;
