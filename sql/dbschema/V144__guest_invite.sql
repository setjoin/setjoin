-- V144__guest_invite.sql — Guest Accounts G1 (spec
-- docs/superpowers/specs/2026-07-19-guest-accounts-G1-invite.md §3).
--
-- Adds invite flow, domain allowlist, and notification digest outbox tables.
-- All three are FORCE-RLS tables: invite and intent rows are worker/reducer
-- only, while allowlist reads are restricted to guests.manage administrators.
-- Also seeds the approval.guest_invite toggle OFF and adds guest.invite to the
-- approval-engine consumer type checks (the V110 drop/re-add recipe).
--
-- MIGRATION AUTHOR: Before applying, verify the current CHECK constraint text
-- for approval_policies_consumer_type_check and approval_requests_consumer_type_check
-- by running:
--   SELECT constraint_name, check_clause
--     FROM information_schema.check_constraints
--    WHERE constraint_name LIKE 'approval_%consumer_type%';
-- Confirm every existing consumer value is represented in the ADD below.

-- Raw invite tokens remain in Go memory and email transport only. The database
-- holds their SHA-256 hex digest; the partial unique index makes a concurrent
-- second pending invite for the same guest structurally impossible.
CREATE TABLE public.guest_invites (
    id                     BIGSERIAL    PRIMARY KEY,
    guest_user_id          BIGINT       NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token_hash             TEXT         NOT NULL UNIQUE,
    host_domain_id         BIGINT       NOT NULL REFERENCES public.domains(id),
    created_by             BIGINT       REFERENCES public.users(id) ON DELETE SET NULL,
    created_by_email       TEXT         NOT NULL,
    expires_at             TIMESTAMPTZ  NOT NULL,
    used_at                TIMESTAMPTZ,
    disclosure_version     TEXT,
    disclosure_accepted_at TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX guest_invites_pending_unique
    ON public.guest_invites (guest_user_id)
 WHERE used_at IS NULL;
CREATE INDEX guest_invites_guest_user_idx ON public.guest_invites (guest_user_id);

ALTER TABLE public.guest_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guest_invites FORCE  ROW LEVEL SECURITY;

-- Zero rows means open invite-domain policy; non-zero rows are an allowlist.
CREATE TABLE public.guest_invite_domains (
    domain         TEXT   PRIMARY KEY
                   CHECK (domain ~ '^[a-z0-9][a-z0-9.-]{0,251}[.][a-z]{2,}$'),
    host_domain_id BIGINT NOT NULL REFERENCES public.domains(id),
    added_by       BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    added_by_email TEXT   NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.guest_invite_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guest_invite_domains FORCE  ROW LEVEL SECURITY;
CREATE POLICY guest_invite_domains_admin_read ON public.guest_invite_domains
    FOR SELECT TO public
    USING (
        (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint) IS NOT NULL
        AND public.drive_has_admin_perm(
            (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
            'guests.manage'
        )
    );

-- Durable, worker-drained digest outbox for offline guest notifications.
CREATE TABLE public.guest_notification_intents (
    id         BIGSERIAL    PRIMARY KEY,
    user_id    BIGINT       NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    kind       TEXT         NOT NULL CHECK (kind IN ('mention','dm','meeting_invite')),
    ref        TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    sent_at    TIMESTAMPTZ
);
CREATE INDEX guest_notification_intents_pending_idx
    ON public.guest_notification_intents (user_id)
 WHERE sent_at IS NULL;
CREATE INDEX guest_notification_intents_created_idx
    ON public.guest_notification_intents (created_at);

ALTER TABLE public.guest_notification_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guest_notification_intents FORCE  ROW LEVEL SECURITY;

INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('approval.guest_invite', false,
   'When ON: members may submit guest invite requests via approval consumer #8 (guest.invite). '
   'When OFF (default): only guests.manage admins may invite directly via POST /admin/guests.')
ON CONFLICT (key) DO NOTHING;

ALTER TABLE public.approval_policies DROP CONSTRAINT IF EXISTS approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies ADD CONSTRAINT approval_policies_consumer_type_check
  CHECK (consumer_type IN (
    'rbac.jit_activation','mail.external_send','mail.group_moderation',
    'hr.leave','hr.expense','drive.share','drive.export','guest.invite'
  ));

ALTER TABLE public.approval_requests DROP CONSTRAINT IF EXISTS approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_consumer_type_check
  CHECK (consumer_type IN (
    'rbac.jit_activation','mail.external_send','mail.group_moderation',
    'hr.leave','hr.expense','drive.share','drive.export','guest.invite'
  ));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (144, now())
    ON CONFLICT (version) DO NOTHING;
