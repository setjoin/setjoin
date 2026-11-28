-- V143__guest_core.sql — Guest Accounts G0 (spec
-- docs/superpowers/specs/2026-07-18-guest-accounts-design.md §4.1, P1).
--
-- guest_accounts: the satellite discriminator (mailbox-type-refactor pattern).
-- Two orthogonal domain axes (codex C-2): users.domain_id = the system guest
-- domain (mail-routing isolation, nothing more); host_domain_id = the
-- IMMUTABLE ownership axis (the inviting org domain, resolved from the
-- inviter at provision, never updated). host_domain_id is RESTRICT
-- (deliberately: a domain with guests refuses deletion). invited_by is
-- SET NULL + an immutable invited_by_email snapshot (codex C-9: users ARE
-- hard-deleted — admin_users.go's hard DELETE — a RESTRICT'd inviter FK
-- would block deleting any inviter until G5).
CREATE TABLE public.guest_accounts (
    user_id          BIGINT PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    invited_email    TEXT   NOT NULL,
    invited_by       BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    invited_by_email TEXT   NOT NULL,   -- immutable audit snapshot, stamped at provision
    sponsor_user_id  BIGINT REFERENCES public.users(id) ON DELETE SET NULL,  -- G5 sponsor-transfer (OD#3)
    host_domain_id   BIGINT NOT NULL REFERENCES public.domains(id),          -- RESTRICT (default FK behavior)
    profile_id       BIGINT,            -- FK added when guest_profiles lands (G2); NULL = most-restrictive
    status           TEXT   NOT NULL DEFAULT 'invited'
                     CHECK (status IN ('invited','active','disabled','expired')),
    expires_at       TIMESTAMPTZ,       -- NULL = no expiry
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX guest_accounts_host_domain_idx ON public.guest_accounts (host_domain_id);

-- FORCE RLS: self may SELECT own row (expiry banner); NO mutation policy —
-- reducer/worker-only writes (guest_account.sql helpers are SECURITY DEFINER
-- worker-owned, the single lookup path for Go and SQL alike).
ALTER TABLE public.guest_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guest_accounts FORCE  ROW LEVEL SECURITY;
CREATE POLICY guest_accounts_self_read ON public.guest_accounts FOR SELECT TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));

-- The system guest domain (P1): users.domain_id is NOT NULL and vivifying
-- external domains is forbidden, so ALL guests land here. is_local = FALSE ⇒
-- inbound delivery never accepts for it (no-mail-escalation preserved).
-- 'guest.invalid' satisfies domains_name_check and is non-routable by RFC 2606.
INSERT INTO public.domains (name, is_local) VALUES ('guest.invalid', FALSE)
ON CONFLICT ON CONSTRAINT domains_name_key DO NOTHING;

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.guest_accounts', false,
   'Guest accounts (external collaborators as constrained mailbox-less users). Seeded OFF — G0 substrate; must not flip ON before G2 lands (spec P11).')
ON CONFLICT (key) DO NOTHING;

-- Perms: drive.view/drive.manage genre — deliberately OUTSIDE the SoD class
-- map in v1 (the P1-drive precedent; do NOT touch shared/permissions/classes.go).
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('guests.view',   'Guests', 'View guest accounts, their status and grants', false),
  ('guests.manage', 'Guests', 'Invite, disable, expire and manage external guest accounts', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['guests.view','guests.manage']) AS p)
 WHERE id = 1;

-- Mailbox-less FLOOR (codex round-3 C-2): "no seam ever gives a guest a
-- mailbox" was previously narrated, enforced only at the provision_account
-- choke — but admin_mailboxes.go's POST /admin/mailboxes INSERTs a mailbox
-- for an arbitrary user_id directly, and authserver's JIT path
-- (handlers/auth.go:1226) INSERTs one too. A guest-with-mailbox hybrid would
-- silently void the containment stories that lean on mailbox-lessness
-- (federation_apply_chat's mailboxes-JOIN justification, CalDAV/IMAP).
-- The trigger is the DEEPEST shared seam: every INSERT path, present and
-- future, hits it. Self-contained EXISTS (is_guest_account() is a reducer,
-- not loaded yet at migration time) + SECURITY DEFINER (under FORCE RLS an
-- app-pool trigger read of guest_accounts would see no rows and fail OPEN).
-- apply_worker_ownership exists since V118 — available here.
CREATE FUNCTION public.guest_mailbox_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.user_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM guest_accounts g WHERE g.user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'guest accounts are mailbox-less; guest->member conversion is not a mailbox side effect'
            USING ERRCODE='BZ221', HINT='{"type":"conflict","detail":"guest accounts cannot own mailboxes"}';
    END IF;
    RETURN NEW;
END;
$$;
SELECT apply_worker_ownership('guest_mailbox_guard()'::regprocedure);
CREATE TRIGGER mailboxes_guest_guard
    BEFORE INSERT OR UPDATE OF user_id ON public.mailboxes
    FOR EACH ROW EXECUTE FUNCTION public.guest_mailbox_guard();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (143, now())
    ON CONFLICT (version) DO NOTHING;
