-- V288__wave18c_root_auth_force_rls.sql — Wave 1.8 Phase 546d: Wave C FORCE RLS
-- across the final 20 root/auth tables (driving legacy_rls_pending_ceiling 20 -> 0):
--   users, mailboxes, sessions, app_passwords, oauth_tokens, oidc_auth_requests,
--   oidc_tokens, passkey_credentials, password_history, push_devices,
--   push_mfa_challenges, mfa_reauth_step_ups, totp_pending_enrollments,
--   totp_removal_step_ups, webauthn_ceremonies, user_app_entitlements,
--   user_smime_certs, recipient_smime_certs, webhook_subscriptions,
--   ws_subscriptions.
--
-- Security model (DATABASE_SECURITY.md R4 + ARCH-018):
--   1. All 20 tables receive ENABLE + FORCE ROW LEVEL SECURITY and least-privilege
--      `TO setjoin_app` policies. Missing/empty GUCs fail closed (NULLIF(..., '')
--      evaluates to NULL -> FALSE).
--   2. Mutual recursion break (`mailbox_delegates` V090 <-> `mailboxes`):
--      `mailboxes_app_select` delegates to the worker-owned pure-boolean
--      ARCH-018 helper `public.rls_mailbox_delegate_for_current_user(...)`
--      (installed in V287, SECURITY DEFINER owned by `setjoin_worker`),
--      allowing owners and delegates to read the mailbox row (for
--      `TxFactory::mint_mailbox_principal`) WITHOUT widening any other
--      `mailbox_scoped` table (`manage_calendar`-only delegates cannot read
--      `rules`/`contacts`/`messages`).
--   3. Nullable scope columns (`mailboxes.user_id` shared mailboxes,
--      `oidc_auth_requests.user_id` pre-login, `webhook_subscriptions.user_id`
--      org webhooks) fail closed on NULL under `setjoin_app`; pre-auth and
--      org-admin paths run through the private `setjoin_worker` seam.
--   4. `resolve_identity(text)` is hardened with caller-scope gating (requires
--      privileged caller or active `app.current_user_id`/`app.current_mailbox_id`
--      GUC) + worker-owned `SECURITY DEFINER SET search_path = pg_catalog, public`
--      so authenticated colleague lookups keep working under `users`/`mailboxes`
--      FORCE RLS while unauthenticated `setjoin_app` callers fail closed.
--   5. Locking & PG 15+ non-superuser DDL safety:
--      - `SET LOCAL lock_timeout = '5s'` inside a single transaction.
--      - Canonical table lock order (`users -> mailboxes -> child/auth tables`).
--      - Transient `GRANT CREATE ON SCHEMA public TO setjoin_worker` around
--        `apply_worker_ownership(...)`, always revoked before commit.
--   6. Verbatim upgrade parity: all new/modified Wave 1.8d reducers are embedded
--      byte-for-byte verbatim before recording migration version 288.

BEGIN;

SET LOCAL lock_timeout = '5s';

-- Canonical lock order: users -> mailboxes -> child/auth tables.
LOCK TABLE
  public.users,
  public.mailboxes,
  public.sessions,
  public.app_passwords,
  public.oauth_tokens,
  public.oidc_auth_requests,
  public.oidc_tokens,
  public.passkey_credentials,
  public.password_history,
  public.push_devices,
  public.push_mfa_challenges,
  public.mfa_reauth_step_ups,
  public.totp_pending_enrollments,
  public.totp_removal_step_ups,
  public.webauthn_ceremonies,
  public.user_app_entitlements,
  public.user_smime_certs,
  public.recipient_smime_certs,
  public.webhook_subscriptions,
  public.ws_subscriptions
IN ACCESS EXCLUSIVE MODE;

-- ── Enable + Force RLS and least-privilege setjoin_app policies (20 tables) ──

-- 1. users (user_scoped on id; least-privilege SELECT+UPDATE only — no setjoin_app INSERT/DELETE or dump oracle)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS users_app_all ON public.users;
DROP POLICY IF EXISTS users_app_select ON public.users;
DROP POLICY IF EXISTS users_app_update ON public.users;
CREATE POLICY users_app_select ON public.users
  FOR SELECT TO setjoin_app
  USING (id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);
CREATE POLICY users_app_update ON public.users
  FOR UPDATE TO setjoin_app
  USING (id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 2. mailboxes (mailbox_scoped on id; nullable user_id fails closed on NULL;
--    SELECT includes ARCH-018 worker-owned delegate helper breaking V090 recursion)
ALTER TABLE public.mailboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mailboxes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mailboxes_app_select ON public.mailboxes;
CREATE POLICY mailboxes_app_select ON public.mailboxes
  FOR SELECT TO setjoin_app
  USING (
    (user_id IS NOT NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
    OR public.rls_mailbox_delegate_for_current_user(
         id, ARRAY['read', 'send_as', 'send_on_behalf', 'full_access', 'manage_calendar']
       )
  );
DROP POLICY IF EXISTS mailboxes_app_insert ON public.mailboxes;
CREATE POLICY mailboxes_app_insert ON public.mailboxes
  FOR INSERT TO setjoin_app
  WITH CHECK (
    user_id IS NOT NULL
    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );
DROP POLICY IF EXISTS mailboxes_app_update ON public.mailboxes;
CREATE POLICY mailboxes_app_update ON public.mailboxes
  FOR UPDATE TO setjoin_app
  USING (
    (user_id IS NOT NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  )
  WITH CHECK (
    (user_id IS NOT NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  );
DROP POLICY IF EXISTS mailboxes_app_delete ON public.mailboxes;
CREATE POLICY mailboxes_app_delete ON public.mailboxes
  FOR DELETE TO setjoin_app
  USING (
    (user_id IS NOT NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  );

-- 3. sessions
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sessions_app_all ON public.sessions;
CREATE POLICY sessions_app_all ON public.sessions
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 4. app_passwords
ALTER TABLE public.app_passwords ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_passwords FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_passwords_app_all ON public.app_passwords;
CREATE POLICY app_passwords_app_all ON public.app_passwords
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 5. oauth_tokens
ALTER TABLE public.oauth_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oauth_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oauth_tokens_app_all ON public.oauth_tokens;
CREATE POLICY oauth_tokens_app_all ON public.oauth_tokens
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 6. oidc_auth_requests (nullable scope fails closed on NULL)
ALTER TABLE public.oidc_auth_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_auth_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oidc_auth_requests_app_all ON public.oidc_auth_requests;
CREATE POLICY oidc_auth_requests_app_all ON public.oidc_auth_requests
  FOR ALL TO setjoin_app
  USING (user_id IS NOT NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id IS NOT NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 7. oidc_tokens
ALTER TABLE public.oidc_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oidc_tokens_app_all ON public.oidc_tokens;
CREATE POLICY oidc_tokens_app_all ON public.oidc_tokens
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 8. passkey_credentials
ALTER TABLE public.passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passkey_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS passkey_credentials_app_all ON public.passkey_credentials;
CREATE POLICY passkey_credentials_app_all ON public.passkey_credentials
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 9. password_history
ALTER TABLE public.password_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.password_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS password_history_app_all ON public.password_history;
CREATE POLICY password_history_app_all ON public.password_history
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 10. push_devices
ALTER TABLE public.push_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.push_devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS push_devices_app_all ON public.push_devices;
CREATE POLICY push_devices_app_all ON public.push_devices
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 11. push_mfa_challenges
ALTER TABLE public.push_mfa_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.push_mfa_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS push_mfa_challenges_app_all ON public.push_mfa_challenges;
CREATE POLICY push_mfa_challenges_app_all ON public.push_mfa_challenges
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 12. mfa_reauth_step_ups
ALTER TABLE public.mfa_reauth_step_ups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mfa_reauth_step_ups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mfa_reauth_step_ups_app_all ON public.mfa_reauth_step_ups;
CREATE POLICY mfa_reauth_step_ups_app_all ON public.mfa_reauth_step_ups
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 13. totp_pending_enrollments
ALTER TABLE public.totp_pending_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.totp_pending_enrollments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS totp_pending_enrollments_app_all ON public.totp_pending_enrollments;
CREATE POLICY totp_pending_enrollments_app_all ON public.totp_pending_enrollments
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 14. totp_removal_step_ups
ALTER TABLE public.totp_removal_step_ups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.totp_removal_step_ups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS totp_removal_step_ups_app_all ON public.totp_removal_step_ups;
CREATE POLICY totp_removal_step_ups_app_all ON public.totp_removal_step_ups
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 15. webauthn_ceremonies
ALTER TABLE public.webauthn_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webauthn_ceremonies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webauthn_ceremonies_app_all ON public.webauthn_ceremonies;
CREATE POLICY webauthn_ceremonies_app_all ON public.webauthn_ceremonies
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 16. user_app_entitlements (read-only for setjoin_app; admin/entitlement writes run on worker)
ALTER TABLE public.user_app_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_app_entitlements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_app_entitlements_app_all ON public.user_app_entitlements;
DROP POLICY IF EXISTS user_app_entitlements_app_select ON public.user_app_entitlements;
CREATE POLICY user_app_entitlements_app_select ON public.user_app_entitlements
  FOR SELECT TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 17. user_smime_certs
ALTER TABLE public.user_smime_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_smime_certs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_smime_certs_app_all ON public.user_smime_certs;
CREATE POLICY user_smime_certs_app_all ON public.user_smime_certs
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 18. recipient_smime_certs
ALTER TABLE public.recipient_smime_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recipient_smime_certs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recipient_smime_certs_app_all ON public.recipient_smime_certs;
CREATE POLICY recipient_smime_certs_app_all ON public.recipient_smime_certs
  FOR ALL TO setjoin_app
  USING (owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 19. webhook_subscriptions (strictly self-scoped; org webhooks and NULL user_id fail closed under setjoin_app)
ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_subscriptions_app_all ON public.webhook_subscriptions;
CREATE POLICY webhook_subscriptions_app_all ON public.webhook_subscriptions
  FOR ALL TO setjoin_app
  USING (
    scope = 'self'
    AND user_id IS NOT NULL
    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  )
  WITH CHECK (
    scope = 'self'
    AND user_id IS NOT NULL
    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );

-- 20. ws_subscriptions
ALTER TABLE public.ws_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ws_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ws_subscriptions_app_all ON public.ws_subscriptions;
CREATE POLICY ws_subscriptions_app_all ON public.ws_subscriptions
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);


-- ── Verbatim embedded Wave 1.8d reducers (atomic upgrade parity) ──

-- Embedded verbatim from mailserver/sql/reducers/resolve_identity.sql
-- resolve_identity.sql — the address-aware identity resolution seam (ADR-004 §3,
-- docs/adr/ARCH-004-directory-org-scope.md). The reducer-layer twin of
-- authserver's connector.ResolveIdentitySQL: resolve a PERSON by ANY of their
-- addresses — `users.email` (primary) ∪ `aliases.email` (every alias on a mailbox
-- the person owns) ∪ `users.ad_upn` (AD userPrincipalName) — case-insensitive.
--
-- WHY THIS EXISTS (the bug class it closes): a setjoin deployment is exactly ONE
-- organization, and a person is one identity with a FULL address set. Mail already
-- resolves a person by their full set (the SMTP alias join); the directory was
-- converged onto it by ADR-004 Half B. The calendar reducers, however, still
-- resolved an owner/delegate/attendee by `users.email` ONLY — so a person addressed
-- by an alias on a sister domain, or by their UPN (which frequently differs from the
-- primary SMTP address), failed to resolve: a shared-calendar open returned empty, a
-- delegate-create was rejected as "delegator not found", an inbound iMIP REPLY was
-- refused as "attendee not authorized". This is the same bug class as ADR-004 Half A
-- (federated SP-mode matched the primary only and JIT-duplicated the person). Routing
-- the calendar person-lookups through this one seam fixes all of them and stops them
-- re-deriving "which person is this address?" their own (divergent) way.
--
-- RESOLUTION CONTRACT (V249 admission/backfill, med-identity-resolution-001): the
-- authoritative anchor is THE enabled users row that legitimately owns the address.
-- Returns ONE row — the single claimant (`identity_address_claim_count(...) = 1`) —
-- or ZERO rows. ZERO rows covers the unknown / disabled case AND the fail-closed
-- cases: an address claimed by 2+ enabled persons (cross-person ambiguity, which
-- admission control makes unwritable and the one-time backfill
-- `identity_address_overlap_backfill()` quarantines with an operator report) or a
-- quarantined address resolves for NO ONE — never an ORDER-BY-id pick, which would
-- silently rebind the address to whichever person sorts first. The trailing
-- ORDER BY/LIMIT is defense only: after the single-claim guarantee at most one row
-- can match.
--
-- The quarantine exclusion goes through the SECURITY DEFINER helper
-- `identity_address_quarantined(...)` (worker-owned, ARCH-018 recipe), NOT the
-- ledger table: the ledger is FORCE RLS with zero policies, so under the runtime
-- role (setjoin_app, NOBYPASSRLS) a direct `NOT EXISTS (... FROM
-- identity_address_quarantine)` probe is vacuously empty and resolution would
-- silently resume once one competing claim is removed — without any operator
-- release. The helper returns the quarantine fact identically to owner and
-- runtime connections.
-- Columns:
--   user_id          — the resolved person (users.id)
--   primary_mailbox  — that person's primary mailbox id (the calendar/ownership key;
--                      NULL only if the person has no primary mailbox, which the
--                      provisioning seam prevents). Callers needing "the owner's
--                      mailbox" use this instead of `mailboxes JOIN users ON email`.
--   domain_id        — the person's home domain (users.domain_id).
--
-- Only ENABLED users resolve (u.enabled = TRUE) — identical to the auth seam and to
-- the directory visibility rule; a disabled person is not addressable.
--
-- CO-EVOLVING TWIN of authserver/internal/connector/connector.go:ResolveIdentitySQL.
-- The matching predicate below (the WHERE: enabled ∧ email ∪ ad_upn ∪ alias, all
-- case-folded, ∧ single-claim ∧ not quarantined) MUST stay structurally identical to
-- that twin — if the two rules drift you get split-brain identity (auth resolves a
-- person the mailserver can't: silent lockout / duplicate JIT).
-- scripts/check-identity-predicate.sh enforces it (extracts + normalizes + diffs
-- both WHERE clauses; shared/identity plan, 2026-06-18). The PROJECTION is allowed
-- to differ (this reducer returns 3 columns; the Go twin returns the full Identity
-- row). A change to the matching RULE here is the documented trigger to merge the
-- union into a single resolvable_identity view.
--
CREATE OR REPLACE FUNCTION resolve_identity(
  p_address TEXT
) RETURNS TABLE(
  user_id          BIGINT,
  primary_mailbox  BIGINT,
  domain_id        BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF NULLIF(current_setting('app.current_user_id', true), '') IS NULL
       AND NULLIF(current_setting('app.current_mailbox_id', true), '') IS NULL THEN
      RETURN;
    END IF;
  END IF;

  RETURN QUERY
  SELECT
    u.id,
    (SELECT mb.id FROM mailboxes mb
       WHERE mb.user_id = u.id AND mb.is_primary
       ORDER BY mb.id LIMIT 1),
    u.domain_id
  FROM users u
  WHERE u.enabled = TRUE
    AND p_address IS NOT NULL
    AND (
      lower(u.email) = lower(p_address)
      OR lower(u.ad_upn) = lower(p_address)
      OR EXISTS (
        SELECT 1 FROM aliases a
        JOIN mailboxes m ON m.id = a.mailbox_id
        WHERE m.user_id = u.id AND lower(a.email) = lower(p_address)
      )
    )
    AND identity_address_claim_count(lower(p_address)) = 1
    AND NOT identity_address_quarantined(lower(p_address))
  ORDER BY u.id
  LIMIT 1;
END;
$$;

COMMENT ON FUNCTION resolve_identity(TEXT) IS
  'Address-aware identity seam (ADR-004 §3): resolve a person by ANY of their '
  'addresses — users.email ∪ aliases.email ∪ users.ad_upn (case-insensitive, '
  'enabled users only). V247 admission contract: fails closed (zero rows) for '
  'cross-person ambiguous or quarantined addresses — exactly one enabled '
  'claimant or nothing. Returns (user_id, primary_mailbox, domain_id). '
  'The reducer-layer twin of connector.ResolveIdentitySQL; calendar owner/delegate/'
  'attendee lookups call this instead of matching users.email only.';

-- Embedded verbatim from mailserver/sql/reducers/rust_system_config_ops.sql
-- rust_system_config_ops.sql — Wave 1.8c (#546c)
-- Owning reducers for system_config mutations (retiring direct cross-domain
-- writes from mail-security and mailboxes). Strictly worker/admin-only:
-- fail closed (42501) unless called from a privileged role, and revoked from
-- PUBLIC and setjoin_app (restated in scripts/provision-roles.sql exact_worker).

CREATE OR REPLACE FUNCTION rust_system_config_upsert_batch(
  p_keys        TEXT[],
  p_values      TEXT[],
  p_description TEXT
) RETURNS INT AS $$
DECLARE
  v_count INT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH w AS (
    INSERT INTO public.system_config (key, value, description)
    SELECT t.k, t.v::jsonb, p_description
      FROM unnest(p_keys, p_values) AS t(k, v)
    ON CONFLICT (key) DO UPDATE
      SET value = EXCLUDED.value,
          updated_at = now()
    RETURNING 1
  )
  SELECT count(*)::int INTO v_count FROM w;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_upsert_batch(text[],text[],text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert_batch(text[],text[],text) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_system_config_upsert(
  p_key       TEXT,
  p_value     TEXT,
  p_encrypted BOOLEAN
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  IF p_encrypted THEN
    WITH w AS (
      INSERT INTO public.system_config (key, value, encrypted)
      VALUES (p_key, p_value::jsonb, TRUE)
      ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            encrypted = TRUE,
            updated_at = now()
      RETURNING 1
    )
    SELECT count(*)::bigint INTO v_count FROM w;
  ELSE
    WITH w AS (
      INSERT INTO public.system_config (key, value)
      VALUES (p_key, p_value::jsonb)
      ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            updated_at = now()
      RETURNING 1
    )
    SELECT count(*)::bigint INTO v_count FROM w;
  END IF;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_upsert(text,text,boolean) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert(text,text,boolean) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_system_config_delete(
  p_key TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH d AS (
    DELETE FROM public.system_config
     WHERE key = p_key
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM d;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_delete(text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_delete(text) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_system_config_upsert_batch_encrypted(
  p_keys        TEXT[],
  p_values      TEXT[],
  p_encrypted   BOOLEAN[],
  p_description TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH w AS (
    INSERT INTO public.system_config (key, value, encrypted, description, updated_at)
    SELECT t.k, t.v::jsonb, t.e, p_description, now()
      FROM unnest(p_keys, p_values, p_encrypted) AS t(k, v, e)
    ON CONFLICT (key) DO UPDATE
      SET value = EXCLUDED.value,
          encrypted = EXCLUDED.encrypted,
          updated_at = now()
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM w;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_upsert_batch_encrypted(text[],text[],boolean[],text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert_batch_encrypted(text[],text[],boolean[],text) TO setjoin_worker;

-- Embedded verbatim from mailserver/sql/reducers/rust_mailbox_admin_ops.sql
-- rust_mailbox_admin_ops.sql — Wave 1.8d (#546d)
-- Owning mailboxes/aliases reducers retiring direct cross-domain writes from
-- admin-identity and identity. Strictly worker/admin-only: fail closed (42501)
-- unless called from a privileged role, and revoked from PUBLIC and setjoin_app
-- (restated in scripts/provision-roles.sql exact_worker).

CREATE OR REPLACE FUNCTION rust_mailbox_admin_set_quota(
  p_user_id           BIGINT,
  p_domain_scope      BIGINT,
  p_quota_bytes       BIGINT,
  p_sending_quota_day INTEGER
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH updated AS (
    UPDATE public.mailboxes
       SET quota_bytes = COALESCE(p_quota_bytes, quota_bytes),
           sending_quota_day = COALESCE(p_sending_quota_day, sending_quota_day),
           updated_at = now()
     WHERE user_id = p_user_id
       AND is_primary = TRUE
       AND (p_domain_scope = 0 OR domain_id = p_domain_scope)
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM updated;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_admin_set_quota(bigint,bigint,bigint,integer) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_admin_set_quota(bigint,bigint,bigint,integer) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_mailbox_alias_add(
  p_mailbox_id     BIGINT,
  p_user_id        BIGINT,
  p_domain_scope   BIGINT,
  p_email          TEXT,
  p_enforce_domain BOOLEAN
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  IF p_enforce_domain THEN
    INSERT INTO public.aliases (mailbox_id, email, domain_id)
    SELECT m.id, p_email, m.domain_id
      FROM public.mailboxes m
     WHERE m.id = p_mailbox_id
       AND m.user_id = p_user_id
       AND m.is_primary = TRUE
       AND (
         p_domain_scope = 0
         OR (
           m.domain_id = p_domain_scope
           AND EXISTS (
             SELECT 1
               FROM public.domains d
              WHERE d.id = m.domain_id
                AND lower(d.name) = lower(split_part(p_email, '@', 2))
           )
         )
       )
    RETURNING id INTO v_id;
  ELSE
    INSERT INTO public.aliases (mailbox_id, email, domain_id)
    SELECT m.id, p_email, m.domain_id
      FROM public.mailboxes m
     WHERE m.id = p_mailbox_id
       AND m.user_id = p_user_id
       AND m.is_primary = TRUE
       AND (p_domain_scope = 0 OR m.domain_id = p_domain_scope)
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_alias_add(bigint,bigint,bigint,text,boolean) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_alias_add(bigint,bigint,bigint,text,boolean) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_mailbox_alias_remove(
  p_alias_id     BIGINT,
  p_user_id      BIGINT,
  p_domain_scope BIGINT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH removed AS (
    DELETE FROM public.aliases
     WHERE id = p_alias_id
       AND mailbox_id IN (
         SELECT id
           FROM public.mailboxes
          WHERE user_id = p_user_id
            AND is_primary = TRUE
            AND (p_domain_scope = 0 OR domain_id = p_domain_scope)
       )
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM removed;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_alias_remove(bigint,bigint,bigint) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_alias_remove(bigint,bigint,bigint) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_mailbox_ensure_primary(
  p_user_id BIGINT
) RETURNS VOID AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  INSERT INTO public.mailboxes (user_id, domain_id, email, display_name, type, is_primary)
  SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
    FROM public.users u
   WHERE u.id = p_user_id
  ON CONFLICT DO NOTHING;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_ensure_primary(bigint) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_ensure_primary(bigint) TO setjoin_worker;

-- Embedded verbatim from mailserver/sql/reducers/rust_migration_self_service.sql
-- rust_migration_self_service.sql — Wave 1.8d (#546d)
-- Owning mailboxes/migration_jobs self-service reducers retiring direct
-- cross-domain writes from identity/src/self_service.rs. Enforces strict
-- p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_migration_history_delete(
  p_user_id BIGINT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  WITH d AS (
    DELETE FROM public.migration_jobs
     WHERE user_id = p_user_id
       AND status IN ('completed', 'cancelled', 'failed')
    RETURNING id
  )
  SELECT count(*)::bigint INTO v_count FROM d;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_migration_job_insert(
  p_user_id           BIGINT,
  p_source_type       TEXT,
  p_source_config_enc BYTEA,
  p_target_mailbox_id BIGINT,
  p_conflict_strategy TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  INSERT INTO public.migration_jobs (
    user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status
  )
  SELECT p_user_id, p_source_type, p_source_config_enc, p_target_mailbox_id, p_conflict_strategy, 'pending'
   WHERE EXISTS (
     SELECT 1
       FROM public.mailboxes
      WHERE id = p_target_mailbox_id
        AND user_id = p_user_id
   )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- Embedded verbatim from mailserver/sql/reducers/rust_user_profile_ops.sql
-- rust_user_profile_ops.sql — Wave 1.8d (#546d)
-- Owning identity (users) self-service profile/view_prefs reducers retiring
-- direct cross-domain UPDATE users statements from user-settings. Enforces
-- strict p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_user_profile_update(
  p_user_id      BIGINT,
  p_display_name TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  WITH written AS (
    UPDATE public.users
       SET display_name = p_display_name,
           updated_at = now()
     WHERE id = p_user_id
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM written;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_user_view_prefs_set(
  p_user_id    BIGINT,
  p_view_prefs TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  WITH written AS (
    UPDATE public.users
       SET view_prefs = p_view_prefs::jsonb
     WHERE id = p_user_id
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM written;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_user_view_prefs_merge(
  p_user_id BIGINT,
  p_patch   TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  WITH written AS (
    UPDATE public.users
       SET view_prefs = COALESCE(view_prefs, '{}'::jsonb) || p_patch::jsonb
     WHERE id = p_user_id
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM written;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- Embedded verbatim from mailserver/sql/reducers/rust_webhook_self_ops.sql
-- rust_webhook_self_ops.sql — Wave 1.8d (#546d)
-- Owning platform (webhook_subscriptions) self-service reducers retiring
-- direct cross-domain writes from identity/src/self_service.rs. Enforces
-- strict p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_webhook_self_create(
  p_user_id       BIGINT,
  p_url           TEXT,
  p_event_types   TEXT,
  p_secret_enc    BYTEA,
  p_secret_key_id TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  INSERT INTO public.webhook_subscriptions (
    user_id, url, event_types, scope, secret_enc, secret_key_id
  )
  VALUES (
    p_user_id, p_url, p_event_types::jsonb, 'self', p_secret_enc, p_secret_key_id
  )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_webhook_self_delete(
  p_user_id BIGINT,
  p_id      BIGINT
) RETURNS BOOLEAN AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  DELETE FROM public.webhook_subscriptions
   WHERE id = p_id
     AND user_id = p_user_id
  RETURNING id INTO v_id;

  RETURN v_id IS NOT NULL;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- Embedded verbatim from mailserver/sql/reducers/rust_admin_bulk_role_job_retry.sql
-- rust_admin_bulk_role_job_retry.sql — Wave 1.8d (#546d)
-- Owning admin-identity (bulk_role_jobs) retry reducer retiring direct
-- cross-domain UPDATE from platform/src/jobs.rs. Writes core audit_write in the
-- same transaction when a job transitions error -> queued (compatible with
-- SqlAuditPosture::ReducerWritesCoreAudit). Strictly worker/admin-only.

CREATE OR REPLACE FUNCTION rust_admin_bulk_role_job_retry(
  p_actor  BIGINT,
  p_job_id BIGINT,
  p_ip     TEXT
) RETURNS BOOLEAN AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;

  UPDATE public.bulk_role_jobs
     SET status = 'queued',
         error = NULL,
         updated_at = now()
   WHERE id = p_job_id
     AND status = 'error'
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    RETURN FALSE;
  END IF;

  PERFORM public.audit_write(
    p_actor,
    'bulk_role_job_retry',
    'bulk_role_job',
    v_id,
    NULL,
    NULL,
    NULLIF(p_ip, '')::inet,
    '',
    'core'
  );
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_admin_bulk_role_job_retry(bigint,bigint,text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_admin_bulk_role_job_retry(bigint,bigint,text) TO setjoin_worker;

-- Embedded verbatim from mailserver/sql/reducers/rust_compliance_audit_log_insert.sql
-- rust_compliance_audit_log_insert.sql — Wave 1.8d (#546d)
-- Owning compliance (audit_log) insert reducer retiring direct cross-domain
-- INSERT into audit_log from identity/src/impersonation.rs. Enforces strict
-- p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_compliance_audit_log_insert(
  p_user_id    BIGINT,
  p_source_ip  TEXT,
  p_event_type TEXT,
  p_metadata   TEXT
) RETURNS VOID AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  INSERT INTO public.audit_log (user_id, source_ip, event_type, metadata)
  VALUES (p_user_id, NULLIF(p_source_ip, '')::inet, p_event_type, p_metadata::jsonb);
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- Embedded verbatim from mailserver/sql/reducers/rust_ca_admin_ops.sql
-- Wave 1.8 Phase 546d: worker-only p_actor-first admin reducer wrappers for
-- conditional-access (F03) so every admin write runs through
-- AdminWriteTx::execute_audited_reducer_contract (SqlAuditPosture::ReducerWritesCoreAudit)
-- with compile-time $1 = p_actor binding and zero double-auditing.
--
-- Every function enforces rls_caller_is_privileged() (setjoin_worker) and is
-- revoked from PUBLIC and setjoin_app.

CREATE OR REPLACE FUNCTION rust_ca_policy_soft_delete(
    p_actor bigint,
    p_id    bigint
) RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    PERFORM public.ca_policy_soft_delete(p_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_restore(
    p_actor bigint,
    p_id    bigint
) RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    PERFORM public.ca_policy_restore(p_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_restore_from_audit(
    p_actor    bigint,
    p_audit_id bigint
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_policy_restore_from_audit(p_audit_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_promote(
    p_actor bigint,
    p_id    bigint
) RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_policy_promote(p_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_import(
    p_actor bigint,
    p_doc   jsonb,
    p_mode  text
) RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_policy_import(p_doc, p_actor, p_mode);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_template_instantiate(
    p_actor bigint,
    p_slug  text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_template_instantiate(p_slug, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_named_location_set(
    p_actor       bigint,
    p_id          bigint,
    p_name        text,
    p_description text,
    p_cidrs       text[],
    p_countries   text[],
    p_trusted     boolean,
    p_delete      boolean,
    p_ip          text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_named_location_set(
        p_id,
        p_name,
        p_description,
        p_cidrs::cidr[],
        p_countries,
        p_trusted,
        p_delete,
        p_actor,
        NULLIF(p_ip, '')::inet
    );
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_named_location_restore(
    p_actor bigint,
    p_id    bigint,
    p_ip    text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_named_location_restore(p_id, p_actor, NULLIF(p_ip, '')::inet);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_auth_strength_set(
    p_actor        bigint,
    p_id           bigint,
    p_slug         text,
    p_name         text,
    p_combinations jsonb,
    p_min_acr      text,
    p_delete       boolean,
    p_ip           text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_auth_strength_set(
        p_id,
        p_slug,
        p_name,
        p_combinations,
        p_min_acr,
        p_delete,
        p_actor,
        NULLIF(p_ip, '')::inet
    );
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_revoke_user_sessions(
    p_actor   bigint,
    p_user_id bigint
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.revoke_user_sessions(p_user_id, 'all', 'admin_revoke_all', p_actor, NULL, NULL);
END;
$$;

REVOKE ALL ON FUNCTION public.rust_ca_policy_soft_delete(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_restore(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_restore_from_audit(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_promote(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_import(bigint, jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_template_instantiate(bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_named_location_set(bigint, bigint, text, text, text[], text[], boolean, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_named_location_restore(bigint, bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_auth_strength_set(bigint, bigint, text, text, jsonb, text, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_revoke_user_sessions(bigint, bigint) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_soft_delete(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_restore(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_restore_from_audit(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_promote(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_import(bigint, jsonb, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_template_instantiate(bigint, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_named_location_set(bigint, bigint, text, text, text[], text[], boolean, boolean, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_named_location_restore(bigint, bigint, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_auth_strength_set(bigint, bigint, text, text, jsonb, text, boolean, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_revoke_user_sessions(bigint, bigint) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_soft_delete(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_restore(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_restore_from_audit(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_promote(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_import(bigint, jsonb, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_template_instantiate(bigint, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_named_location_set(bigint, bigint, text, text, text[], text[], boolean, boolean, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_named_location_restore(bigint, bigint, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_auth_strength_set(bigint, bigint, text, text, jsonb, text, boolean, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_revoke_user_sessions(bigint, bigint) TO setjoin_worker;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_resolve_user_groups(
  p_ids BIGINT[]
) RETURNS TABLE(id BIGINT, name TEXT) AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY EXECUTE
    'SELECT id, COALESCE(name, '''') FROM public.user_groups WHERE id = ANY($1)'
    USING p_ids;
END;
$$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_ca_resolve_user_groups(bigint[]) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_ca_resolve_user_groups(bigint[]) TO setjoin_worker;

-- Embedded verbatim from mailserver/sql/reducers/rust_compliance_admin_ops.sql
-- Wave 1.8 Phase 546d: worker-only admin helpers for compliance (F04).
-- 1. rust_compliance_content_purge: p_actor-first wrapper around
--    content_purge_messages so AdminWriteTx::execute_audited_reducer_contract
--    (SqlAuditPosture::ReducerWritesCoreAudit) binds $1 = p_actor.
-- 2. rust_compliance_content_search_kql: STABLE worker-only KQL query executor
--    (mirroring rust_compliance_search_complete) so crates/domains/compliance
--    contains zero runtime format! SQL strings.

CREATE OR REPLACE FUNCTION rust_compliance_content_purge(
    p_actor      bigint,
    p_ids        bigint[],
    p_admin_user text,
    p_reason     text
) RETURNS TABLE(deleted_count integer, held_count integer, not_found_count integer)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
        SELECT c.deleted_count, c.held_count, c.not_found_count
          FROM public.content_purge_messages(p_ids, p_admin_user, p_reason, p_actor) AS c;
END;
$$;

CREATE OR REPLACE FUNCTION rust_compliance_content_search_kql(
    p_predicate text,
    p_values    text[]
) RETURNS TABLE(
    id          bigint,
    subject     text,
    from_addr   text,
    received_at text,
    email       text
)
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY EXECUTE
        'SELECT m.id, m.subject, m.from_addr, '
        || 'to_char(m.received_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS"Z"''), '
        || 'mb.email '
        || 'FROM public.messages m JOIN public.mailboxes mb ON mb.id = m.mailbox_id '
        || 'WHERE (' || p_predicate || ') '
        || 'ORDER BY m.received_at DESC LIMIT 500'
        USING p_values;
END;
$$;

REVOKE ALL ON FUNCTION public.rust_compliance_content_purge(bigint, bigint[], text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_compliance_content_search_kql(text, text[]) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE EXECUTE ON FUNCTION public.rust_compliance_content_purge(bigint, bigint[], text, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_compliance_content_search_kql(text, text[]) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.rust_compliance_content_purge(bigint, bigint[], text, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_compliance_content_search_kql(text, text[]) TO setjoin_worker;
    END IF;
END;
$$;

-- Embedded verbatim from mailserver/sql/reducers/rust_identity_client_version.sql
-- rust_identity_client_version.sql — optional client_versions lookup for /api/v1/version.
-- The active mailserver schema omits the legacy client_versions table; conformance tests
-- create and drop it dynamically. Checking to_regclass keeps the typed SQL contract valid
-- against the canonical schema while preserving Go's up_to_date fallback when absent.

CREATE OR REPLACE FUNCTION rust_identity_client_version_latest(
  p_platform text,
  p_app text
) RETURNS TABLE(
  version text,
  sha256 text,
  release_notes text,
  file_path text,
  release_date timestamptz
)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF to_regclass('public.client_versions') IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY EXECUTE
    'SELECT version, sha256, COALESCE(release_notes, ''''), COALESCE(file_path, ''''), release_date
       FROM public.client_versions
      WHERE platform = $1 AND app = $2
      ORDER BY string_to_array(version, ''.'')::int[] DESC
      LIMIT 1'
    USING p_platform, p_app;
END;
$$;


-- ── Function ACLs + PG 15+ owner-safe worker ownership for embedded reducers ──

REVOKE ALL ON FUNCTION public.resolve_identity(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_identity(text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_migration_history_delete(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_migration_history_delete(bigint) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_migration_job_insert(bigint,text,bytea,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_migration_job_insert(bigint,text,bytea,bigint,text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_user_profile_update(bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_user_profile_update(bigint,text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_user_view_prefs_set(bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_user_view_prefs_set(bigint,text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_user_view_prefs_merge(bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_user_view_prefs_merge(bigint,text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_webhook_self_create(bigint,text,text,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_webhook_self_create(bigint,text,text,bytea,text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_webhook_self_delete(bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_webhook_self_delete(bigint,bigint) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_compliance_audit_log_insert(bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_compliance_audit_log_insert(bigint,text,text,text) TO setjoin_app, setjoin_worker;

REVOKE ALL ON FUNCTION public.rust_identity_client_version_latest(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_identity_client_version_latest(text,text) TO setjoin_app, setjoin_worker;

-- ── Embedded hardened pure-boolean admin reach predicates (ARCH-018, verbatim) ──

CREATE OR REPLACE FUNCTION admin_can_reach(p_actor bigint, p_target bigint)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_actor IS NULL
       OR p_actor IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RETURN FALSE;
    END IF;
  END IF;
  RETURN EXISTS (
    SELECT 1
    FROM public.admin_role_assignments ra
    JOIN public.admin_role_groups rg ON rg.id = ra.role_group_id
    LEFT JOIN public.departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
    WHERE ra.user_id = p_actor
      AND (ra.expires_at IS NULL OR ra.expires_at > now())
      AND public.admin_assignment_active(ra.eligible, ra.activated_until)
      AND ( COALESCE(ra.domain_override, rg.domain_scope) IS NULL
            OR EXISTS (SELECT 1 FROM public.users tu WHERE tu.id = p_target
                        AND COALESCE(public.guest_account_host_domain(tu.id), tu.domain_id)
                            = COALESCE(ra.domain_override, rg.domain_scope)) )
      AND ( ra.scope_type IS NULL
            OR ( ra.scope_type = 'ou'
                 AND EXISTS (SELECT 1 FROM public.users tu JOIN public.departments td ON td.id = tu.department_id
                              WHERE tu.id = p_target
                                AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))) )
            OR ( ra.scope_type = 'set' AND public.admin_set_reaches(ra.scope_id, p_target) ) )
  );
END;
$$;

CREATE OR REPLACE FUNCTION admin_can_manage_with_permission(
    p_actor bigint, p_target bigint, p_permission text
) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_actor IS NULL
       OR p_actor IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RETURN FALSE;
    END IF;
  END IF;
  RETURN EXISTS (
    SELECT 1
      FROM public.admin_role_assignments ra
      JOIN public.admin_role_groups rg ON rg.id = ra.role_group_id
      LEFT JOIN public.departments sd
        ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
     WHERE ra.user_id = p_actor
       AND p_permission = ANY(rg.permissions)
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND public.admin_assignment_active(ra.eligible, ra.activated_until)
       AND (
         COALESCE(ra.domain_override, rg.domain_scope) IS NULL
         OR EXISTS (
           SELECT 1
             FROM public.users tu
            WHERE tu.id = p_target
              AND COALESCE(public.guest_account_host_domain(tu.id), tu.domain_id)
                  = COALESCE(ra.domain_override, rg.domain_scope)
         )
       )
       AND (
         ra.scope_type IS NULL
         OR (
           ra.scope_type = 'ou'
           AND EXISTS (
             SELECT 1
               FROM public.users tu
               JOIN public.departments td ON td.id = tu.department_id
              WHERE tu.id = p_target
                AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))
           )
         )
         OR (
           ra.scope_type = 'set'
           AND public.admin_set_reaches(ra.scope_id, p_target)
         )
       )
  );
END;
$$;

CREATE OR REPLACE FUNCTION admin_can_reach_perm(p_actor bigint, p_target bigint, p_perms text[])
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_actor IS NULL
       OR p_actor IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RETURN FALSE;
    END IF;
  END IF;
  RETURN EXISTS (
    SELECT 1
    FROM public.admin_role_assignments ra
    JOIN public.admin_role_groups rg ON rg.id = ra.role_group_id
    LEFT JOIN public.departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
    WHERE ra.user_id = p_actor
      AND rg.permissions && p_perms
      AND (ra.expires_at IS NULL OR ra.expires_at > now())
      AND public.admin_assignment_active(ra.eligible, ra.activated_until)
      AND ( COALESCE(ra.domain_override, rg.domain_scope) IS NULL
            OR EXISTS (SELECT 1 FROM public.users tu WHERE tu.id = p_target
                        AND COALESCE(public.guest_account_host_domain(tu.id), tu.domain_id)
                            = COALESCE(ra.domain_override, rg.domain_scope)) )
      AND ( ra.scope_type IS NULL
            OR ( ra.scope_type = 'ou'
                 AND EXISTS (SELECT 1 FROM public.users tu JOIN public.departments td ON td.id = tu.department_id
                              WHERE tu.id = p_target
                                AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))) )
            OR ( ra.scope_type = 'set' AND public.admin_set_reaches(ra.scope_id, p_target) ) )
  );
END;
$$;

-- ── Embedded pure-boolean first-boot setup check (verbatim from system_has_users.sql) ──

CREATE OR REPLACE FUNCTION system_has_users()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM public.users);
END;
$$;

COMMENT ON FUNCTION public.system_has_users() IS
  'First-boot setup check (Wave 1.8C, V288): pure-boolean SECURITY DEFINER '
  'helper owned by setjoin_worker so public `/` -> `/setup` detection works '
  'under FORCE RLS on public.users without disclosing any user row or count.';

-- ── Hardened V249 identity-address admission substrate & triggers ──
-- Under V288 FORCE RLS on users/mailboxes (and V287 FORCE RLS on aliases), invoker
-- triggers would be blinded to competing enabled users' claims under setjoin_app.
-- Hardening the trigger functions themselves (RETURNS trigger, never directly callable
-- from SQL, EXECUTE revoked from PUBLIC & setjoin_app) preserves BZ328 cross-person
-- exclusion without widening any table policy or exposing a lookup oracle. All
-- relations are schema-qualified and pg_temp is pinned last in search_path so a
-- session-local temp table can never shadow public.*.

CREATE OR REPLACE FUNCTION public.identity_address_claims(p_address TEXT)
RETURNS TABLE (user_id BIGINT)
LANGUAGE sql STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT u.id
    FROM public.users u
   WHERE u.enabled = TRUE
     AND (
       lower(u.email) = lower(p_address)
       OR lower(u.ad_upn) = lower(p_address)
       OR EXISTS (
         SELECT 1 FROM public.aliases a
         JOIN public.mailboxes m ON m.id = a.mailbox_id
         WHERE m.user_id = u.id AND lower(a.email) = lower(p_address)
       )
     )
$$;

CREATE OR REPLACE FUNCTION public.identity_address_admission_users()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_addresses TEXT[];
  v_addr      TEXT;
  v_other     BIGINT;
BEGIN
  IF NEW.enabled THEN
    SELECT array_agg(DISTINCT s.addr) INTO v_addresses
      FROM (
        SELECT lower(NEW.email) AS addr
        UNION ALL
        SELECT lower(NEW.ad_upn) WHERE NEW.ad_upn IS NOT NULL
        UNION ALL
        SELECT lower(a.email)
          FROM public.aliases a
          JOIN public.mailboxes m ON m.id = a.mailbox_id
         WHERE m.user_id = NEW.id
      ) s
     WHERE s.addr IS NOT NULL;
    FOREACH v_addr IN ARRAY v_addresses LOOP
      SELECT c.user_id INTO v_other
        FROM public.identity_address_claims(v_addr) c
       WHERE c.user_id <> NEW.id
       LIMIT 1;
      IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'identity address admission: % is already claimed by enabled user %',
                        v_addr, v_other
          USING ERRCODE = 'BZ328',
                HINT = '{"type":"identity_address_admission_conflict"}';
      END IF;
    END LOOP;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.identity_address_admission_aliases()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_addr  TEXT;
  v_owner BIGINT;
  v_other BIGINT;
BEGIN
  v_addr := lower(NEW.email);
  SELECT m.user_id INTO v_owner
    FROM public.mailboxes m
   WHERE m.id = NEW.mailbox_id;
  IF v_owner IS NOT NULL THEN
    SELECT c.user_id INTO v_other
      FROM public.identity_address_claims(v_addr) c
     WHERE c.user_id <> v_owner
     LIMIT 1;
    IF v_other IS NOT NULL THEN
      RAISE EXCEPTION 'identity address admission: % is already claimed by enabled user %',
                      v_addr, v_other
        USING ERRCODE = 'BZ328',
              HINT = '{"type":"identity_address_admission_conflict"}';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.identity_address_admission_mailboxes()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_addr TEXT;
BEGIN
  IF NEW.user_id IS NOT NULL AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    SELECT lower(a.email) INTO v_addr
      FROM public.aliases a
     WHERE a.mailbox_id = NEW.id
       AND EXISTS (
         SELECT 1 FROM public.identity_address_claims(lower(a.email)) c
          WHERE c.user_id <> NEW.user_id
       )
     LIMIT 1;
    IF v_addr IS NOT NULL THEN
      RAISE EXCEPTION 'identity address admission: % (alias on mailbox %) is already claimed by another enabled user',
                      v_addr, NEW.id
        USING ERRCODE = 'BZ328',
              HINT = '{"type":"identity_address_admission_conflict"}';
    END IF;
  END IF;
  RETURN NEW;
END $$;

-- PG 15+ owner-safe worker ownership transfer for SECURITY DEFINER resolve_identity(text),
-- pure-boolean ARCH-018 admin reach predicates, system_has_users(), and V249 admission triggers
DO $$
DECLARE
  v_granted_create boolean := false;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      EXECUTE 'GRANT CREATE ON SCHEMA public TO setjoin_worker';
      v_granted_create := true;
    END IF;
  END IF;

  BEGIN
    PERFORM public.apply_worker_ownership('public.resolve_identity(text)'::regprocedure);
    PERFORM public.apply_worker_ownership('public.admin_can_reach(bigint,bigint)'::regprocedure);
    PERFORM public.apply_worker_ownership('public.admin_can_manage_with_permission(bigint,bigint,text)'::regprocedure);
    PERFORM public.apply_worker_ownership('public.admin_can_reach_perm(bigint,bigint,text[])'::regprocedure);
    PERFORM public.apply_worker_ownership('public.system_has_users()'::regprocedure);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
      ALTER FUNCTION public.identity_address_admission_users() OWNER TO setjoin_worker;
      ALTER FUNCTION public.identity_address_admission_aliases() OWNER TO setjoin_worker;
      ALTER FUNCTION public.identity_address_admission_mailboxes() OWNER TO setjoin_worker;
      REVOKE ALL ON FUNCTION public.identity_address_admission_users() FROM PUBLIC, setjoin_app;
      REVOKE ALL ON FUNCTION public.identity_address_admission_aliases() FROM PUBLIC, setjoin_app;
      REVOKE ALL ON FUNCTION public.identity_address_admission_mailboxes() FROM PUBLIC, setjoin_app;
      GRANT EXECUTE ON FUNCTION public.identity_address_admission_users() TO setjoin_worker;
      GRANT EXECUTE ON FUNCTION public.identity_address_admission_aliases() TO setjoin_worker;
      GRANT EXECUTE ON FUNCTION public.identity_address_admission_mailboxes() TO setjoin_worker;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    IF v_granted_create THEN
      EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
    END IF;
    RAISE;
  END;

  IF v_granted_create THEN
    EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
  END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (288, now())
ON CONFLICT (version) DO NOTHING;

COMMIT;
