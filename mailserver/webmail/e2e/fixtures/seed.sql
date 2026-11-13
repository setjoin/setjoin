-- e2e/fixtures/seed.sql
-- Minimal seed for E2E testing. Assumes full schema is already applied.
-- Idempotent: deletes then re-inserts test data.
--
-- ── Fail-closed environment assertion (E2E-SEED-UNGUARDED-GLOBAL-MUTATION) ──
-- This file performs CLUSTER-GLOBAL posture mutations (MFA mode, CA toggles,
-- break-glass list, device upsert). It must never run against a real database.
-- The guard refuses to proceed unless the connected database name matches the
-- disposable e2e naming used by every in-repo consumer (mailserver_e2e by
-- default, or an explicit *_e2e / *_e2e_* disposable name). A deliberate
-- override is explicit and loud: pass `-v E2E_SEED_CONFIRM=1` to psql.
-- ON_ERROR_STOP is forced HERE so the guard's exception aborts this file even
-- when an ad-hoc caller forgot the flag — a refused seed must never fall
-- through and mutate the refused database.
\set ON_ERROR_STOP on
\if :{?E2E_SEED_CONFIRM}
SELECT set_config('e2e.seed.guard_confirmed', :'E2E_SEED_CONFIRM', FALSE);
\endif
DO $$
DECLARE
  v_db text := current_database();
BEGIN
  IF COALESCE(current_setting('e2e.seed.guard_confirmed', TRUE), '') <> '' THEN
    RAISE NOTICE 'seed guard: explicit E2E_SEED_CONFIRM override accepted for database "%"', v_db;
    RETURN;
  END IF;
  IF v_db = 'mailserver_e2e' OR v_db LIKE '%\_e2e' OR v_db LIKE '%\_e2e\_%' THEN
    RETURN; -- disposable e2e naming
  END IF;
  RAISE EXCEPTION
    'seed.sql refuses to run against database "%" — it is not a disposable e2e database. Pass -v E2E_SEED_CONFIRM=1 to psql to override deliberately.',
    v_db
    USING ERRCODE = 'P0001';
END
$$;

-- Ensure test domain exists
INSERT INTO domains (name, is_primary, is_local)
VALUES ('test.local', true, true)
ON CONFLICT (name) DO NOTHING;

-- Clean previous test data
DELETE FROM users WHERE email = 'e2e-drive-guest@external.test';
DELETE FROM mailboxes WHERE email LIKE '%@test.local';
DELETE FROM users WHERE email LIKE '%@test.local';

-- Test users (bcrypt hash of password)
-- TestPass123! -> $2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm
-- AdminPass123! -> $2a$10$5FPVqXGCfFeyTtmQIZo63uEiSkGPe/4vycJn8mbBAoRvg4NGthSJy
--
-- The users.admin_role enum was dropped by the RBAC cut-over: an admin's
-- authority now flows EXCLUSIVELY from a governed admin_role_assignments row
-- (seeded below for the admin → Super Admin, group id 1). is_admin is retained
-- as authn context (impersonate defense-in-depth) but grants nothing on its own.
INSERT INTO users (username, domain_id, email, display_name, password_hash, is_admin)
SELECT
  u.username,
  d.id,
  u.email,
  u.display_name,
  u.password_hash,
  u.is_admin
-- Note: the CA users (terms/risky/device) share alice's hash (TestPass123!) and,
-- being @test.local, inherit the mfa_exempt + mailbox + 'optional' MFA seeding below.
FROM (VALUES
  ('alice', 'alice@test.local', 'Alice Test', '$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm', FALSE),
  ('bob',   'bob@test.local',   'Bob Test',   '$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm', FALSE),
  ('visual','visual@test.local','Visual Test','$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm', FALSE),
  ('admin', 'admin@test.local', 'Admin Test', '$2a$10$5FPVqXGCfFeyTtmQIZo63uEiSkGPe/4vycJn8mbBAoRvg4NGthSJy', TRUE),
  ('limited-admin', 'limited-admin@test.local', 'Limited Admin Test', '$2a$10$5FPVqXGCfFeyTtmQIZo63uEiSkGPe/4vycJn8mbBAoRvg4NGthSJy', TRUE),
  ('terms', 'terms@test.local', 'Terms User', '$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm', FALSE),
  ('risky', 'risky@test.local', 'Risky User', '$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm', FALSE),
  ('device','device@test.local','Device User','$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm', FALSE)
) AS u(username, email, display_name, password_hash, is_admin)
CROSS JOIN domains d
WHERE d.name = 'test.local';

-- Grant the admin its authority via the GOVERNED axis: a Super Admin
-- (admin_role_groups id 1, AllPermissions) assignment with NULL granted_by
-- (system-seeded, no human granter). Without this row the admin resolves to an
-- empty permission set and is denied everywhere (deny-by-default).
INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
SELECT u.id, 1, NULL
FROM users u
WHERE u.email = 'admin@test.local'
ON CONFLICT (user_id, role_group_id) DO NOTHING;

-- A deliberately narrow real administrator for negative authorization E2E.
-- system.config makes the account a governed admin and exposes only the System
-- console; it intentionally lacks every Auth/Logs permission accepted by the
-- sign-in-history route.
INSERT INTO admin_role_groups (name, description, permissions, is_builtin)
VALUES ('E2E Limited System Admin', 'E2E negative authorization fixture', ARRAY['system.config'], FALSE)
ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions;
INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
SELECT u.id, g.id, NULL
FROM users u
JOIN admin_role_groups g ON g.name = 'E2E Limited System Admin'
WHERE u.email = 'limited-admin@test.local'
ON CONFLICT (user_id, role_group_id) DO NOTHING;

-- Test mailboxes
INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
SELECT
  u.id,
  d.id,
  u.email,
  u.display_name,
  'personal',
  TRUE
FROM users u
CROSS JOIN domains d
WHERE d.name = 'test.local' AND u.email LIKE '%@test.local';

-- E2E auth: the test users must log in via /auth/login without an MFA challenge
-- or a forced password change. Otherwise /auth/login returns an mfa_required /
-- force_pw_change token (still HTTP 200), and global.setup silently saves an
-- UNAUTHENTICATED session — which is why the whole suite couldn't run.
UPDATE users
   SET mfa_exempt = TRUE, must_change_password = FALSE
 WHERE email LIKE '%@test.local';

-- Drive member-picker privacy fixture: a real, enabled, mailbox-less guest.
-- The picker journey searches this exact email and proves the shared directory
-- seam excludes the guest discriminator rather than relying on users.enabled.
INSERT INTO users (username, domain_id, email, display_name, enabled)
SELECT 'e2e-drive-guest', d.id, 'e2e-drive-guest@external.test', 'E2E Drive Guest', TRUE
  FROM domains d
 WHERE d.name = 'guest.invalid';
INSERT INTO guest_accounts (
  user_id, invited_email, invited_by, invited_by_email, host_domain_id, status
)
SELECT guest.id, guest.email, inviter.id, inviter.email, host.id, 'active'
  FROM users guest
  JOIN users inviter ON inviter.email = 'alice@test.local'
  JOIN domains host ON host.name = 'test.local'
 WHERE guest.email = 'e2e-drive-guest@external.test';

-- Relax org-wide MFA enforcement for the test env (belt-and-suspenders with
-- mfa_exempt above). 'optional' is the non-forcing value (modes: optional | required).
UPDATE system_config SET value = '"optional"'::jsonb
 WHERE key = 'mfa_enforcement_mode';

-- Guest invitation delivery requires an absolute authserver public URL so the
-- emailed acceptance link is valid. The E2E gateway proxies /guest-invite/* to
-- the authserver at this same browser-visible origin.
INSERT INTO system_config (key, value)
VALUES ('authserver.public_url', to_jsonb('http://localhost:8080'::text))
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

-- ════════════════════════════════════════════════════════════════════════════
-- Conditional-Access / offline E2E fixtures  (gated specs; E2E_CA_LIVE=1).
--
-- Toggle posture baked here is the SAFE base:
--   cae_runtime ON         → RequireRuntimeAccess re-evaluates per request.
--   conditional_access ON  → PolicyEngine.Evaluate actually runs (it short-circuits
--                            to ALLOW when this is OFF, regardless of cae_runtime).
--   user_risk ON           → login embeds the JWT Risk claim from user_risk.
--   device_lockdown OFF    → the DEVICE-lockdown hard gate needs BOTH
--                            conditional_access AND device_lockdown, so it stays
--                            inert; otherwise every non-break-glass user without an
--                            approved device would be 403'd on /jmap, breaking the
--                            default suite. The device-lockdown + banner specs flip
--                            device_lockdown ON themselves (admin API →
--                            trg_feature_notify → live hot-reload) and restore.
--
-- The terms/risk policies are USER-SCOPED to dedicated users (terms@/risky@) so
-- alice/admin are never blocked even with cae_runtime ON.
-- ════════════════════════════════════════════════════════════════════════════

-- Idempotency: drop prior CA fixtures (devices/user_risk cascade from users on
-- the @test.local DELETE above; policies + ToU do not, so clear them explicitly).
DELETE FROM conditional_access_policies WHERE name LIKE 'e2e-%';
DELETE FROM terms_of_use WHERE name = 'E2E Acceptable Use';

-- Sign-in activity (end-user History tab reads GET /user/login-history → login_events).
-- The authserver records these best-effort on /auth/login, but the E2E run needs a
-- deterministic, non-empty history regardless, so seed a success + a failure per
-- @test.local user (real rows the real endpoint returns).
DELETE FROM login_events WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.local');
INSERT INTO login_events (user_id, success, client, protocol, auth_method, source_ip, location, device_name, occurred_at)
SELECT u.id, TRUE, 'web', 'http', 'password', '203.0.113.10'::inet, 'Test City, TC', 'E2E Browser', now() - interval '1 hour'
FROM users u WHERE u.email LIKE '%@test.local';
INSERT INTO login_events (user_id, success, fail_reason, client, protocol, auth_method, source_ip, location, occurred_at)
SELECT u.id, FALSE, 'bad_password', 'web', 'http', 'password', '198.51.100.5'::inet, 'Other City, OC', now() - interval '2 hour'
FROM users u WHERE u.email LIKE '%@test.local';

-- Base toggle posture (rows pre-exist from the baseline; flip the safe ones ON,
-- keep device_lockdown OFF — see the block comment above).
UPDATE feature_toggles SET enabled = TRUE  WHERE key IN ('feature.cae_runtime', 'feature.user_risk', 'feature.conditional_access', 'feature.email_address_policy');
UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.device_lockdown';

-- Super Admin (admin_role_groups id 1) in the collapsed baseline predates the CA
-- permission pair (access.policy_read/write) — code's AllPermissions includes them,
-- but the seeded role group does not (baseline drift). Grant them so the admin can
-- drive the CA console + mailctl CA verbs (init/promote/export/why/signin-log/apply).
UPDATE admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p)
                      FROM unnest(permissions || ARRAY['access.policy_read', 'access.policy_write']) p)
 WHERE id = 1;

-- Break-glass: admin is always exempt (Decision 9 build-gate refuses to enforce
-- device lockdown unless this list is non-empty). Stored as a JSON array of ids.
UPDATE system_config
   SET value = (SELECT to_jsonb(array_agg(id)) FROM users WHERE email = 'admin@test.local')
 WHERE key = 'ca_break_glass_user_ids';

-- ── Terms-of-Use: an enabled, scroll-required document terms@ has not accepted ──
INSERT INTO terms_of_use (name, version, body_md, lang, require_scroll, enabled)
VALUES ('E2E Acceptable Use', 1,
        E'# Acceptable Use Policy\n\n' || repeat(E'You must read and accept these terms before continuing. ', 60),
        'en', TRUE, TRUE);

-- require_terms policy (state=on, user-scoped to terms@) → /jmap 403 remediation=terms.
-- Distinct high priorities (ca_policies_priority_unique_idx forbids collisions).
INSERT INTO conditional_access_policies (priority, name, state, enabled, scope_type, scope_target, conditions, actions)
SELECT 99001, 'e2e-require-terms', 'on', TRUE, 'user', u.id::text, '{}'::jsonb,
       jsonb_build_object('action', 'require_terms',
                          'tou_id', (SELECT id FROM terms_of_use WHERE name = 'E2E Acceptable Use' AND version = 1 AND lang = 'en'))
FROM users u WHERE u.email = 'terms@test.local';

-- ── Risk: risky@ is at an elevated band so its JWT carries Risk.Level='high' ──
INSERT INTO user_risk (user_id, score, level, signals)
SELECT u.id, 80, 'high', '["impossible_travel"]'::jsonb
FROM users u WHERE u.email = 'risky@test.local'
ON CONFLICT (user_id) DO UPDATE SET score = 80, level = 'high', signals = '["impossible_travel"]'::jsonb;

-- require_risk_remediation policy (state=on, user-scoped to risky@) → blocks only
-- when the caller's risk band is elevated → /jmap 403 remediation=risk.
INSERT INTO conditional_access_policies (priority, name, state, enabled, scope_type, scope_target, conditions, actions)
SELECT 99002, 'e2e-require-risk', 'on', TRUE, 'user', u.id::text, '{}'::jsonb,
       jsonb_build_object('action', 'require_risk_remediation')
FROM users u WHERE u.email = 'risky@test.local';

-- ── Device-lockdown: an enrolled+approved device for device@ with a known HMAC ──
-- secret. The device-lockdown spec flips the two toggles ON and proves
-- X-Device-HMAC(id:timestamp) → 200 / no-proof → 403 BZ095. Fixed id + secret so
-- the spec can sign without an extra round-trip.
INSERT INTO devices (id, user_id, device_name, platform, fingerprint, hmac_secret, enroll_state, credential_kind)
SELECT 990001, u.id, 'E2E Approved Device', 'test', 'e2e-device-fp-990001',
       'e2e-device-hmac-secret-990001', 'approved', 'hmac'
FROM users u WHERE u.email = 'device@test.local'
ON CONFLICT (id) DO UPDATE SET enroll_state = 'approved', revoked_at = NULL, hmac_secret = EXCLUDED.hmac_secret;
SELECT setval(pg_get_serial_sequence('devices', 'id'), GREATEST((SELECT MAX(id) FROM devices), 990001));

-- ── Seed inbound messages to alice's inbox so the mail surface (list, reading
--    pane, reply/forward, triage, snooze) is exercisable end to end. deliver() is
--    the real inbound path; p_raw_ref is a placeholder string — no S3 blob is
--    needed because the reading pane renders body_text/html (which deliver stores).
--    Staggered received_at so ordering is deterministic.
DO $$
DECLARE i INT;
BEGIN
  FOR i IN 1..3 LOOP
    PERFORM deliver(
      'e2e-seed-ref-' || i,                       -- p_raw_ref (placeholder)
      '<e2e-seed-' || i || '@test.local>',        -- p_message_id
      'partner' || i || '@partner.test',          -- p_from_addr
      'Partner ' || i,                            -- p_from_name
      'alice@test.local',                         -- p_to_addr (resolves to alice's mailbox)
      '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,       -- to/cc/bcc header lists
      'E2E seeded message ' || i,                 -- p_subject
      NULL, NULL,
      'Body of seeded message ' || i || '.',      -- p_body
      NULL, 200, FALSE,
      now() - (i || ' hours')::INTERVAL,          -- p_received_at (staggered)
      'pass', 'pass', 'pass', 0.0, NULL);
  END LOOP;

  -- Dedicated fixture for focused-other.spec.ts's pile move (Focused ↔ Other).
  -- Its subject intentionally does NOT match 'E2E seeded message' so
  -- inbox-read's exact row-count assertion is isolated from the move.
  PERFORM deliver(
    'e2e-seed-pile-ref', '<e2e-seed-pile@test.local>',
    'partner-pile@partner.test', 'Partner Pile',
    'alice@test.local',
    '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
    'E2E pile probe',
    NULL, NULL,
    'Body of the pile probe message.',
    NULL, 200, FALSE,
    now() - INTERVAL '45 minutes',
    'pass', 'pass', 'pass', 0.0, NULL);

  -- An HTML message with a body >256 chars. Guards the regression where the reading
  -- pane under-fetched (no bodyHTML) and truncated every body to the 256-char preview:
  -- HTML must render (the "Show HTML" control appears) and the full text be present.
  PERFORM deliver(
    'e2e-seed-html-ref', '<e2e-seed-html@test.local>',
    'partner-html@partner.test', 'Partner HTML',
    'alice@test.local',
    '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
    'E2E HTML render check',
    NULL, NULL,
    'Plain fallback for the HTML render check message.',          -- p_body_text
    '<h2>HTML render check</h2><p>' || repeat('This sentence pads the HTML body well past the 256-character preview cap so a regression that truncates to preview is caught. ', 4) || '<b>HTML-MARKER-END</b></p>',  -- p_body_html
    400, FALSE,
    now() - INTERVAL '30 minutes',
    'pass', 'pass', 'pass', 0.0, NULL);
END $$;

-- The welcome-tour visual matrix needs a mailbox whose rows cannot be polluted
-- by the behavioral specs. Keep this fixture intentionally small and static so
-- full-viewport screenshots are order-independent within the complete suite.
DO $$
DECLARE i INT;
BEGIN
  FOR i IN 1..3 LOOP
    PERFORM deliver(
      'e2e-visual-ref-' || i,
      '<e2e-visual-' || i || '@test.local>',
      'partner' || i || '@partner.test',
      'Partner ' || i,
      'visual@test.local',
      '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
      'E2E seeded message ' || i,
      NULL, NULL,
      'Body of seeded message ' || i || '.',
      NULL, 200, FALSE,
      now() - (i || ' hours')::INTERVAL,
      'pass', 'pass', 'pass', 0.0, NULL);
  END LOOP;

  PERFORM deliver(
    'e2e-visual-html-ref', '<e2e-visual-html@test.local>',
    'partner-html@partner.test', 'Partner HTML',
    'visual@test.local',
    '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
    'E2E HTML render check',
    NULL, NULL,
    'Plain fallback for the HTML render check message.',
    NULL, 200, FALSE,
    now() - INTERVAL '30 minutes',
    'pass', 'pass', 'pass', 0.0, NULL);

  PERFORM deliver(
    'e2e-visual-pile-ref', '<e2e-visual-pile@test.local>',
    'partner-pile@partner.test', 'Partner Pile',
    'visual@test.local',
    '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
    'E2E pile probe',
    NULL, NULL,
    'Body of the pile probe message.',
    NULL, 200, FALSE,
    now() - INTERVAL '45 minutes',
    'pass', 'pass', 'pass', 0.0, NULL);
END $$;
