-- provision_account: the ONE seam that creates (or upserts) a person + their
-- primary personal mailbox (+ optional aliases) from any provisioning source.
--
-- Replaces five hand-rolled Go call sites that each re-implemented raw INSERTs
-- into users / mailboxes / aliases (admin create, admin CSV import, AD sync,
-- LDAP sync, SCIM). Several of those omitted NOT NULL columns (username,
-- domain_id) or never created the primary mailbox at all — "logic where the
-- data is" puts the full, schema-correct sequence in one place.
--
-- Idempotent / upsert by a stable identity key, chosen in this order:
--   1. p_ad_object_guid (AD sync)        — users.ad_object_guid UNIQUE
--   2. p_scim_external_id (SCIM)         — users.scim_external_id UNIQUE
--   3. lower(p_email)                    — users(lower(email)) UNIQUE
-- A match UPDATEs the existing person + their primary mailbox; otherwise a new
-- user + primary mailbox are INSERTed. user_id and mailbox_id come from their
-- own independent BIGSERIAL sequences (never coincident — ADR-003).
--
-- Resolves domain_id from the email domain. The admin/local path auto-creates a
-- LOCAL domain row if the domain is unknown (pre-gated by resolveLocalDomain at the
-- call site). Directory-sync sources (ad/ldap/scim/scim-jit/sso-jit) must NOT
-- auto-vivify: a mistyped or attacker-influenced IdP mail attribute would otherwise
-- register a locally-authoritative domain (deliver_* then accepts inbound mail for
-- any is_local domain) — directory-attribute-driven trust escalation. For those
-- sources the domain must ALREADY exist and be local, else BZ056.
-- Derives the username from the email local-part when p_username is absent
-- (UNIQUE(username, domain_id), matching the existing reducers).
--
-- Returns JSONB: {user_id, mailbox_id, domain_id, username, created,
--   skipped_aliases}. skipped_aliases is a (usually empty) array of requested
--   alias addresses that were NOT created because they are already an alias of a
--   DIFFERENT mailbox — a non-fatal cross-mailbox collision surfaced as a warning
--   rather than failing the whole provision (an idempotent re-run that re-requests
--   THIS mailbox's own existing alias stays silent / is not reported).
--
-- BZ072 invalid_provision_email — email is NULL/blank or has no domain part.
-- BZ056 provision_unknown_domain — a directory-sync source named an unknown or
--       non-local domain (no auto-vivify on the sync path).
--
-- NOTE: this owns the person + PRIMARY mailbox. Secondary mailboxes for an
-- already-existing user (admin_mailboxes "create extra mailbox") are a separate
-- concern and intentionally NOT routed here.

-- Guest G0 added p_guest/p_invited_by/p_guest_expires_at, changing the arity.
-- CREATE OR REPLACE does NOT replace across a different signature — it would
-- leave the old 19-param overload alive on an upgraded DB, and a named-args
-- caller (scim_upsert_user's funnel, AD/LDAP) would then match BOTH and die
-- 42725 "function is not unique", breaking MEMBER provisioning. Drop the old
-- overload first (the chat_channel_update precedent, chat_channel.sql:156).
DROP FUNCTION IF EXISTS provision_account(TEXT,TEXT,TEXT,TEXT,BOOLEAN,BOOLEAN,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT[]);
DROP FUNCTION IF EXISTS provision_account(TEXT,TEXT,TEXT,TEXT,BOOLEAN,BOOLEAN,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT[],BOOLEAN,BIGINT,TIMESTAMPTZ);
-- Also retire the immediately-preceding 23-parameter form (…, p_create_only):
-- a DEFAULTed p_actor appended AFTER it makes positional calls omitting the
-- actor match BOTH overloads → 42725 ambiguity on every upgraded database
-- (fresh loads never see the old row). Every prior signature is retired so
-- exactly one provision_account exists after this file runs.
DROP FUNCTION IF EXISTS provision_account(TEXT,TEXT,TEXT,TEXT,BOOLEAN,BOOLEAN,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT[],BOOLEAN,BIGINT,TIMESTAMPTZ,BOOLEAN);
CREATE OR REPLACE FUNCTION provision_account(
  p_email            TEXT,
  p_display_name     TEXT    DEFAULT NULL,
  p_username         TEXT    DEFAULT NULL,
  p_password_hash    TEXT    DEFAULT NULL,
  p_is_local_admin   BOOLEAN DEFAULT NULL,
  p_enabled          BOOLEAN DEFAULT NULL,
  p_sync_source      TEXT    DEFAULT NULL,
  p_first_name       TEXT    DEFAULT NULL,
  p_last_name        TEXT    DEFAULT NULL,
  p_job_title        TEXT    DEFAULT NULL,
  p_phone            TEXT    DEFAULT NULL,
  p_department_id    BIGINT  DEFAULT NULL,
  p_quota_bytes      BIGINT  DEFAULT NULL,
  p_ad_object_guid   UUID    DEFAULT NULL,
  p_ad_usn_changed   BIGINT  DEFAULT NULL,
  p_ad_upn           TEXT    DEFAULT NULL,
  p_krb5_principal   TEXT    DEFAULT NULL,
  p_scim_external_id TEXT    DEFAULT NULL,
  p_aliases          TEXT[]  DEFAULT NULL,
  -- Guest Accounts G0 (spec P1): guest mode — no mailbox, no domain vivify,
  -- no chat autojoin; satellite insert with host_domain_id resolved from the
  -- inviter. BZ221 both directions at this ONE choke (codex C-1).
  p_guest            BOOLEAN DEFAULT FALSE,
  p_invited_by       BIGINT  DEFAULT NULL,
  p_guest_expires_at TIMESTAMPTZ DEFAULT NULL,
  -- Admin/CSV creation must never inherit this reducer's directory-upsert
  -- behavior. An existing stable identity raises 23505 before any committed
  -- account mutation; any setup earlier in this transaction rolls back.
  p_create_only      BOOLEAN DEFAULT FALSE,
  -- WP3 audit coverage: trusted acting-admin identity for the account_provision
  -- audit row. Appended DEFAULT NULL — every pre-existing call shape is
  -- unchanged; AD/LDAP/SCIM system flows pass no actor (sync_source notes
  -- carry the system origin instead).
  p_actor            BIGINT  DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_email        TEXT;
  v_domain_name  TEXT;
  v_domain_id    BIGINT;
  v_username     TEXT;   -- effective username (explicit, or derived for a fresh row)
  v_display_name TEXT;    -- effective display_name (explicit, or derived for a fresh row)
  v_username_in  TEXT;    -- explicitly-provided username, normalized (or NULL)
  v_dispname_in  TEXT;    -- explicitly-provided display_name, normalized (or NULL)
  v_enabled      BOOLEAN := COALESCE(p_enabled, TRUE);
  v_cur_admin    BOOLEAN;   -- pre-update authority state (astra P2-5 audit arm)
  v_cur_enabled  BOOLEAN;
  v_sync_source  TEXT    := COALESCE(NULLIF(p_sync_source, ''), 'local');
  v_user_id      BIGINT;
  v_mailbox_id   BIGINT;
  v_created      BOOLEAN := FALSE;
  v_alias        TEXT;
  v_alias_email  TEXT;
  v_alias_domain TEXT;
  v_alias_dom_id BIGINT;
  v_alias_ins_id BIGINT;   -- mailbox_id RETURNed by the alias INSERT (NULL ⇒ ON CONFLICT fired)
  v_alias_own_id BIGINT;   -- mailbox that already owns a conflicting alias
  v_skipped      JSONB := '[]'::jsonb;  -- cross-mailbox alias collisions (non-fatal warnings)
  v_host_domain_id BIGINT;
  v_inviter_email  TEXT;
BEGIN
  -- Provisioning can change users.enabled (including guest reprovisioning).
  -- Fence before identity/person/guest rows so authority writers share one order.
  PERFORM admin_authority_fence();

  -- ── Validate + normalize email ──────────────────────────────────────────
  v_email := lower(trim(COALESCE(p_email, '')));
  IF v_email = '' THEN
    RAISE EXCEPTION 'provision_account: email is required'
      USING ERRCODE = 'BZ072',
            HINT = jsonb_build_object('type', 'invalid_provision_email', 'email', p_email)::TEXT;
  END IF;

  v_domain_name := split_part(v_email, '@', 2);
  IF v_domain_name = '' OR position('@' IN v_email) = 0 THEN
    RAISE EXCEPTION 'provision_account: cannot extract domain from email %', p_email
      USING ERRCODE = 'BZ072',
            HINT = jsonb_build_object('type', 'invalid_provision_email', 'email', p_email)::TEXT;
  END IF;

  -- ── Derive defaults ─────────────────────────────────────────────────────
  -- Separate "explicitly provided" (normalized, or NULL) from the fresh-row
  -- default. On UPDATE the *_in values COALESCE against the existing column, so
  -- a NULL arg never clobbers a previously-set name (mirrors every other field);
  -- only a brand-new row falls back to the email / local-part.
  -- Hoisted above the domain-resolve block (Guest G0 Task 3, eng re-score
  -- MINOR-1): the guest arm below reads v_dispname_in/v_display_name and must
  -- run BEFORE domain resolution (guests never vivify their external domain);
  -- this block is side-effect-free (no DB access), so moving it earlier is safe.
  v_username_in  := NULLIF(trim(COALESCE(p_username, '')), '');
  v_dispname_in  := NULLIF(trim(COALESCE(p_display_name, '')), '');
  v_username     := COALESCE(v_username_in, split_part(v_email, '@', 1));
  v_display_name := COALESCE(v_dispname_in, v_email);

  -- ── Guest arm (G0, spec P1) ─────────────────────────────────────────────
  IF p_guest THEN
    IF p_invited_by IS NULL THEN
      RAISE EXCEPTION 'provision_account: guest mode requires p_invited_by'
        USING ERRCODE = 'BZ072',
              HINT = jsonb_build_object('type', 'invalid_provision_email', 'email', p_email)::TEXT;
    END IF;
    -- host_domain_id: the IMMUTABLE ownership axis — the inviting org domain,
    -- resolved from the inviter at provision, NEVER updated after (codex C-2).
    SELECT u.domain_id, u.email INTO v_host_domain_id, v_inviter_email
      FROM users u WHERE u.id = p_invited_by;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'provision_account: inviter % not found', p_invited_by
        USING ERRCODE = 'BZ072',
              HINT = jsonb_build_object('type', 'invalid_provision_email', 'email', p_email)::TEXT;
    END IF;
    -- All guests land in the system guest domain (is_local = FALSE — inbound
    -- delivery never accepts for it). NEVER vivify the external domain.
    SELECT id INTO v_domain_id FROM domains WHERE name = 'guest.invalid';

    SELECT id INTO v_user_id FROM users WHERE lower(email) = v_email;
    IF p_create_only AND v_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'provision_account: account already exists'
        USING ERRCODE = '23505',
              CONSTRAINT = 'users_email_lower_unique';
    END IF;
    -- BZ221 arm 1: guest-mode provisioning REFUSES an email collision with a
    -- non-guest row (a member must never be silently rewritten into a guest).
    IF v_user_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM guest_accounts WHERE user_id = v_user_id) THEN
      RAISE EXCEPTION 'provision_account: % already belongs to a non-guest account', v_email
        USING ERRCODE = 'BZ221',
              HINT = '{"type":"conflict","detail":"email belongs to an existing member account"}';
    END IF;

    IF v_user_id IS NOT NULL THEN
      -- P9 re-arm, guest→guest ONLY: refresh mutable fields; identity axes
      -- (host_domain_id, invited_by*, user_id) are immutable.
      UPDATE users SET
        display_name  = COALESCE(v_dispname_in, display_name),
        password_hash = COALESCE(p_password_hash, password_hash),
        -- C-7 sync (re-score minor): enabled must track the RESULTING satellite
        -- status, never unconditional TRUE — a no-password re-provision of a
        -- disabled guest must NOT leave enabled=TRUE/status='disabled'.
        -- Resulting status is 'active' iff a password is provided now OR the
        -- pre-update status is already 'active' (the satellite UPDATE below
        -- only flips to 'active' when p_password_hash IS NOT NULL).
        enabled       = (p_password_hash IS NOT NULL
                         OR EXISTS (SELECT 1 FROM guest_accounts g
                                    WHERE g.user_id = v_user_id AND g.status = 'active')),
        updated_at    = now()
      WHERE id = v_user_id;
      UPDATE guest_accounts SET
        status     = CASE WHEN p_password_hash IS NOT NULL THEN 'active' ELSE status END,
        expires_at = COALESCE(p_guest_expires_at, expires_at),
        -- G5: a re-invite repairs a sponsorless guest but never overwrites an
        -- explicit transfer. The immutable invited_by audit axis stays intact.
        sponsor_user_id = COALESCE(sponsor_user_id, p_invited_by),
        updated_at = now()
      WHERE user_id = v_user_id;
    ELSE
      -- username = the FULL lowercased external email (deterministic,
      -- collision-safe within the one guest domain — spec P1).
      INSERT INTO users (username, domain_id, email, display_name,
                         password_hash, is_local_admin, enabled, sync_source)
      VALUES (v_email, v_domain_id, v_email, v_display_name,
              p_password_hash, FALSE, p_password_hash IS NOT NULL, 'local')
      RETURNING id INTO v_user_id;
      INSERT INTO guest_accounts (user_id, invited_email, invited_by, invited_by_email,
                                  sponsor_user_id, host_domain_id, status, expires_at)
      VALUES (v_user_id, v_email, p_invited_by, v_inviter_email, p_invited_by, v_host_domain_id,
              CASE WHEN p_password_hash IS NOT NULL THEN 'active' ELSE 'invited' END,
              p_guest_expires_at);
      v_created := TRUE;
    END IF;

    -- NO mailbox, NO chat_autojoin_defaults, NO email-address policy,
    -- NO aliases — a guest is a mailbox-less principal, full stop.
    RETURN jsonb_build_object(
      'user_id',         v_user_id,
      'mailbox_id',      NULL,
      'domain_id',       v_domain_id,
      'username',        v_email,
      'created',         v_created,
      'skipped_aliases', '[]'::jsonb
    );
  END IF;

  -- ── Resolve the domain ──────────────────────────────────────────────────
  -- Directory-sync sources may only provision into a domain that is ALREADY local
  -- (no auto-vivify — sync input must never mint an authoritative LOCAL domain).
  -- The admin/local path keeps auto-vivify (its call site pre-gates via
  -- resolveLocalDomain).
  IF v_sync_source IN ('ad','ldap','scim','scim-jit','sso-jit') THEN
    SELECT id INTO v_domain_id FROM domains WHERE name = v_domain_name AND is_local = TRUE;
    IF v_domain_id IS NULL THEN
      RAISE EXCEPTION 'provision_account: directory sync cannot provision into unknown/non-local domain %', v_domain_name
        USING ERRCODE = 'BZ056',
              HINT = jsonb_build_object('type', 'provision_unknown_domain',
                                        'domain', v_domain_name,
                                        'sync_source', v_sync_source)::TEXT;
    END IF;
  ELSE
    SELECT id INTO v_domain_id FROM domains WHERE name = v_domain_name;
    IF v_domain_id IS NULL THEN
      INSERT INTO domains (name, is_local) VALUES (v_domain_name, TRUE)
      RETURNING id INTO v_domain_id;
    END IF;
  END IF;

  -- ── Locate an existing person by the strongest available stable key ──────
  IF p_ad_object_guid IS NOT NULL THEN
    SELECT id INTO v_user_id FROM users WHERE ad_object_guid = p_ad_object_guid;
  END IF;
  IF v_user_id IS NULL AND p_scim_external_id IS NOT NULL AND p_scim_external_id != '' THEN
    SELECT id INTO v_user_id FROM users WHERE scim_external_id = p_scim_external_id;
  END IF;
  IF v_user_id IS NULL THEN
    SELECT id INTO v_user_id FROM users WHERE lower(email) = v_email;
  END IF;

  IF p_create_only AND v_user_id IS NOT NULL THEN
    RAISE EXCEPTION 'provision_account: account already exists'
      USING ERRCODE = '23505',
            CONSTRAINT = 'users_email_lower_unique';
  END IF;

  -- BZ221 arm 2 (codex C-1): non-guest provisioning (admin/CSV/AD/LDAP/SCIM —
  -- scim_upsert_user is a thin caller of this choke) REFUSES a collision with
  -- a guest row: the UPDATE path below would mint the guest a mailbox via the
  -- self-heal and silently convert it to a member. Guest→member "upgrade" is
  -- an explicit admin act (a named G5+ seam), never a provisioning side effect.
  IF v_user_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM guest_accounts WHERE user_id = v_user_id) THEN
    RAISE EXCEPTION 'provision_account: % belongs to a guest account (guest→member conversion is not a provisioning side effect)', v_email
      USING ERRCODE = 'BZ221',
            HINT = '{"type":"conflict","detail":"email belongs to an existing guest account"}';
  END IF;

  IF v_user_id IS NOT NULL THEN
    -- ── UPDATE existing person (COALESCE: NULL args never clobber state) ───
    -- Capture the pre-update authority state: an is_local_admin or enabled
    -- flip on an EXISTING account is an authority transition and audits
    -- below even though ordinary sync traffic stays silent (astra P2-5).
    SELECT is_local_admin, enabled INTO v_cur_admin, v_cur_enabled
      FROM users WHERE id = v_user_id;
    UPDATE users SET
      domain_id        = v_domain_id,
      email            = CASE WHEN EXISTS (SELECT 1 FROM field_policy fp
                                           WHERE fp.user_id = v_user_id AND fp.field = 'email' AND fp.policy = 'local_only')
                              THEN email ELSE v_email END,
      display_name     = COALESCE(v_dispname_in, display_name),
      username         = COALESCE(v_username_in, username),
      first_name       = COALESCE(p_first_name, first_name),
      last_name        = COALESCE(p_last_name, last_name),
      job_title        = COALESCE(p_job_title, job_title),
      phone            = COALESCE(p_phone, phone),
      department_id    = COALESCE(p_department_id, department_id),
      password_hash    = COALESCE(p_password_hash, password_hash),
      is_local_admin   = COALESCE(p_is_local_admin, is_local_admin),
      enabled          = v_enabled,
      sync_source      = v_sync_source,
      ad_object_guid   = COALESCE(p_ad_object_guid, ad_object_guid),
      ad_usn_changed   = COALESCE(p_ad_usn_changed, ad_usn_changed),
      ad_upn           = COALESCE(p_ad_upn, ad_upn),
      -- krb5_principal is FLOOR-PROTECTED on the UPDATE path and is
      -- deliberately absent from this SET list: it is the Kerberos/SPNEGO SSO
      -- identity, so an upsert that falls through to an existing user (the AD
      -- unmatched-GUID → email-match arm, scim_upsert_user, any re-provision)
      -- must never rewrite it — a directory-supplied principal would let a
      -- controlled directory entry point an attacker-authenticatable principal
      -- at a victim account. This mirrors the Go always-local-only floor
      -- (alwaysLocalOnlyFields in mailserver/internal/ldaputil/ldaputil.go,
      -- enforced by EnforceAlwaysLocalOnly/ApplyUserUpdate); each side notes the
      -- other. Creation-time provisioning below still writes p_krb5_principal.
      -- The ONLY sanctioned change on an existing user is the audited,
      -- intentional admin action (POST /admin/ad/principal →
      -- internal/admin/admin_ad.go SetPrincipal).
      scim_external_id = COALESCE(p_scim_external_id, scim_external_id),
      updated_at       = now()
    WHERE id = v_user_id
    -- Capture the *effective* (post-COALESCE) values so the mailbox sync, the
    -- self-heal INSERT, and the returned JSONB all report what was actually
    -- stored — not the fresh-row default.
    RETURNING display_name, username INTO v_display_name, v_username;

    IF COALESCE(v_cur_admin, FALSE) IS DISTINCT FROM COALESCE(p_is_local_admin, v_cur_admin)
       OR v_cur_enabled IS DISTINCT FROM v_enabled THEN
      PERFORM audit_write(
        p_actor, 'account_authority_change', 'user', v_user_id,
        jsonb_build_object('is_local_admin', v_cur_admin, 'enabled', v_cur_enabled),
        jsonb_build_object('is_local_admin', COALESCE(p_is_local_admin, v_cur_admin),
                           'enabled', v_enabled,
                           'sync_source', v_sync_source),
        NULL, v_sync_source, 'core');
    END IF;

    -- Sync the primary mailbox's identity fields + quota.
    UPDATE mailboxes SET
      domain_id    = v_domain_id,
      email        = CASE WHEN EXISTS (SELECT 1 FROM field_policy fp
                                       WHERE fp.user_id = v_user_id AND fp.field = 'email' AND fp.policy = 'local_only')
                          THEN email ELSE v_email END,
      display_name = v_display_name,
      quota_bytes  = COALESCE(p_quota_bytes, quota_bytes),
      updated_at   = now()
    WHERE user_id = v_user_id AND is_primary = TRUE
    RETURNING id INTO v_mailbox_id;

    -- Self-heal: a person with no primary mailbox (the AD/LDAP-sync bug) gets
    -- one now, so the address actually receives mail.
    IF v_mailbox_id IS NULL THEN
      INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary, quota_bytes)
      VALUES (v_user_id, v_domain_id, v_email, v_display_name, 'personal', TRUE,
              COALESCE(p_quota_bytes, 53687091200))
      RETURNING id INTO v_mailbox_id;
    END IF;
  ELSE
    -- ── INSERT new person + primary mailbox ───────────────────────────────
    INSERT INTO users (
      username, domain_id, email, display_name,
      first_name, last_name, job_title, phone, department_id,
      password_hash, is_local_admin, enabled, sync_source,
      ad_object_guid, ad_usn_changed, ad_upn, krb5_principal, scim_external_id
    ) VALUES (
      v_username, v_domain_id, v_email, v_display_name,
      p_first_name, p_last_name, p_job_title, p_phone, p_department_id,
      p_password_hash, COALESCE(p_is_local_admin, FALSE), v_enabled, v_sync_source,
      p_ad_object_guid, p_ad_usn_changed, p_ad_upn, p_krb5_principal, p_scim_external_id
    )
    RETURNING id INTO v_user_id;

    INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary, quota_bytes)
    VALUES (v_user_id, v_domain_id, v_email, v_display_name, 'personal', TRUE,
            COALESCE(p_quota_bytes, 53687091200))
    RETURNING id INTO v_mailbox_id;

    v_created := TRUE;
  END IF;

  -- ── Chat org-default channel auto-join (A3 QoL Task 12) ──────────────────
  -- The ONE provisioning seam — covers admin-create/CSV/AD/LDAP/SCIM/JIT in
  -- one line instead of five re-implementations. Idempotent (ON CONFLICT DO
  -- NOTHING per channel), so re-provisioning an existing person (an AD/LDAP
  -- re-sync UPDATE) never duplicates a membership row or re-notifies a
  -- channel the user already belongs to.
  PERFORM chat_autojoin_defaults(v_user_id);

  -- ── Governance-gated email address policy (eng review R6/R8) ────────────
  -- Apply ONLY on create (R6: no auto-restamp). Gated behind the kill switch
  -- (R8). No-sync sources apply unconditionally (engine still honors opt-out
  -- and no-match); ad/ldap apply only when an enabled override policy exists.
  IF v_created
     AND EXISTS (SELECT 1 FROM feature_toggles WHERE key = 'feature.email_address_policy' AND enabled)
     AND ( v_sync_source IN ('local','scim','scim-jit','sso-jit')
           OR (v_sync_source IN ('ad','ldap')
               AND EXISTS (SELECT 1 FROM email_address_policies WHERE enabled AND overwrite_directory_address)) )
  THEN
    PERFORM email_address_policy_apply(v_mailbox_id, v_user_id);
  END IF;

  -- ── Optional alias upsert (keyed to the primary mailbox) ─────────────────
  -- Each alias's domain must already be a LOCAL domain; an alias on a non-local
  -- or unknown domain is skipped (never fails the whole provision). Idempotent
  -- via aliases.email UNIQUE.
  IF p_aliases IS NOT NULL THEN
    FOREACH v_alias IN ARRAY p_aliases LOOP
      v_alias_email := lower(trim(v_alias));
      CONTINUE WHEN v_alias_email = '' OR position('@' IN v_alias_email) = 0;
      CONTINUE WHEN v_alias_email = v_email;  -- the primary address is not an alias

      v_alias_domain := split_part(v_alias_email, '@', 2);
      SELECT id INTO v_alias_dom_id
        FROM domains WHERE name = v_alias_domain AND is_local = TRUE;
      CONTINUE WHEN v_alias_dom_id IS NULL;  -- non-local / unknown domain: skip

      -- Idempotent via the case-insensitive UNIQUE index aliases(lower(email))
      -- (V054 dropped the case-sensitive aliases_email_key). v_alias_email is
      -- already lowercased. ON CONFLICT DO NOTHING is the idempotency for a
      -- re-provision of the SAME mailbox — but it ALSO swallows a cross-mailbox
      -- collision (the address is already an alias of a DIFFERENT mailbox). A
      -- NULL RETURNING means the conflict fired: look up who owns the row and,
      -- if it's NOT this mailbox, surface it as a non-fatal skipped_aliases
      -- warning (provisioning must not wholly fail on one contested alias). A
      -- same-mailbox conflict (idempotent re-run) stays silent.
      INSERT INTO aliases (mailbox_id, email, domain_id)
      VALUES (v_mailbox_id, v_alias_email, v_alias_dom_id)
      ON CONFLICT (lower(email)) DO NOTHING
      RETURNING mailbox_id INTO v_alias_ins_id;

      IF v_alias_ins_id IS NULL THEN
        SELECT mailbox_id INTO v_alias_own_id
          FROM aliases WHERE lower(email) = v_alias_email;
        IF v_alias_own_id IS DISTINCT FROM v_mailbox_id THEN
          v_skipped := v_skipped || to_jsonb(v_alias_email);
        END IF;
      END IF;
    END LOOP;
  END IF;

  -- ── WP3 audit coverage ──────────────────────────────────────────────────
  -- A NEW account materializing is a core lifecycle transition. The sync
  -- UPDATE arm (AD/LDAP re-provision of an existing person) stays unaudited:
  -- IdP sync is high-frequency machine flow with its own ledger. System flows
  -- (AD/LDAP/SCIM) pass no actor; p_sync_source in the notes is the trusted
  -- system origin. p_actor is an appended DEFAULT NULL parameter, so every
  -- pre-existing call shape is unchanged.
  IF v_created THEN
    PERFORM audit_write(
      p_actor, 'account_provision', 'user', v_user_id,
      NULL,
      jsonb_build_object('email', v_email,
                         'mailbox_id', v_mailbox_id,
                         'domain_id', v_domain_id,
                         'sync_source', v_sync_source,
                         'guest', COALESCE(p_guest, FALSE)),
      NULL, v_sync_source, 'core');
  END IF;

  RETURN jsonb_build_object(
    'user_id',         v_user_id,
    'mailbox_id',      v_mailbox_id,
    'domain_id',       v_domain_id,
    'username',        v_username,
    'created',         v_created,
    'skipped_aliases', v_skipped  -- aliases owned by ANOTHER mailbox; not created (non-fatal)
  );
END;
$$ LANGUAGE plpgsql;
