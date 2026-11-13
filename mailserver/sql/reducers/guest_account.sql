-- guest_account.sql — Guest Accounts G0 (spec P9/P13, codex C-7/C-14).
--
-- is_guest_account / guest_account_status are THE single-homed guest lookup
-- for Go (auth chain belt, CheckPassword, session payloads) and SQL (door
-- reducers) alike. They are SECURITY DEFINER + worker-owned because
-- guest_accounts is FORCE-RLS with a self-SELECT-only policy: a raw app-pool
-- SELECT with no app.current_user_id GUC would see zero rows and FAIL OPEN.
-- scripts/check-guest-doors.sh guards that no raw guest_accounts read
-- bypasses these helpers.
--
-- guest_set_status is the SINGLE WRITER for both status authorities (C-7):
-- guest_accounts.status + users.enabled + the refresh-family revocation
-- (oauth_tokens lives in the same database) flip in ONE transaction, so the
-- columns can never disagree and a disabled guest's refresh chain dies at
-- disable time. P9 split: DISABLE deletes chat-membership grant rows (clean
-- slate; attribution keys chat_messages.author_id, never membership; A4b
-- case-hold coverage is durable by design); EXPIRE freezes grants (access
-- blocked via status/BZ219; extend restores with zero re-granting).
--
-- BZ219: guest account not active. BZ162 reused for bad arguments; BZ170
-- reused for guest-not-found (both established codes, not new allocations).

-- r3 (CARDDAV-V-002 hold finding, transitive): this helper declares its OWN
-- search_path, which OVERRIDES the outer gal_visibility_record's pg_temp-LAST
-- pin for the duration of its execution when the journal seam reaches it
-- through directory_visible_users. With pg_temp omitted, PostgreSQL searches
-- an existing TEMP schema FIRST, so an app-owned empty TEMP guest_accounts
-- flipped a real enabled guest to "non-guest" and let the seam journal an
-- org-invisible guest into the REAL journal. Same V254 trusted-seam form as
-- the r2 seam fixes: qualify the relation AND pin pg_temp LAST. Pinned by
-- tests/gal_visibility_journal.pg section 10b (guest-shadow regression).
CREATE OR REPLACE FUNCTION is_guest_account(p_user_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM public.guest_accounts WHERE user_id = p_user_id);
$$;
SELECT apply_worker_ownership('is_guest_account(bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_account_status(p_user_id bigint)
RETURNS TABLE(status text, expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT g.status, g.expires_at FROM guest_accounts g WHERE g.user_id = p_user_id;
$$;
SELECT apply_worker_ownership('guest_account_status(bigint)'::regprocedure);

-- The RLS-safe ownership-domain lookup. A guest's users.domain_id is the
-- routing-only guest.invalid landing domain; administrative reach keys on the
-- immutable host_domain_id instead. NULL means the target is not a guest.
CREATE OR REPLACE FUNCTION guest_account_host_domain(p_user_id bigint) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT g.host_domain_id FROM guest_accounts g WHERE g.user_id = p_user_id;
$$;
SELECT apply_worker_ownership('guest_account_host_domain(bigint)'::regprocedure);

-- Guest-administration authorization must come from persisted, live role
-- assignments. Keep permission, domain, and (for target writes) OU/set reach
-- on the SAME assignment row so two individually insufficient assignments
-- cannot compose into authority.
CREATE OR REPLACE FUNCTION guest_admin_has_live_permission(
    p_actor_user_id bigint, p_permission text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1
          FROM admin_role_assignments ra
          JOIN admin_role_groups rg ON rg.id = ra.role_group_id
         WHERE ra.user_id = p_actor_user_id
           AND p_permission = ANY(rg.permissions)
           AND (ra.expires_at IS NULL OR ra.expires_at > now())
           AND admin_assignment_active(ra.eligible, ra.activated_until)
    );
$$;
SELECT apply_worker_ownership('guest_admin_has_live_permission(bigint,text)'::regprocedure);

-- Profiles are domain-wide policy objects. A narrowed OU/set assignment may
-- manage reachable users, but it can never read or mutate a domain-wide
-- profile or enumerate its domain option. The qualifying unscoped assignment
-- must itself carry the requested permission and cover the domain.
CREATE OR REPLACE FUNCTION guest_admin_has_domain_permission(
    p_actor_user_id bigint, p_host_domain_id bigint, p_permission text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1
          FROM admin_role_assignments ra
          JOIN admin_role_groups rg ON rg.id = ra.role_group_id
         WHERE ra.user_id = p_actor_user_id
           AND p_permission = ANY(rg.permissions)
           AND (ra.expires_at IS NULL OR ra.expires_at > now())
           AND admin_assignment_active(ra.eligible, ra.activated_until)
           AND ra.scope_type IS NULL
           AND (COALESCE(ra.domain_override, rg.domain_scope) IS NULL
                OR COALESCE(ra.domain_override, rg.domain_scope) = p_host_domain_id)
    );
$$;
SELECT apply_worker_ownership('guest_admin_has_domain_permission(bigint,bigint,text)'::regprocedure);

-- Target-user lifecycle/profile writes may honor OU/set narrowing, but only
-- when the SAME live assignment carries the requested permission, covers the
-- guest's immutable host domain, and reaches the guest through that scope.
CREATE OR REPLACE FUNCTION guest_admin_can_reach_with_permission(
    p_actor_user_id bigint, p_guest_user_id bigint, p_permission text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1
          FROM guest_accounts g
          JOIN users tu ON tu.id = g.user_id
          JOIN admin_role_assignments ra ON ra.user_id = p_actor_user_id
          JOIN admin_role_groups rg ON rg.id = ra.role_group_id
          LEFT JOIN departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
         WHERE g.user_id = p_guest_user_id
           AND p_permission = ANY(rg.permissions)
           AND (ra.expires_at IS NULL OR ra.expires_at > now())
           AND admin_assignment_active(ra.eligible, ra.activated_until)
           AND (COALESCE(ra.domain_override, rg.domain_scope) IS NULL
                OR COALESCE(ra.domain_override, rg.domain_scope) = g.host_domain_id)
           AND (
               ra.scope_type IS NULL
               OR (ra.scope_type = 'ou'
                   AND EXISTS (
                       SELECT 1 FROM departments td
                        WHERE td.id = tu.department_id
                          AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))
                   ))
               OR (ra.scope_type = 'set' AND admin_set_reaches(ra.scope_id, p_guest_user_id))
           )
    );
$$;
SELECT apply_worker_ownership('guest_admin_can_reach_with_permission(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_require_active(p_user_id bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_status  text;
    v_expires timestamptz;
BEGIN
    SELECT g.status, g.expires_at INTO v_status, v_expires
      FROM guest_accounts g WHERE g.user_id = p_user_id;
    IF NOT FOUND THEN
        RETURN;  -- member: no-op
    END IF;
    IF v_status <> 'active' OR (v_expires IS NOT NULL AND v_expires < now()) THEN
        RAISE EXCEPTION 'guest account is not active'
            USING ERRCODE='BZ219', HINT='{"type":"forbidden","detail":"guest account disabled or expired"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership('guest_require_active(bigint)'::regprocedure);

-- C-5 (codex round 3): the grant-writer variant. chat_member_add /
-- chat_dm_open call this on every guest TARGET before inserting the
-- membership row: FOR SHARE conflicts with guest_set_status's FOR UPDATE,
-- so a grant either commits BEFORE a disable (and the disable's clean-slate
-- delete sweeps it) or waits and then sees status='disabled' → BZ219. A
-- non-guest target finds no row: no lock taken, zero new cost for members.
CREATE OR REPLACE FUNCTION guest_require_grantable(p_user_id bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_status  text;
    v_expires timestamptz;
BEGIN
    SELECT g.status, g.expires_at INTO v_status, v_expires
      FROM guest_accounts g WHERE g.user_id = p_user_id FOR SHARE;
    IF NOT FOUND THEN
        RETURN;  -- member target: no-op, no lock
    END IF;
    IF v_status <> 'active' OR (v_expires IS NOT NULL AND v_expires < now()) THEN
        RAISE EXCEPTION 'guest account is not active'
            USING ERRCODE='BZ219', HINT='{"type":"forbidden","detail":"guest account disabled (re-invite required) or expired (extend to restore)"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership('guest_require_grantable(bigint)'::regprocedure);

-- Credential recovery keeps the authenticated LiveKit identity stable at
-- u:<user_id>. A token minted before re-invite can therefore reconnect under
-- the same identity until its four-hour horizon closes. The durable G5
-- eviction intents are the single fence: recovery may restore Chat/Drive
-- immediately, but Meet token minting waits until every re-invite intent is
-- complete. No second mutable "fence" flag can drift from the worker queue.
CREATE OR REPLACE FUNCTION guest_require_meet_ready(p_user_id bigint) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM guest_live_eviction_intents
         WHERE guest_user_id = p_user_id
           AND action = 'reinvite'
           AND completed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'guest Meet access is fenced during credential recovery'
            USING ERRCODE='BZ219',
                  HINT='{"type":"forbidden","detail":"Meet access resumes after stale session eviction completes"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership('guest_require_meet_ready(bigint)'::regprocedure);

-- G2 member-add snapshot. guest_require_grantable has already taken the
-- guest row's FOR SHARE lock, so this read cannot race profile apply/update.
-- Members return no row; NULL profile data is deliberately restrictive.
CREATE OR REPLACE FUNCTION guest_chat_policy_snapshot(p_user_id bigint)
RETURNS TABLE(can_post boolean, history_from_join boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT COALESCE(gp.can_post, false), COALESCE(gp.history_from_join, true)
      FROM guest_accounts g
      LEFT JOIN guest_profiles gp ON gp.id = g.profile_id
     WHERE g.user_id = p_user_id;
$$;
SELECT apply_worker_ownership('guest_chat_policy_snapshot(bigint)'::regprocedure);

-- G2 DM-initiation policy authority. This stays single-homed beside the
-- other guest satellite helpers so FORCE RLS cannot turn a raw caller read
-- into a false "not a guest"/"policy disabled" answer.
CREATE OR REPLACE FUNCTION guest_dm_policy_allows(p_user_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT COALESCE((
      SELECT g.status = 'active'
             AND (g.expires_at IS NULL OR g.expires_at > now())
             AND COALESCE(gp.can_initiate_dm, false)
        FROM guest_accounts g
        LEFT JOIN guest_profiles gp ON gp.id = g.profile_id
       WHERE g.user_id = p_user_id
    ), false);
$$;
SELECT apply_worker_ownership('guest_dm_policy_allows(bigint)'::regprocedure);

-- Compatibility tombstone for the pre-review signature. A caller-supplied
-- host-domain id carries no actor/channel authority, so this overload must
-- never disclose a guest. New callers use the actor/channel-bound overload
-- below.
CREATE OR REPLACE FUNCTION guest_active_preview(
    p_host_domain_id bigint, p_email text
) RETURNS TABLE(user_id bigint, display_name text, history_from_join boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT NULL::bigint, NULL::text, NULL::boolean WHERE FALSE;
$$;
SELECT apply_worker_ownership('guest_active_preview(bigint,text)'::regprocedure);

-- G2 exact-email lookup authority. The SECURITY-DEFINER target read is
-- inseparable from the actor's channel owner/admin check and host-domain
-- derivation. Missing, inactive, member, and foreign-host targets return no
-- row; unauthorized callers fail before the email is touched.
CREATE OR REPLACE FUNCTION guest_active_preview(
    p_user_id bigint, p_channel_id bigint, p_email text
) RETURNS TABLE(user_id bigint, display_name text, history_from_join boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_role text;
    v_kind text;
    v_host_domain_id bigint;
BEGIN
    IF is_guest_account(p_user_id) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
    SELECT m.role, c.kind, u.domain_id
      INTO v_role, v_kind, v_host_domain_id
      FROM chat_channels c
      JOIN chat_channel_members m
        ON m.channel_id = c.id AND m.user_id = p_user_id
      JOIN users u ON u.id = p_user_id
     WHERE c.id = p_channel_id;
    IF v_role IS NULL OR v_role NOT IN ('owner','admin') THEN
        RAISE EXCEPTION 'owner/admin required'
            USING ERRCODE='BZ161', HINT='{"type":"forbidden"}';
    END IF;
    IF v_kind IN ('dm','group_dm') THEN
        RAISE EXCEPTION 'cannot add members to a dm/group_dm'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;

    RETURN QUERY
    SELECT u.id, u.display_name, COALESCE(gp.history_from_join, true)
      FROM guest_accounts g
      JOIN users u ON u.id = g.user_id
      LEFT JOIN guest_profiles gp ON gp.id = g.profile_id
     WHERE lower(g.invited_email) = lower(btrim(COALESCE(p_email, '')))
       AND g.host_domain_id = v_host_domain_id
       AND g.status = 'active'
       AND (g.expires_at IS NULL OR g.expires_at > now())
     LIMIT 1;
END;
$$;
SELECT apply_worker_ownership('guest_active_preview(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_set_status(
    p_admin_user_id bigint, p_guest_user_id bigint, p_action text,
    p_new_expires_at timestamptz DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_status         text;
    v_expires        timestamptz;
    v_new_status     text;
    v_channel_id     bigint;
    v_system_expire  boolean := p_admin_user_id IS NULL AND p_action = 'expire';
    v_transition_id  uuid;
    v_eviction_count integer := 0;
    v_revocation_id  bigint;
    v_invite_id      bigint;
    v_federated_identity boolean;
BEGIN
    -- Universal authority lock order: advisory fence before guest/user rows.
    -- The users.enabled trigger takes the same fence reentrantly.
    PERFORM admin_authority_fence();

    IF p_action NOT IN ('disable','enable','expire','extend','reinvite') THEN
        RAISE EXCEPTION 'guest_set_status: invalid action %', p_action
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"action must be disable|enable|expire|extend|reinvite"}';
    END IF;

    -- G5 system expiry is the one actor-less entrance. It is narrowed again
    -- after the target row lock to active+already-due; NULL can never perform
    -- disable/enable/extend or an early expiry.
    IF p_admin_user_id IS NULL AND NOT v_system_expire THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden","detail":"guests.manage required"}';
    END IF;
    IF NOT v_system_expire
       AND NOT guest_admin_has_live_permission(p_admin_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden","detail":"guests.manage required"}';
    END IF;

    SELECT g.status, g.expires_at,
           (u.sync_source = 'sso'
            OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
            OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
      INTO v_status, v_expires, v_federated_identity
     FROM guest_accounts g
     JOIN users u ON u.id = g.user_id
     WHERE g.user_id = p_guest_user_id
       AND (v_system_expire OR guest_admin_can_reach_with_permission(
           p_admin_user_id, g.user_id, 'guests.manage'))
     FOR UPDATE OF g, u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account % not found', p_guest_user_id
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    IF v_system_expire AND (
        v_status <> 'active' OR v_expires IS NULL OR v_expires > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'guest_set_status: system expiry requires an active due guest'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"system expiry requires an active guest whose expiry is due"}';
    END IF;

    CASE p_action
    WHEN 'disable' THEN
        v_new_status := 'disabled';
        -- A disabled invited principal must not retain a usable credential.
        -- Stamp already-elapsed links truthfully at their effective expiry,
        -- then revoke the one remaining live invite under the guest/user lock.
        UPDATE guest_invites
           SET used_at = expires_at,
               terminal_reason = 'expired'
         WHERE guest_user_id = p_guest_user_id
           AND used_at IS NULL
           AND expires_at <= clock_timestamp()
           AND guest_admin_can_reach_with_permission(
               p_admin_user_id, p_guest_user_id, 'guests.manage');

        UPDATE guest_invites
           SET used_at = now(),
               terminal_reason = 'revoked'
         WHERE guest_user_id = p_guest_user_id
           AND used_at IS NULL
           AND expires_at > clock_timestamp()
           AND guest_admin_can_reach_with_permission(
               p_admin_user_id, p_guest_user_id, 'guests.manage')
         RETURNING id INTO v_invite_id;
        IF v_invite_id IS NOT NULL THEN
            PERFORM audit_write(
                p_admin_user_id, 'guest.invite_revoke', 'guest_invite',
                v_invite_id, NULL,
                jsonb_build_object(
                    'terminalReason', 'revoked',
                    'guestUserId', p_guest_user_id::text,
                    'reason', 'guest.disable'
                ), NULL, 'pending guest invite revoked by lifecycle disable', 'core'
            );
        END IF;
        -- P9 DISABLE = clean slate, via the EXISTING removal shape — per
        -- affected channel: delete row + (compliance audit when the toggle is
        -- ON) + notify_chat_state('member_removed'), copied from
        -- chat_member_remove (chat_channel.sql:388–400). Open-coded rather
        -- than calling chat_member_remove because that reducer refuses
        -- dm/group_dm kinds (BZ162) and a guest CAN hold DM memberships (P8).
        -- No separate change_seq bump: the existing member-remove path bumps
        -- none either (notify carries seq NULL for membership events).
        -- Drive derivation arm 2 dies with the channel membership it derives
        -- from. Authenticated Meet admissions and participants are separate
        -- future-grant rails (meeting_guest_join_allowed + Drive arm 3), so
        -- disable invalidates their authority while retaining the rows as
        -- history. G5 still owes live SFU eviction: this transaction prevents
        -- every future DB grant but cannot eject an already-connected client.
        -- ponytail: no owner-succession copy — a guest cannot create channels
        -- (BZ215), so it can only own one via an explicit role promotion; if
        -- G1 opens that path it owes the succession arm here.
        FOR v_channel_id IN
            SELECT channel_id FROM chat_channel_members
             WHERE user_id = p_guest_user_id
             ORDER BY channel_id
        LOOP
            DELETE FROM chat_channel_members
             WHERE channel_id = v_channel_id AND user_id = p_guest_user_id;
            IF FOUND THEN
                IF COALESCE((SELECT enabled FROM feature_toggles
                             WHERE key = 'feature.chat_compliance'), FALSE) THEN
                    PERFORM chat_access_audit(p_admin_user_id, v_channel_id, 'member.remove',
                        'member', p_guest_user_id, NULL,
                        jsonb_build_object('userId', p_guest_user_id, 'reason', 'guest.disable'),
                        NULL, NULL);
                END IF;
                PERFORM notify_chat_state(v_channel_id, 'member_removed', NULL, NULL);
            END IF;
        END LOOP;

    WHEN 'expire' THEN
        IF v_status <> 'active' THEN
            RAISE EXCEPTION 'guest_set_status: expire requires active status'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"expire is only valid for an active guest"}';
        END IF;
        v_new_status := 'expired';  -- P9 EXPIRY = freeze: grant rows kept
    WHEN 'enable' THEN
        IF v_status <> 'disabled' THEN
            RAISE EXCEPTION 'guest_set_status: enable requires disabled status'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"enable is only valid for a disabled guest; invited guests must accept their invitation and expired guests must be extended"}';
        END IF;
        IF v_expires IS NOT NULL AND v_expires <= clock_timestamp() THEN
            RAISE EXCEPTION 'guest_set_status: enable requires a future expiry'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"extend the guest to a future expiry before enabling"}';
        END IF;
        v_new_status := 'active';
    WHEN 'extend' THEN
        IF v_status NOT IN ('active','disabled','expired') THEN
            RAISE EXCEPTION 'guest_set_status: extend requires active, disabled, or expired status'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"extend is valid for active, disabled, or expired guests; invited guests must accept their invitation"}';
        END IF;
        IF p_new_expires_at IS NULL OR p_new_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'guest_set_status: extend requires a future p_new_expires_at'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"extend requires a future expiry"}';
        END IF;
        v_new_status := 'active';
    WHEN 'reinvite' THEN
        -- Recovery preserves the identity and whatever grants the prior
        -- lifecycle state intentionally retained. A disabled guest therefore
        -- stays clean-slate; an expired/active guest's grants stay frozen while
        -- status=invited. A due expiry must be replaced atomically so invite
        -- acceptance cannot produce an active-but-still-expired account.
        IF v_federated_identity THEN
            RAISE EXCEPTION 'guest_set_status: federated guest recovery requires identity policy'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"federated guest recovery cannot mint a local password fallback"}';
        END IF;
        IF p_new_expires_at IS NOT NULL AND p_new_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'guest_set_status: re-invite expiry must be in the future'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"re-invite expiry must be in the future"}';
        END IF;
        IF v_expires IS NOT NULL AND v_expires <= clock_timestamp()
           AND p_new_expires_at IS NULL THEN
            RAISE EXCEPTION 'guest_set_status: expired recovery requires a future expiry'
                USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"expired guest recovery requires a future expiry"}';
        END IF;
        v_new_status := 'invited';
    END CASE;

    UPDATE guest_accounts g
       SET status     = v_new_status,
           expires_at = CASE
               WHEN p_action = 'extend' THEN p_new_expires_at
               WHEN p_action = 'reinvite' AND p_new_expires_at IS NOT NULL THEN p_new_expires_at
               ELSE expires_at
           END,
           updated_at = now()
     WHERE g.user_id = p_guest_user_id
       AND (v_system_expire OR guest_admin_can_reach_with_permission(
           p_admin_user_id, g.user_id, 'guests.manage'));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account % not found', p_guest_user_id
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    -- C-7 atomicity: users.enabled + refresh-family death in the SAME txn.
    -- 47edc4ff made RefreshTokens honor users.enabled, but the guest story
    -- deliberately does not lean on that alone — the revocation is explicit.
    UPDATE users SET enabled = (v_new_status = 'active'), updated_at = now()
     WHERE id = p_guest_user_id
       AND (v_system_expire OR guest_admin_can_reach_with_permission(
               p_admin_user_id, p_guest_user_id, 'guests.manage'));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest account % not found', p_guest_user_id
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    IF p_action IN ('disable','expire','reinvite') THEN
        UPDATE oauth_tokens SET revoked_at = now()
         WHERE user_id = p_guest_user_id AND revoked_at IS NULL
           AND (v_system_expire OR guest_admin_can_reach_with_permission(
                   p_admin_user_id, p_guest_user_id, 'guests.manage'));

        -- G5 live-containment evidence. Snapshot EVERY room belonging to each
        -- non-ended meeting the guest has participated in, not only the room
        -- whose participant row is currently open. A recently-left client can
        -- reconnect with its still-valid token, and a participant moved across
        -- breakouts can retain a token for an earlier room. LiveKit auto-create
        -- is OFF, so ended meetings need no retry; ongoing parent + all child
        -- rooms are the complete stale-token set. Disable closes participant
        -- rows only after this snapshot. Expiry keeps grants frozen but still
        -- ejects the peripheral sessions.
        v_transition_id := gen_random_uuid();
        INSERT INTO guest_live_eviction_intents
            (transition_id, guest_user_id, action, room_name, identity)
        SELECT v_transition_id, p_guest_user_id, p_action, targets.room_name, targets.identity
          FROM (
            SELECT m.id AS meeting_id, m.room_name, p.identity
              FROM meeting_participants p
              JOIN meetings m ON m.id = p.meeting_id
             WHERE p.user_id = p_guest_user_id AND m.state <> 'ended'
            UNION
            SELECT m.id AS meeting_id, b.room_name, p.identity
              FROM meeting_participants p
              JOIN meetings m ON m.id = p.meeting_id
              JOIN meeting_breakouts b ON b.meeting_id = m.id
             WHERE p.user_id = p_guest_user_id AND m.state <> 'ended'
          ) targets
         ORDER BY targets.meeting_id, targets.room_name, targets.identity
        ON CONFLICT (transition_id, room_name, identity) DO NOTHING;
        GET DIAGNOSTICS v_eviction_count = ROW_COUNT;

        -- Existing durable denylist + app_notify rail closes WebSocket and
        -- EventSource sessions and blocks subsequent HTTP use. NULL creator is
        -- the explicit system-expiry actor; both audit tables accept it.
        v_revocation_id := revoke_user_sessions(
            p_guest_user_id, 'all', 'guest.' || p_action,
            p_admin_user_id, NULL, NULL);

        IF p_action = 'disable' THEN
            UPDATE meeting_join_requests
               SET state = 'expired',
                   decided_at = COALESCE(decided_at, now())
             WHERE user_id = p_guest_user_id
               AND state IN ('pending', 'admitted');

            UPDATE meeting_participants
               SET left_at = COALESCE(left_at, now()),
                   banned_at = COALESCE(banned_at, now())
             WHERE user_id = p_guest_user_id;
        END IF;
    END IF;

    PERFORM audit_write(p_admin_user_id, 'guest.' || p_action, 'user', p_guest_user_id,
        jsonb_build_object('status', v_status, 'expiresAt', v_expires),
        jsonb_build_object('status', v_new_status,
                           'expiresAt', CASE
                               WHEN p_action = 'extend' THEN p_new_expires_at
                               WHEN p_action = 'reinvite' AND p_new_expires_at IS NOT NULL THEN p_new_expires_at
                               ELSE v_expires
                           END,
                           'liveEvictionTargets', v_eviction_count,
                           'sessionRevocationId', v_revocation_id,
                           'system', v_system_expire),
        NULL, NULL, 'core');
END;
$$;
SELECT apply_worker_ownership('guest_set_status(bigint,bigint,text,timestamptz)'::regprocedure);

-- G5 hourly lifecycle sweep. The worker owns scheduling only; every state
-- transition still enters guest_set_status, whose actor-less branch accepts
-- exactly active rows already due. SKIP LOCKED lets rolling gateways split a
-- batch without double-auditing one guest.
CREATE OR REPLACE FUNCTION guest_expire_due(p_limit integer DEFAULT 500)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_guest_user_id bigint;
    v_expired integer := 0;
BEGIN
    -- Fence before the SKIP LOCKED guest-row claim; guest_set_status re-enters it.
    PERFORM admin_authority_fence();

    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 5000 THEN
        RAISE EXCEPTION 'guest_expire_due: limit must be 1..5000'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;

    FOR v_guest_user_id IN
        SELECT g.user_id
          FROM guest_accounts g
         WHERE g.status = 'active'
           AND g.expires_at IS NOT NULL
           AND g.expires_at <= clock_timestamp()
         ORDER BY g.user_id
         FOR UPDATE SKIP LOCKED
         LIMIT p_limit
    LOOP
        PERFORM guest_set_status(NULL, v_guest_user_id, 'expire', NULL);
        v_expired := v_expired + 1;
    END LOOP;
    RETURN v_expired;
END;
$$;
SELECT apply_worker_ownership('guest_expire_due(integer)'::regprocedure);

-- Same-assignment proof for a transfer: one live guests.manage assignment
-- must cover BOTH the guest and replacement sponsor. Separate permission and
-- reach assignments cannot compose into authority.
CREATE OR REPLACE FUNCTION guest_admin_can_transfer_to(
    p_actor_user_id bigint, p_guest_user_id bigint, p_sponsor_user_id bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1
          FROM guest_accounts g
          JOIN users gu ON gu.id = g.user_id
          JOIN users su ON su.id = p_sponsor_user_id
          JOIN admin_role_assignments ra ON ra.user_id = p_actor_user_id
          JOIN admin_role_groups rg ON rg.id = ra.role_group_id
          LEFT JOIN departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
         WHERE g.user_id = p_guest_user_id
           AND 'guests.manage' = ANY(rg.permissions)
           AND (ra.expires_at IS NULL OR ra.expires_at > now())
           AND admin_assignment_active(ra.eligible, ra.activated_until)
           AND su.domain_id = g.host_domain_id
           AND (COALESCE(ra.domain_override, rg.domain_scope) IS NULL
                OR COALESCE(ra.domain_override, rg.domain_scope) = g.host_domain_id)
           AND (
               ra.scope_type IS NULL
               OR (ra.scope_type = 'ou'
                   AND EXISTS (
                       SELECT 1 FROM departments gd, departments sd2
                        WHERE gd.id = gu.department_id AND sd2.id = su.department_id
                          AND (gd.path = sd.path OR starts_with(gd.path, sd.path || '/'))
                          AND (sd2.path = sd.path OR starts_with(sd2.path, sd.path || '/'))
                   ))
               OR (ra.scope_type = 'set'
                   AND admin_set_reaches(ra.scope_id, p_guest_user_id)
                   AND admin_set_reaches(ra.scope_id, p_sponsor_user_id))
           )
    );
$$;
SELECT apply_worker_ownership('guest_admin_can_transfer_to(bigint,bigint,bigint)'::regprocedure);

-- G5 explicit sponsor/resource transfer. Attribution rows are never rewritten:
-- only mutable authority/ownership columns move to the enabled member sponsor.
CREATE OR REPLACE FUNCTION guest_transfer(
    p_actor_user_id bigint, p_guest_user_id bigint, p_sponsor_user_id bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_old_sponsor bigint;
    v_host_domain bigint;
    v_channel_id bigint;
    v_channel_count integer := 0;
    v_space_count integer := 0;
BEGIN
    IF p_actor_user_id IS NULL OR p_guest_user_id IS NULL OR p_sponsor_user_id IS NULL
       OR p_guest_user_id = p_sponsor_user_id THEN
        RAISE EXCEPTION 'guest_transfer: distinct positive ids are required'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments"}';
    END IF;

    -- Global lifecycle order is guest_accounts → users. guest_set_status and
    -- guest_expire_due take the same order, so transfer-vs-disable cannot form
    -- an ABBA deadlock. User rows remain id-ordered for inverse transfers.
    SELECT g.sponsor_user_id, g.host_domain_id
      INTO v_old_sponsor, v_host_domain
      FROM guest_accounts g
     WHERE g.user_id = p_guest_user_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'guest or replacement sponsor not found'
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;

    PERFORM 1 FROM users
     WHERE id IN (p_guest_user_id, p_sponsor_user_id)
     ORDER BY id FOR UPDATE;

    IF NOT EXISTS (
        SELECT 1 FROM users sponsor
         WHERE sponsor.id = p_sponsor_user_id
           AND sponsor.enabled
           AND sponsor.domain_id = v_host_domain
           AND NOT is_guest_account(sponsor.id)
           AND guest_admin_can_transfer_to(
                   p_actor_user_id, p_guest_user_id, p_sponsor_user_id)
    ) THEN
        RAISE EXCEPTION 'guest or replacement sponsor not found'
            USING ERRCODE='BZ170', HINT='{"type":"notFound"}';
    END IF;
    IF v_old_sponsor = p_sponsor_user_id THEN
        RAISE EXCEPTION 'guest_transfer: replacement sponsor is unchanged'
            USING ERRCODE='BZ162', HINT='{"type":"invalidArguments","detail":"replacement sponsor is unchanged"}';
    END IF;

    -- A personal space is a per-user identity object and should be impossible
    -- for a mailbox-less guest. Refuse rather than silently re-home one and
    -- collide with the sponsor's own personal-space unique index.
    IF EXISTS (SELECT 1 FROM drive_spaces
                WHERE owner_user_id = p_guest_user_id AND is_personal) THEN
        RAISE EXCEPTION 'guest_transfer: guest unexpectedly owns a personal Drive space'
            USING ERRCODE='BZ221', HINT='{"type":"conflict"}';
    END IF;

    FOR v_channel_id IN
        SELECT channel_id FROM chat_channel_members
         WHERE user_id = p_guest_user_id AND role = 'owner'
         ORDER BY channel_id FOR UPDATE
    LOOP
        INSERT INTO chat_channel_members (channel_id, user_id, role)
        VALUES (v_channel_id, p_sponsor_user_id, 'owner')
        ON CONFLICT (channel_id, user_id) DO UPDATE SET role = 'owner';
        UPDATE chat_channel_members SET role = 'member'
         WHERE channel_id = v_channel_id AND user_id = p_guest_user_id;
        v_channel_count := v_channel_count + 1;
    END LOOP;

    PERFORM 1 FROM drive_spaces
     WHERE owner_user_id = p_guest_user_id
     ORDER BY id FOR UPDATE;
    UPDATE drive_spaces
       SET owner_user_id = p_sponsor_user_id
     WHERE owner_user_id = p_guest_user_id AND NOT is_personal;
    GET DIAGNOSTICS v_space_count = ROW_COUNT;

    UPDATE guest_accounts
       SET sponsor_user_id = p_sponsor_user_id, updated_at = now()
     WHERE user_id = p_guest_user_id;

    PERFORM audit_write(
        p_actor_user_id, 'guest.transfer', 'user', p_guest_user_id,
        jsonb_build_object('sponsorUserId', v_old_sponsor),
        jsonb_build_object('sponsorUserId', p_sponsor_user_id,
                           'channelOwnersTransferred', v_channel_count,
                           'driveSpacesTransferred', v_space_count),
        NULL, NULL, 'core');

    RETURN jsonb_build_object(
        'guestUserId', p_guest_user_id,
        'sponsorUserId', p_sponsor_user_id,
        'channelOwnersTransferred', v_channel_count,
        'driveSpacesTransferred', v_space_count);
END;
$$;
SELECT apply_worker_ownership('guest_transfer(bigint,bigint,bigint)'::regprocedure);
