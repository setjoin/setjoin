-- mailserver/sql/reducers/drive_scope_helper.sql — the Drive-family FORCE-RLS
-- SECURITY DEFINER scope helpers (ARCH-018 recipe rows 1/1b/1c, 2, 3, 8).
--
-- Moved here from dbschema (arch review #A6): these four bodies were
-- scattered across V114 (drive_space_owner, drive_has_admin_perm), V120/V129
-- (drive_member_role, "newest CREATE OR REPLACE wins"), and V135
-- (drive_user_can_write_regular) — "what does it do today" meant finding the
-- newest-looking migration. Reducer reload (fixed-point, LC_ALL=C path order)
-- CREATE OR REPLACEs over whatever the migrations shipped, so this file is
-- now the live definition; the historical migrations are UNTOUCHED (they
-- remain the first-CREATE record, per V134's stated convention — a future
-- pin/logic fix is a reducer edit here, not a new migration).
--
-- All four: STABLE, SECURITY DEFINER, `SET search_path = pg_catalog, public`
-- (the SECURITY DEFINER privilege-escalation foot-gun belt), owned by
-- setjoin_worker (BYPASSRLS) via apply_worker_ownership(), EXECUTE granted to
-- the app/owner/worker trio only. See docs/adr/ARCH-018-force-rls-scope-
-- helper-recipe.md for the five-point checklist and the liveness-filter
-- matrix these four occupy (rows 1/1b/1c, 2, 3, 8).

-- Row 1/1b/1c — drive_member_role: membership/role across three derivation
-- arms (explicit drive_space_members, chat-bound via chat_channel_members,
-- meeting-bound via meeting_participants). Based on V129 (the
-- current, third CREATE OR REPLACE — V114 arm 1 only, V120 added arm 2, V129
-- added arm 3); Guest G4 caps derived guest roles while separating membership
-- (preview authority) from original-byte download policy. Read
-- the ADR before changing any arm's liveness filter.
CREATE OR REPLACE FUNCTION drive_member_role(p_space_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT COALESCE(
     (SELECT role FROM public.drive_space_members
       WHERE space_id = p_space_id AND user_id = p_user_id),
     (SELECT CASE
                  WHEN public.is_guest_account(p_user_id) THEN 'viewer'
                  WHEN m.role IN ('owner','admin') THEN 'manager'
                  ELSE 'editor'
             END
        FROM public.drive_spaces s
        JOIN public.chat_channel_members m ON m.channel_id = s.chat_channel_id
       WHERE s.id = p_space_id AND m.user_id = p_user_id),
     (SELECT CASE WHEN p.role IN ('host','cohost') THEN 'manager'
                  WHEN p.joined_at IS NOT NULL THEN 'viewer' END
        FROM public.drive_spaces s
        JOIN public.meeting_participants p ON p.meeting_id = s.meeting_id
       WHERE s.id = p_space_id AND p.user_id = p_user_id AND p.banned_at IS NULL
         AND (p.role IN ('host','cohost') OR p.joined_at IS NOT NULL))
   ) $$;
SELECT apply_worker_ownership('drive_member_role(bigint,bigint)'::regprocedure);

-- Guest G4 raw-byte choke. Membership and attachment liveness are checked by
-- the caller's version query; this reducer answers the orthogonal question:
-- may this authenticated principal receive original file bytes at all?
-- Members are a no-op. Guests fail with one constant BZ215 shape before the
-- requested version is resolved, so a remembered id cannot become an oracle.
CREATE OR REPLACE FUNCTION drive_content_download_require(p_user_id bigint)
RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$
BEGIN
    IF NOT public.is_guest_account(p_user_id) THEN
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM public.guest_accounts ga
          JOIN public.users u ON u.id = ga.user_id
         WHERE ga.user_id = p_user_id
           AND u.enabled
           AND ga.status = 'active'
           AND (ga.expires_at IS NULL OR ga.expires_at >= now())
    )
       OR NOT public.check_user_app_entitlement(p_user_id, 'drive')
       OR NOT public.guest_profile_flag(p_user_id, 'allow_download') THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215',
                  HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;
END;
$$;
SELECT apply_worker_ownership('drive_content_download_require(bigint)'::regprocedure);

-- Row 2 — drive_space_owner: static owner-column read, not a membership
-- check. Callers separately guard its relevance to unbound spaces (DES-009
-- D3). Body verbatim from V114.
CREATE OR REPLACE FUNCTION drive_space_owner(p_space_id bigint)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT owner_user_id FROM public.drive_spaces WHERE id = p_space_id $$;
SELECT apply_worker_ownership('drive_space_owner(bigint)'::regprocedure);

-- Row 3 — drive_has_admin_perm: the admin-grant analog of a liveness filter
-- (expiry + JIT eligibility). Logic verbatim from V114 — the eligibility
-- clause is now a call to admin_assignment_active() (D7's single source of
-- truth for that predicate) instead of an inline copy: moving this body out
-- of dbschema/ into reducers/*.sql (arch #A6) brought it into
-- check-jit-coverage.sh's scanned tree for the first time, and the guard
-- treats an inline copy as an unclassified site rather than trusting it's
-- identical to the named function. Calling admin_assignment_active makes it
-- textually WRAPPED (the guard's own preferred detection), removes the
-- duplicate copy of the eligibility logic, and is behavior-identical.
CREATE OR REPLACE FUNCTION drive_has_admin_perm(p_user_id bigint, p_perm text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT EXISTS (
     SELECT 1 FROM public.admin_role_assignments ara
     JOIN public.admin_role_groups arg ON arg.id = ara.role_group_id
     WHERE ara.user_id = p_user_id
       AND (ara.expires_at IS NULL OR ara.expires_at > now())
       AND public.admin_assignment_active(ara.eligible, ara.activated_until)
       AND p_perm = ANY(arg.permissions)) $$;
SELECT apply_worker_ownership('drive_has_admin_perm(bigint,text)'::regprocedure);

-- Row 8 — drive_user_can_write_regular: "is this user manager/editor of ANY
-- regular (unbound) space" — the drive_chunks_insert 'g'-scope (global-dedup)
-- policy's authorization gate (V135).
--
-- ARCH #A3 root-cause finding (2026-07-16): V135 shipped this INLINING all
-- three drive_member_role arms verbatim, VOLATILE, EXECUTE-to-setjoin_app-
-- only, because "a nested STABLE-DEFINER call, evaluated inside another
-- DEFINER helper inside a plpgsql reducer's RLS WITH CHECK, silently
-- returned no rows on the live gate" — undiagnosed at the time.
--
-- REPRODUCED AND ROOT-CAUSED, and it is a RED HERRING: nested delegation to
-- drive_member_role works correctly in every tested shape — a direct call as
-- setjoin_app, a WITH CHECK policy evaluated during a plain INSERT (inline in
-- a DO block AND wrapped in a separate invoker-rights plpgsql function). The
-- actual failure only appears when the INSERT carries an ON CONFLICT clause
-- (DO NOTHING or DO UPDATE): PostgreSQL's row-security implementation
-- additionally requires the tentative new row to satisfy the table's SELECT
-- policy for ANY statement with an ON CONFLICT arbiter — an anti-oracle
-- measure so ON CONFLICT DO NOTHING can't be used to probe the existence of
-- a row the caller couldn't otherwise SELECT. drive_chunks_read's SELECT
-- policy requires a pre-existing drive_upload_claims row (which does not yet
-- exist for a first-time chunk — the exact chicken/egg the real
-- drive_chunk_register INSERT ... ON CONFLICT DO NOTHING statement hits), so
-- ANY chunk-insert-with-ON-CONFLICT as a non-bypass role fails this check —
-- completely independent of whether drive_user_can_write_regular inlines or
-- delegates. Proven live: temporarily making drive_chunks_read's USING
-- permissive (true) makes the SAME ON CONFLICT INSERT succeed with NO change
-- to the INSERT WITH CHECK policy or helper at all.
--
-- Consequently this policy is DEAD on both of drive_chunks' real writers
-- today: drive_chunk_register is itself SECURITY DEFINER + worker-owned
-- (runs as setjoin_worker, BYPASSRLS — bypasses RLS entirely regardless of
-- caller role or ON CONFLICT), and drive_preview_attach is only ever invoked
-- on the preview worker's own BYPASSRLS pool. drive_chunks_insert's WITH
-- CHECK — and therefore this helper — only matters as defense-in-depth for a
-- FUTURE writer that runs as setjoin_app directly (and such a writer would
-- ALSO need to avoid ON CONFLICT, or hit the anti-oracle check above,
-- independent of this function). Delegating to drive_member_role (rather
-- than keeping the VOLATILE 3-arm inline copy) removes the duplication with
-- zero behavior change and lets a future drive_member_role arm addition
-- apply here automatically. Normalized to the ARCH-018 recipe: STABLE (pure
-- read, no mutation — was VOLATILE), EXECUTE to the app/owner/worker trio
-- (was app-only) via apply_worker_ownership().
CREATE OR REPLACE FUNCTION drive_user_can_write_regular(p_user_id bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT EXISTS (
     SELECT 1 FROM public.drive_spaces s
      WHERE s.classification = 'regular'
        AND public.drive_member_role(s.id, p_user_id) IN ('manager','editor')
   ) $$;
SELECT apply_worker_ownership('drive_user_can_write_regular(bigint)'::regprocedure);
