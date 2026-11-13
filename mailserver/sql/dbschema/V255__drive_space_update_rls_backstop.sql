-- ════════════════════════════════════════════════════════════════════════
-- V255__drive_space_update_rls_backstop.sql — R3 restatement for
-- drive_spaces_update (DBSCHEMA-008: WITH CHECK carried no ownership
-- predicate, breaking the V114 sibling restated-predicate pattern).
--
-- V114 created drive_spaces_update with WITH CHECK (true): a manager could
-- write ARBITRARY columns on the new row at the RLS layer — reassigning
-- owner_user_id (an authorization boundary) or lifting quota_bytes (a
-- drive.manage admin knob per drive_space_set_quota) even though both
-- mutations flow exclusively through their own reducers. No current code
-- path issues a raw user-reachable UPDATE on drive_spaces, so this is RLS
-- backstop hardening — but the backstop must be honest.
--
-- 1. WITH CHECK restates the USING membership/admin predicate (the V114
--    drive_space_members_write / drive_spaces_insert pattern), so a new row
--    must still satisfy the same manager/admin visibility predicate.
-- 2. A BEFORE UPDATE trigger pins the two authorization-bearing columns:
--      - owner_user_id may only move in the sanctioned guest sponsor-transfer
--        shape (guest → a valid, non-guest, enabled sponsor of the guest's
--        host domain; never on a personal space) — the exact shape the
--        guest_transfer reducer moves (guest_account.sql, V143/V143 host
--        domain), which is the ONLY in-repo owner mutation.
--      - quota_bytes may only change for a drive.manage admin (matching
--        drive_space_set_quota's own gate), resolved from the same
--        app.current_user_id GUC every RLS arm uses.
--    Row-value comparisons are impossible inside a policy's WITH CHECK
--    (only the new row is visible), so the pin lives in a trigger, mirroring
--    trg_drive_space_no_downgrade (V114 §D).
-- ════════════════════════════════════════════════════════════════════════

-- ── 1. Restate the update predicate in WITH CHECK ─────────────────────────
DROP POLICY IF EXISTS drive_spaces_update ON public.drive_spaces;
CREATE POLICY drive_spaces_update ON public.drive_spaces FOR UPDATE TO public
  USING (public.drive_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.manage'))
  WITH CHECK (public.drive_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.manage'));

-- ── 2. Pin owner_user_id / quota_bytes against old-row values ─────────────
CREATE FUNCTION public.trg_drive_space_no_reassign_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
    -- Sanctioned shape: the guest sponsor-transfer (guest_account.sql
    -- guest_transfer). Personal spaces never reassign (the reducer refuses
    -- them too, BZ221); every other source or target is forbidden.
    IF OLD.is_personal OR NEW.owner_user_id IS NULL OR NOT EXISTS (
         SELECT 1
           FROM public.guest_accounts g
           JOIN public.users sponsor ON sponsor.id = NEW.owner_user_id
          WHERE g.user_id = OLD.owner_user_id
            AND sponsor.enabled
            AND sponsor.domain_id = g.host_domain_id
            AND NOT EXISTS (SELECT 1 FROM public.guest_accounts g2
                             WHERE g2.user_id = NEW.owner_user_id)
    ) THEN
      RAISE EXCEPTION 'drive space ownership reassignment outside guest sponsor-transfer is forbidden'
        USING ERRCODE = 'BZ142',
              HINT = '{"type":"stateMismatch","detail":"ownership flows only through the guest transfer reducer"}';
    END IF;
  END IF;

  IF NEW.quota_bytes IS DISTINCT FROM OLD.quota_bytes THEN
    IF NOT public.drive_has_admin_perm(
           (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint),
           'drive.manage') THEN
      RAISE EXCEPTION 'quota_bytes is a drive.manage admin knob'
        USING ERRCODE = 'BZ140',
              HINT = '{"type":"forbidden","detail":"quota changes flow through drive_space_set_quota"}';
    END IF;
  END IF;

  RETURN NEW;
END $$;

CREATE TRIGGER trg_drive_space_no_reassign
  BEFORE UPDATE OF owner_user_id, quota_bytes ON public.drive_spaces
  FOR EACH ROW EXECUTE FUNCTION public.trg_drive_space_no_reassign_fn();

-- ── ACL hygiene on the new trigger function (V114 §B pattern) ─────────────
REVOKE EXECUTE ON FUNCTION public.trg_drive_space_no_reassign_fn() FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.trg_drive_space_no_reassign_fn() TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
    GRANT EXECUTE ON FUNCTION public.trg_drive_space_no_reassign_fn() TO setjoin_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.trg_drive_space_no_reassign_fn() TO setjoin_worker;
  END IF;
END $$;

-- ── Schema migration record (V060 bookkeeping form) ───────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (255, now())
    ON CONFLICT (version) DO NOTHING;
