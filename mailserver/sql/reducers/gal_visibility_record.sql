-- gal_visibility_record: THE single writer of gal_visibility_journal (V261,
-- CARDDAV-V-002). Records which directory members a caller's primary mailbox
-- has been DISCLOSED, so gal_changes can distinguish "removed after being
-- visible" from "never visible" and never render a never-visible directory id
-- as a sync-collection removal.
--
-- R1/R2 BY RESOLUTION: the caller mailbox is validated in-DB (BZ001 when
-- unknown) and the id set is filtered through directory_visible_users — the
-- ADR-004 seam — BEFORE the INSERT, so a journal row can only ever be written
-- for a member the seam actually shows that mailbox. A client-supplied id that
-- the seam does not return journals nothing (and reveals nothing). Ownership
-- column (mailbox_id) comes from the validated p_mailbox_id, never from a
-- request-owned field.
--
-- Idempotent: re-recording an already-journaled member is a no-op
-- (ON CONFLICT DO NOTHING) — first_seen_at keeps the FIRST disclosure, which
-- is the load-bearing datum ("previously visible since"). Volatile by
-- definition (it writes).
--
-- SECURITY DEFINER owned by setjoin_worker (the V254 mdm_checkin_event_append
-- trusted-seam form): gal_visibility_journal is FORCE-RLS deny-all to every
-- runtime role, so the definer's BYPASSRLS is the only path in. App-invokable
-- ON PURPOSE — the CardDAV gateway calls it over DB_DSN (setjoin_app) after
-- rendering GAL cards, and gal_changes PERFORMs it for every disclosed sync
-- delta. It MUST therefore NOT be added to provision-roles.sql's worker-only
-- EXECUTE carve-out (that list is for reducers setjoin_app must never call).
--
-- r2 (CARDDAV-V-002 hold finding, P1): because an omitted pg_temp makes an
-- existing TEMP schema search FIRST for relation names, every relation here is
-- schema-qualified (the V254 trusted-seam form) AND the pinned search_path
-- lists pg_temp LAST (`pg_catalog, public, pg_temp`). The pg_temp-last pin also
-- covers the seam this function invokes: directory_visible_users is SECURITY
-- INVOKER with unqualified internals (users/departments/mailboxes/aliases/
-- is_guest_account), and as a callee it resolves those relations against the
-- DEFINER's search_path — pg_temp last means a caller-planted TEMP shadow
-- (journal, mailboxes, users, …) can never win, forge a journal answer, or
-- redirect the privileged INSERT. Pinned by tests/gal_visibility_journal.pg
-- section 10 (app-role TEMP shadow regression).
CREATE OR REPLACE FUNCTION gal_visibility_record(
  p_mailbox_id BIGINT,
  p_user_ids   BIGINT[]          -- directory member ids about to be disclosed
) RETURNS JSONB AS $$
DECLARE
  v_recorded BIGINT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.mailboxes WHERE id = p_mailbox_id) THEN
    RAISE EXCEPTION 'gal_visibility_record: unknown caller mailbox %', p_mailbox_id
      USING ERRCODE = 'BZ001';
  END IF;

  -- Journal ONLY the subset the seam actually shows this mailbox; anything
  -- else in p_user_ids is invisible by definition and must stay unjournaled
  -- (an unjournaled id can never be reported as a removal).
  INSERT INTO public.gal_visibility_journal (mailbox_id, user_id)
  SELECT p_mailbox_id, v.id
    FROM public.directory_visible_users(p_mailbox_id) v
   WHERE v.id = ANY (p_user_ids)
  ON CONFLICT (mailbox_id, user_id) DO NOTHING;

  GET DIAGNOSTICS v_recorded = ROW_COUNT;
  RETURN jsonb_build_object('recorded', v_recorded);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp;

-- Ownership + EXECUTE grants (V254 guarded form): the definer is the worker
-- credential; EXECUTE is revoked from PUBLIC and re-granted to the runtime
-- roles (setjoin_app MUST keep EXECUTE — see the header note).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        ALTER FUNCTION public.gal_visibility_record(bigint, bigint[]) OWNER TO setjoin_worker;
    END IF;
    REVOKE EXECUTE ON FUNCTION public.gal_visibility_record(bigint, bigint[]) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.gal_visibility_record(bigint, bigint[]) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        GRANT EXECUTE ON FUNCTION public.gal_visibility_record(bigint, bigint[]) TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.gal_visibility_record(bigint, bigint[]) TO setjoin_worker;
    END IF;
END $$;
