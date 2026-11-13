-- V135 — drive_chunks INSERT policy: honor DERIVED space memberships.
--
-- Found LIVE by the 2026-07-16 fresh-VM systemd gate (chat+drive attachment
-- smoke under the constrained setjoin_app runtime): chat attachment upload
-- 500'd at drive_chunk_register — "new row violates row-level security policy
-- for table drive_chunks" — on EVERY native-RLS deployment. Two compounding
-- causes in the V114 drive_chunks_insert 'g'-scope (global-dedup) arm:
--
--   1. It authorized via a DIRECT drive_space_members lookup, predating A2/B2
--      derived membership: chat-bound (V120) and meeting-bound (V129) spaces
--      carry ZERO drive_space_members rows by design (DES-009 even BLOCKS
--      ad-hoc grants there, BZ175). A user whose only Drive access is derived
--      — every chat/meeting participant — matched nothing.
--   2. The obvious fix ("EXISTS over drive_spaces WHERE drive_member_role IN
--      (…)") does NOT work from inside a policy: that inner drive_spaces read
--      is ITSELF RLS-filtered, and drive_spaces_read (V129) deliberately
--      HIDES chat/meeting-bound spaces — so the EXISTS sees nothing for the
--      derived members we need to admit.
--
-- Fix: a SECURITY DEFINER helper (setjoin_worker-owned, BYPASSRLS — the
-- drive_member_role genre) answers "is this user manager/editor of ANY
-- regular space." The three membership arms are INLINED verbatim from
-- drive_member_role v3 (V129) rather than CALLED: a nested STABLE-DEFINER
-- call, evaluated inside another DEFINER helper inside a plpgsql reducer's
-- RLS WITH CHECK, silently returned no rows on the live gate even though the
-- top-level call returned true — inlining sidesteps that nested-context
-- evaluation entirely (proven live: reducer INSERT passes post-inline). The
-- s<id> compliance-scope arm (drive_member_role-based, single level) is
-- unchanged.

CREATE OR REPLACE FUNCTION public.drive_user_can_write_regular(p_user_id bigint)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT EXISTS (
     SELECT 1 FROM public.drive_spaces s
      WHERE s.classification = 'regular'
        AND (
          -- arm 1: explicit membership (plain spaces)
          EXISTS (SELECT 1 FROM public.drive_space_members m
                   WHERE m.space_id = s.id AND m.user_id = p_user_id
                     AND m.role IN ('manager','editor'))
          -- arm 2: chat-derived (V120) — owner/admin ⇒ manager, else editor
          OR EXISTS (SELECT 1 FROM public.chat_channel_members cm
                      WHERE cm.channel_id = s.chat_channel_id AND cm.user_id = p_user_id)
          -- arm 3: meeting-derived (V129) — any non-banned participant is at
          -- least viewer, host/cohost manager; only manager/editor may write,
          -- so a plain meeting attendee (viewer) does NOT gain global-write
          OR EXISTS (SELECT 1 FROM public.meeting_participants p
                      WHERE p.meeting_id = s.meeting_id AND p.user_id = p_user_id
                        AND p.banned_at IS NULL AND p.role IN ('host','cohost')))) $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    ALTER FUNCTION public.drive_user_can_write_regular(bigint) OWNER TO setjoin_worker;
  END IF;
  REVOKE ALL ON FUNCTION public.drive_user_can_write_regular(bigint) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.drive_user_can_write_regular(bigint) TO setjoin_app;
  END IF;
END $$;

DROP POLICY IF EXISTS drive_chunks_insert ON public.drive_chunks;
CREATE POLICY drive_chunks_insert ON public.drive_chunks FOR INSERT TO public
  WITH CHECK (
    (scope_key = 'g'
      AND public.drive_user_can_write_regular(
            (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)))
    OR (scope_key ~ '^s[0-9]+$'
        AND public.drive_member_role(substring(scope_key from 2)::bigint,
              (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('manager','editor')));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (135, now())
ON CONFLICT (version) DO NOTHING;
