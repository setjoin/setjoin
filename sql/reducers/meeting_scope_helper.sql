-- mailserver/sql/reducers/meeting_scope_helper.sql — the Meet-family
-- FORCE-RLS SECURITY DEFINER scope helpers (ARCH-018 recipe rows 5 and 6).
--
-- Moved here from dbschema (arch review #A6): both live bodies were the V133
-- search_path-pin CREATE OR REPLACE over their V125/V129 originals. Reducer
-- reload (fixed-point, LC_ALL=C path order) CREATE OR REPLACEs over whatever
-- the migrations shipped, so this file is now the live definition; the
-- historical migrations are UNTOUCHED (first-CREATE record only — a future
-- pin/logic fix is a reducer edit here, not a new migration).
--
-- Both: STABLE, SECURITY DEFINER, `SET search_path = pg_catalog, public`,
-- owned by setjoin_worker (BYPASSRLS) via apply_worker_ownership(), EXECUTE
-- granted to the app/owner/worker trio only. Row 5 and row 6 deliberately
-- filter OPPOSITE columns on the SAME table (meeting_participants) — see
-- docs/adr/ARCH-018-force-rls-scope-helper-recipe.md before touching either.

-- Row 5 — meeting_member_role: LIVE in-meeting reads. Filters left_at IS
-- NULL; deliberately NO banned_at filter (see the ADR's "kicked-but-not-yet-
-- evicted edge" — the SFU eviction, not this predicate, is the real-time
-- authority). Body verbatim from V133.
CREATE OR REPLACE FUNCTION meeting_member_role(p_meeting_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
    SELECT role FROM public.meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id AND left_at IS NULL
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC LIMIT 1
$$;
SELECT apply_worker_ownership('meeting_member_role(bigint,bigint)'::regprocedure);

-- Row 6 — meeting_attendee_role: POST-END recording/attendance reads (the
-- historical participant row — meeting_member_role is DEAD post-end since
-- meeting_end mass-stamps left_at). Filters banned_at IS NULL; deliberately
-- NO left_at filter (the inverse of row 5). Body verbatim from V133.
CREATE OR REPLACE FUNCTION meeting_attendee_role(p_meeting_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
    SELECT role FROM public.meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id AND banned_at IS NULL
       AND (role IN ('host', 'cohost') OR joined_at IS NOT NULL)
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC LIMIT 1
$$;
SELECT apply_worker_ownership('meeting_attendee_role(bigint,bigint)'::regprocedure);
