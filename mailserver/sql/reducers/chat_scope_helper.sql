-- mailserver/sql/reducers/chat_scope_helper.sql — the Chat-family FORCE-RLS
-- SECURITY DEFINER scope helpers (ARCH-018 recipe rows 4 and 7).
--
-- Moved here from dbschema (arch review #A6): chat_member_role's live body
-- was the V133 search_path-pin CREATE OR REPLACE over V119's original;
-- chat_hold_active's live body is V127's. Reducer reload (fixed-point,
-- LC_ALL=C path order) CREATE OR REPLACEs over whatever the migrations
-- shipped, so this file is now the live definition; the historical
-- migrations are UNTOUCHED (first-CREATE record only — a future pin/logic
-- fix is a reducer edit here, not a new migration).
--
-- Both: STABLE, SECURITY DEFINER, `SET search_path = pg_catalog, public`,
-- owned by setjoin_worker (BYPASSRLS) via apply_worker_ownership(), EXECUTE
-- granted to the app/owner/worker trio only. See
-- docs/adr/ARCH-018-force-rls-scope-helper-recipe.md.

-- Row 4 — chat_member_role: row presence IS liveness (no left_at/banned_at —
-- chat_channel_members has no ban primitive; leaving DELETEs the row). Body
-- verbatim from V133 (the search_path-pin CREATE OR REPLACE).
CREATE OR REPLACE FUNCTION chat_member_role(p_channel_id bigint, p_user_id bigint)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT role FROM public.chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
$$;
SELECT apply_worker_ownership('chat_member_role(bigint,bigint)'::regprocedure);

-- Row 7 — chat_hold_active: a per-channel boolean (legal_hold OR an active
-- case hold), not a membership check — shares the recursion-dodge + pin
-- rationale (chat_channels has no UPDATE policy). Body verbatim from V127
-- (arm 1 the V126 boolean + arm 2 the case-hold EXISTS).
CREATE OR REPLACE FUNCTION chat_hold_active(p_channel_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT legal_hold FROM public.chat_channels WHERE id = p_channel_id), false)
      OR EXISTS (SELECT 1 FROM public.chat_case_hold_channels hc
                   JOIN public.chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL
                  WHERE hc.channel_id = p_channel_id)
$$;
SELECT apply_worker_ownership('chat_hold_active(bigint)'::regprocedure);
