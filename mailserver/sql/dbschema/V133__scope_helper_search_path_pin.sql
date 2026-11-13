-- V133__scope_helper_search_path_pin.sql — pipeline review arch finding #2
-- (Strong): normalize the SECURITY DEFINER scope-helper search_path pin.
-- ADR: docs/adr/ARCH-018-force-rls-scope-helper-recipe.md.
--
-- The drive family (drive_member_role/drive_space_owner/drive_has_admin_perm,
-- V114; chat_hold_active, V126/V127) all pin `SET search_path = pg_catalog,
-- public` — the belt against the classic SECURITY DEFINER search_path
-- privilege-escalation foot-gun (a caller-controlled search_path could shadow
-- an unqualified catalog identifier with a same-named object in a schema they
-- control; pinning pg_catalog first closes that even though every statement
-- in these bodies already schema-qualifies its own tables with `public.`).
-- chat_member_role (V119) and meeting_member_role (V125) shipped pinning
-- `public` ONLY — V125's own comment names the foot-gun and then uses the
-- weaker form. meeting_attendee_role (V129) copied the V125 shape verbatim.
--
-- CREATE OR REPLACE, bodies BYTE-IDENTICAL to their most recent definition —
-- the ONLY delta is the search_path clause. Behavior-invariant: pg_catalog is
-- already implicitly first in any search_path that doesn't explicitly
-- exclude it, and every SELECT in these three bodies already schema-
-- qualifies `public.<table>`, so this is a hardening no-op, not a fix to an
-- observed exploit. apply_worker_ownership() re-run defensively (matches the
-- V120/V127/V129 CREATE-OR-REPLACE precedent) though CREATE OR REPLACE does
-- not itself reset ownership/grants.

CREATE OR REPLACE FUNCTION chat_member_role(p_channel_id bigint, p_user_id bigint)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT role FROM public.chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
$$;
SELECT apply_worker_ownership('chat_member_role(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION meeting_member_role(p_meeting_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
    SELECT role FROM public.meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id AND left_at IS NULL
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC LIMIT 1
$$;
SELECT apply_worker_ownership('meeting_member_role(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION meeting_attendee_role(p_meeting_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
    SELECT role FROM public.meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id AND banned_at IS NULL
       AND (role IN ('host', 'cohost') OR joined_at IS NOT NULL)
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC LIMIT 1
$$;
SELECT apply_worker_ownership('meeting_attendee_role(bigint,bigint)'::regprocedure);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (133, now())
    ON CONFLICT (version) DO NOTHING;
