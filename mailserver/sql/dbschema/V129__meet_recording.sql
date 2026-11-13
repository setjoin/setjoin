-- V129__meet_recording.sql — Meet B2: recording → Drive substrate.
-- Spec: docs/superpowers/specs/2026-07-15-meet-B2-recording-design.md §4.
-- §A meeting-bound spaces (the V120 §A clone) · §B the recording registry
-- (FORCE RLS, attendee-scoped SELECT, reducer-only mutation) · §B2 the
-- post-end role gate meeting_attendee_role · §C drive_member_role v3
-- (attendance-derivation arm) · §D governance policy halves (DES-009 parity;
-- the BZ175 reducer belts live in the reducer files, Tasks 2/3) · §E retire
-- the dead settings.recording stub · §F toggle.

-- §A — meeting-bound spaces (D1: ON DELETE SET NULL, the exact V120 §A shape)
ALTER TABLE public.drive_spaces ADD COLUMN meeting_id bigint
    REFERENCES public.meetings(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX drive_spaces_meeting_uq ON public.drive_spaces (meeting_id)
    WHERE meeting_id IS NOT NULL;

-- §B — the recording registry. meeting_id is a plain REFERENCES (RESTRICT):
-- a record table fails loudly, never silently vanishes. staging_key is OURS
-- (Go composes it into StartRoomComposite and persists it at bind — NEVER
-- derived from egress_ended, whose payload only confirms size/duration).
CREATE TABLE public.meeting_recordings (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id      bigint NOT NULL REFERENCES public.meetings(id),
    egress_id       text UNIQUE,
    state           text NOT NULL DEFAULT 'requested' CHECK (state IN
                    ('requested','active','stopping','pending_ingest','ready','failed')),
    started_by      bigint NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    stopped_at      timestamptz,
    staging_key     text,
    size_bytes      bigint,
    duration_ms     bigint,
    file_node_id    bigint REFERENCES public.drive_nodes(id),
    version_id      bigint REFERENCES public.drive_file_versions(id),
    ingest_attempts int NOT NULL DEFAULT 0,  -- §6.4 bounded-retry state (plan delta 9)
    error           text
);
CREATE INDEX meeting_recordings_meeting_idx ON public.meeting_recordings (meeting_id);
CREATE INDEX meeting_recordings_nonterminal_idx ON public.meeting_recordings (state)
    WHERE state NOT IN ('ready','failed');

-- §B2 — the post-end role gate. meeting_member_role (V125) filters
-- left_at IS NULL and meeting end mass-stamps left_at — it is DEAD for every
-- post-end surface. This helper reads the HISTORICAL participant row:
-- host/cohost count regardless of joined_at (their row is reducer-created,
-- and the ingest attributes to the meeting owner — plan deltas 7/10); a plain member
-- counts only with the webhook-fed attendance stamp (D2's admission-vs-
-- attendance line); banned_at excludes (kick=ban, gate-ratified); NO left_at
-- filter (attendance is the historical fact). SECURITY DEFINER + pinned
-- search_path (the V125 eng-#2 pin, same recursion-dodge family).
CREATE OR REPLACE FUNCTION meeting_attendee_role(p_meeting_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $$
    SELECT role FROM public.meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id AND banned_at IS NULL
       AND (role IN ('host', 'cohost') OR joined_at IS NOT NULL)
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC LIMIT 1
$$;
SELECT apply_worker_ownership('meeting_attendee_role(bigint,bigint)'::regprocedure);

ALTER TABLE public.meeting_recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_recordings FORCE  ROW LEVEL SECURITY;
-- SELECT via the attendee gate (NOT meeting_member_role — dead post-end).
-- No mutation policies: reducers on the app pool (ARCH-006 app-level-primary);
-- the guest lobby has no recording surface.
CREATE POLICY meeting_recordings_read ON public.meeting_recordings FOR SELECT TO public
  USING (meeting_attendee_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- §C — drive_member_role v3: arm 3, attendance derivation (D2). Same
-- COALESCE chain as V120 §C; NULL for every non-meeting space (the V120
-- arm-2 no-op proof shape). host/cohost → 'manager' (title only — bound-
-- space manager verbs stay gated per DES-009 D2); attended member →
-- 'viewer'; banned excluded; NO left_at filter (meeting_end mass-stamps
-- left_at; attendance is historical fact). Guests have no users row, so
-- p.user_id = p_user_id can never match one (guest access = the
-- guest-accounts program's seam).
-- M5 note (V120 §C's flag, verbatim carry-forward): CREATE OR REPLACE on the
-- worker-owned function requires the connecting role to BE the owner or a
-- superuser. The mailctl resolveSchemaDSN DB_OWNER_DSN gap is STILL open —
-- re-confirm before this migration ships in production (spec §12.5).
CREATE OR REPLACE FUNCTION public.drive_member_role(p_space_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT COALESCE(
     (SELECT role FROM public.drive_space_members
       WHERE space_id = p_space_id AND user_id = p_user_id),
     (SELECT CASE WHEN m.role IN ('owner','admin') THEN 'manager' ELSE 'editor' END
        FROM public.drive_spaces s
        JOIN public.chat_channel_members m ON m.channel_id = s.chat_channel_id
       WHERE s.id = p_space_id AND m.user_id = p_user_id),
     (SELECT CASE WHEN p.role IN ('host','cohost') THEN 'manager'
                  WHEN p.joined_at IS NOT NULL THEN 'viewer' END
        FROM public.drive_spaces s
        JOIN public.meeting_participants p ON p.meeting_id = s.meeting_id
       WHERE s.id = p_space_id AND p.user_id = p_user_id AND p.banned_at IS NULL)
   ) $$;
SELECT apply_worker_ownership('drive_member_role(bigint,bigint)'::regprocedure);

-- §D — governance policy halves (DES-009 parity; V120 §D's exact bodies with
-- ONLY the meeting_id guard clauses added — no other predicate text changes).
-- D3-parity: the owner-read arm is inert on ANY bound space (chat or meeting).
DROP POLICY drive_spaces_read ON public.drive_spaces;
CREATE POLICY drive_spaces_read ON public.drive_spaces FOR SELECT TO public
  USING (public.drive_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR (chat_channel_id IS NULL AND meeting_id IS NULL
         AND owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) -- self-seed window; inert on bound spaces (DES-009 D3, B2 parity)
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.view'));

-- D2-parity: no ad-hoc drive_space_members rows on ANY bound space — EVER.
DROP POLICY drive_space_members_write ON public.drive_space_members;
CREATE POLICY drive_space_members_write ON public.drive_space_members FOR ALL TO public
  USING (public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     OR user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK ((public.drive_member_role(space_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) = 'manager'
     AND NOT EXISTS (SELECT 1 FROM public.drive_spaces s WHERE s.id = space_id
                       AND (s.chat_channel_id IS NOT NULL OR s.meeting_id IS NOT NULL)))
     OR (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND role = 'manager'
         AND public.drive_space_owner(space_id) = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
         AND EXISTS (SELECT 1 FROM public.drive_spaces s WHERE s.id = space_id
                       AND s.chat_channel_id IS NULL AND s.meeting_id IS NULL)));

-- §E — retire the dead stub: the settings DEFAULT drops "recording" (never
-- read in B1; recording truth is meeting_recordings). Old rows harmless —
-- the key was never read; meeting_create.sql stops writing it in Task 2.
ALTER TABLE public.meetings ALTER COLUMN settings
    SET DEFAULT '{"guestAllowed": false}';

-- §F — toggle (D11: gates the START route only; drain runs unconditionally)
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.meet_recording', false,
   'Meet B2 recording→Drive. Gates the recording START route only; stop/webhook/ingest drain unconditionally. Requires feature.meet + feature.drive ON and the setjoin-egress + setjoin-valkey sidecars.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (129, now())
    ON CONFLICT (version) DO NOTHING;
