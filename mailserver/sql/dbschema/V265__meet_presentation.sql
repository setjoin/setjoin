-- V265__meet_presentation.sql — MEET plan M2: the reducer-owned presentation
-- session (docs/superpowers/plans/2026-08-25-meet-document-presentation-
-- semantic-recording.md, M2). §A the durable checkpoint table (the M0
-- "Presentation state" field set), §B its FORCE-RLS posture (participant-
-- scoped read backstop; reducer-owned mutation backstops), §C the durable
-- event rail (the versioned envelope facts each reducer commits atomically),
-- §D the feature.meet_document_presentation seed (DEFAULT OFF — the entire
-- M2 surface is inert until separately admitted).
--
-- Boundaries preserved verbatim:
--   · Meet never becomes a WOPI host and never touches blobs.ref_count —
--     this schema references Drive identities (drive_nodes /
--     drive_file_versions) and owns nothing about source bytes.
--   · V227 (the recording byte map / staging protection set) is untouched.
--   · Annotation snapshots are RESERVED: `annotation_snapshot_ref` exists
--     (the M0 checkpoint field set) but stays NULL until M4 admission — the
--     events CHECK below excludes every `annotation.*` kind, so a durable
--     annotation commit has no home to land in even if a future caller
--     bypassed the reducer's BZ277 refusal (fail closed at both layers).
--   · Status vocabulary is the frozen M0 lifecycle.go state machine:
--     PREPARING→READY/FAILED/CANCELLED · READY→ACTIVE/FAILED/CANCELLED ·
--     ACTIVE→ENDED/REVOKED/DEGRADED · DEGRADED→ACTIVE · terminals final.

-- ════════════════════════════════════════════════════════════════════════
-- §A — the durable presentation checkpoint (one live session per meeting).
-- The partial unique index is the row-serialized "one meeting authority"
-- belt: a second live session can never exist even if a future reducer
-- forgot its own existence guard. Terminal rows are history (the M0
-- checkpoint read may still converge a late joiner onto the last state).
-- source_sha256 is DERIVED from drive_file_versions.content_sha256 at
-- prepare/switch time (never request-owned identity — the R2 posture); it
-- pins the immutable version identity the session presents (SourceRef).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_presentations (
    id                       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id               bigint NOT NULL REFERENCES public.meetings(id),
    drive_node_id            bigint NOT NULL REFERENCES public.drive_nodes(id),
    drive_version_id         bigint NOT NULL REFERENCES public.drive_file_versions(id),
    source_sha256            text   NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_digest          text   NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    manifest_generation      bigint NOT NULL DEFAULT 1 CHECK (manifest_generation > 0),
    status                   text   NOT NULL DEFAULT 'PREPARING' CHECK (status IN
                             ('PREPARING','READY','ACTIVE','FAILED','CANCELLED','ENDED','REVOKED','DEGRADED')),
    presenter_participant_id bigint REFERENCES public.meeting_participants(id),
    presenter_generation     bigint NOT NULL DEFAULT 1 CHECK (presenter_generation > 0),
    page_index               integer NOT NULL DEFAULT 0 CHECK (page_index >= 0),
    checkpoint_seq           bigint  NOT NULL DEFAULT 0 CHECK (checkpoint_seq >= 0),
    -- M4 reservation: the annotation snapshot reference and the recording
    -- capture-mode snapshot ride the frozen M0 checkpoint field set. The
    -- ref is never written before M4 admits durable annotation commits
    -- (BZ277 in reducers/meeting_presentation.sql).
    annotation_snapshot_ref  text,
    recording_capture_mode   text,
    initiated_by             bigint NOT NULL,
    last_actor_user_id       bigint,
    started_at               timestamptz,
    ended_at                 timestamptz,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    reducer_state_version    bigint NOT NULL DEFAULT 1 CHECK (reducer_state_version > 0)
);

-- One LIVE session per meeting (the "one meeting authority" partial-unique
-- belt). Terminal states are excluded: history never blocks a new session.
CREATE UNIQUE INDEX meeting_presentations_live_uq
    ON public.meeting_presentations (meeting_id)
    WHERE status IN ('PREPARING','READY','ACTIVE','DEGRADED');
CREATE INDEX meeting_presentations_meeting_idx
    ON public.meeting_presentations (meeting_id, id);
CREATE INDEX meeting_presentations_nonterminal_idx
    ON public.meeting_presentations (status)
    WHERE status IN ('PREPARING','READY','ACTIVE','DEGRADED');

-- ════════════════════════════════════════════════════════════════════════
-- §B — FORCE RLS: the tenant-isolation backstop (R4), scoped to meeting
-- participants (the brief's "RLS scoped to meeting participant"). The
-- SECURITY DEFINER meeting_member_role (V125) is the scope helper — an
-- inline membership subquery would be the FORCE-RLS recursion trap
-- (ARCH-018). The write policies are the V134 posture: they admit the
-- reducer's legitimate app-pool write (the GUC convention below) and pin
-- the row's own identity fields; the VERB authority ladder stays in the
-- reducer (ARCH-006 app-level-primary). Fail-closed: no GUC ⇒ NULL ⇒ no
-- arm is true.
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_presentations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_presentations FORCE  ROW LEVEL SECURITY;

CREATE POLICY meeting_presentations_read ON public.meeting_presentations FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- INSERT (meeting_presentation_prepare): initiated_by pinned to the caller,
-- host/cohost floor (the meeting_recordings_insert V134 §E shape).
CREATE POLICY meeting_presentations_insert ON public.meeting_presentations FOR INSERT TO public
  WITH CHECK (initiated_by = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     AND meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));

-- UPDATE (page/grant/switch/degrade/recover/end/revoke + meeting_end's
-- same-txn cancel): any CURRENT participant is the tenant backstop — a
-- plain member may lawfully be the PRESENTER (verb-specific authority is
-- the reducer's ladder, not this policy's).
CREATE POLICY meeting_presentations_update ON public.meeting_presentations FOR UPDATE TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL)
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- ════════════════════════════════════════════════════════════════════════
-- §C — the durable event rail. Each mutating reducer commits exactly one
-- row atomically with its state bump; (checkpoint_seq) is per-session
-- monotonic and presenter_generation records the generation the event
-- executed under — the facts a versioned t:'presentation' envelope carries.
-- The kind CHECK is the CLOSED durable vocabulary; `annotation.cleared`/
-- `annotation.committed` are deliberately ABSENT — they parse on the
-- client (forward-compatible reads) but have NO durable home until M4
-- admission (envelope.go DurableCommittable + the reducer's BZ277).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_presentation_events (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    presentation_id      bigint NOT NULL REFERENCES public.meeting_presentations(id) ON DELETE CASCADE,
    meeting_id           bigint NOT NULL REFERENCES public.meetings(id) ON DELETE CASCADE,
    checkpoint_seq       bigint NOT NULL CHECK (checkpoint_seq > 0),
    presenter_generation bigint NOT NULL CHECK (presenter_generation > 0),
    kind                 text   NOT NULL CHECK (kind IN
                         ('start','ready','page.changed','presenter.granted','presenter.takeover',
                          'source.switched','fallback.changed','end')),
    actor_user_id        bigint,
    actor_participant_id bigint,
    payload              jsonb,
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX meeting_presentation_events_seq_uq
    ON public.meeting_presentation_events (presentation_id, checkpoint_seq);
CREATE INDEX meeting_presentation_events_meeting_idx
    ON public.meeting_presentation_events (meeting_id, id);

ALTER TABLE public.meeting_presentation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_presentation_events FORCE  ROW LEVEL SECURITY;

CREATE POLICY meeting_presentation_events_read ON public.meeting_presentation_events FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY meeting_presentation_events_insert ON public.meeting_presentation_events FOR INSERT TO public
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- ════════════════════════════════════════════════════════════════════════
-- §D — the toggle. DEFAULT OFF: the entire M2 surface is inert (routes 404,
-- reducers unreachable through them) until separately admitted. Operator
-- semantics (shared/toggle): ChangeLive + DisableDrain with feature.meet +
-- feature.drive dependencies — the flip never strands an accepted session;
-- the drain verbs (end/revoke/checkpoint read) stay reachable for committed
-- state exactly like recording's stop (D11: a toggle gates new intent,
-- never the draining of committed state).
-- ════════════════════════════════════════════════════════════════════════
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.meet_document_presentation', false,
   'MEET M2 reducer-owned presentation session (prepare/start, presenter grant/takeover, page change, source-version switch, degrade/recover, end). Gates the new-intent routes; end/revoke/checkpoint drain committed sessions unconditionally. Requires feature.meet + feature.drive ON.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (265, now())
    ON CONFLICT (version) DO NOTHING;
