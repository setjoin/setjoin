-- V266__meet_semantic_recording.sql — MEET plan M4 slice 1: the semantic
-- event capture and replay durable state (docs/superpowers/plans/
-- 2026-08-25-meet-document-presentation-semantic-recording.md, M4), over the
-- frozen M0/M1 contracts in mailserver/internal/meet/presentation/
-- (lifecycle.go's .sjrec package machine, segment.go's segment binding
-- contract, sjrec.go's manifest grammar, acquisition.go's fail-closed
-- adapter, export.go's idempotent export receipt).
--
-- §A meeting_semantic_recordings — the `.sjrec` logical package row: the
--     recording-active lifecycle (single primary mode, BZ199 guest arm via
--     meeting_recording_active's extension in meeting_recording.sql), the
--     version-pinned capture profile, and the reducer-atomic package state
--     (ACTIVE→DELETE_PENDING→{HELD_COMPLETE,HELD_PARTIAL,DELETED};
--     HELD_PARTIAL ineligible for restore in V1).
-- §B meeting_semantic_segments — the segment binding contract: every segment
--     binds meeting/recording ID, content digest, actual MIME/codec, time
--     interval and completeness. Verified requires digest+size+ack; the
--     unique (recording, seq) + the overlap belt in the ingest reducer make
--     duplicate media impossible, and interrupted/failed rows are truthful
--     partial results, never fabricated silence.
-- §C meeting_semantic_children — the expected child set the delete sweep
--     releases one receipt at a time (the worker never touches
--     blobs.ref_count; it requests each release through the owning reducer).
-- §D meeting_semantic_exports — the idempotent export receipts: one
--     (recording, generation) identity; retries re-enter the same receipt;
--     a ready receipt is immutable, so a retry can never mint a second
--     Drive version.
-- §E FORCE RLS on all four tables (R4), scoped through the existing
--     SECURITY DEFINER helpers (meeting_member_role live /
--     meeting_attendee_role historical) — the V265 posture verbatim; the
--     GUC-less worker plane rides SECURITY DEFINER reducers
--     (meeting_recording_event precedent).
--
-- Feature flag: NONE seeded here. `feature.meet_semantic_recording` already
-- exists DEFAULT OFF in the V264 registry projection; this slice adds no
-- route and no user-visible behavior — rows are created only through the
-- reducers (pgTAP/worker), and every worker arm is a D11 drain leg that
-- converges committed state regardless of any toggle.

-- ════════════════════════════════════════════════════════════════════════
-- §A — the .sjrec logical package row (one live recording per meeting).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_semantic_recordings (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id      bigint NOT NULL REFERENCES public.meetings(id),
    capture_mode    text   NOT NULL DEFAULT 'server_audio' CHECK (capture_mode IN
                    ('server_audio','local_registered','b2_companion_index')),
    -- Recording-active lifecycle: 'active' while capture runs; terminal
    -- values are history (stopped truthfully, or failed without capture).
    rec_state       text   NOT NULL DEFAULT 'active' CHECK (rec_state IN
                    ('active','stopped','failed')),
    -- The .sjrec package lifecycle (lifecycle.go PackageState; transitions
    -- are reducer-owned via CanTransitionPackage).
    package_state   text   NOT NULL DEFAULT 'ACTIVE' CHECK (package_state IN
                    ('ACTIVE','DELETE_PENDING','HELD_COMPLETE','HELD_PARTIAL','DELETED')),
    -- Version-pinned capture profile (acquisition.go CaptureProfile). An
    -- evidence-pending profile carries class 'evidence_pending' and empty
    -- pins — the fail-closed classification, recorded as a fact.
    profile_class   text   NOT NULL DEFAULT 'evidence_pending' CHECK (profile_class IN
                    ('qualified','evidence_pending','unsupported')),
    producer_id       text NOT NULL DEFAULT '',
    producer_version  text NOT NULL DEFAULT '',
    container         text NOT NULL DEFAULT '',
    codec             text NOT NULL DEFAULT '',
    profile_evidence  text NOT NULL DEFAULT '',
    policy_mode     text   NOT NULL DEFAULT 'server_only' CHECK (policy_mode IN
                    ('local_preferred','server_only','local_only','disabled')),
    -- Local registration truthfulness: a local_only capture registers
    -- locally and must never be represented as centrally retained bytes.
    local_only      boolean NOT NULL DEFAULT false,
    manifest_digest text   CHECK (manifest_digest IS NULL OR manifest_digest ~ '^[0-9a-f]{64}$'),
    timeline_sha256 text   CHECK (timeline_sha256 IS NULL OR timeline_sha256 ~ '^[0-9a-f]{64}$'),
    timeline_records integer CHECK (timeline_records IS NULL OR timeline_records >= 0),
    -- Delete/hold fencing (lifecycle.go): deletion_generation serializes
    -- release receipts; pending holds suspend the sweep.
    deletion_generation bigint NOT NULL DEFAULT 0 CHECK (deletion_generation >= 0),
    holds           integer NOT NULL DEFAULT 0 CHECK (holds >= 0),
    started_by      bigint NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    stopped_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One LIVE semantic recording per meeting — the single-primary-mode belt
-- behind the BZ278 existence guard (the meeting_presentations_live_uq shape).
CREATE UNIQUE INDEX meeting_semantic_recordings_live_uq
    ON public.meeting_semantic_recordings (meeting_id)
    WHERE rec_state = 'active' AND package_state = 'ACTIVE';
CREATE INDEX meeting_semantic_recordings_meeting_idx
    ON public.meeting_semantic_recordings (meeting_id, id);
CREATE INDEX meeting_semantic_recordings_delete_pending_idx
    ON public.meeting_semantic_recordings (package_state)
    WHERE package_state = 'DELETE_PENDING';

-- A stop truthfully stamps when it happened.
ALTER TABLE public.meeting_semantic_recordings
    ADD CONSTRAINT meeting_semantic_recordings_stopped_at_chk
    CHECK (rec_state = 'active' OR stopped_at IS NOT NULL);

-- ════════════════════════════════════════════════════════════════════════
-- §B — segment bindings (the M4 bullet 2 contract, durable twin of
-- presentation/segment.go). Segments number from 1 per recording; a
-- restart opens a NEW seq, never rewrites an old row.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_semantic_segments (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recording_id   bigint NOT NULL REFERENCES public.meeting_semantic_recordings(id) ON DELETE CASCADE,
    seq            integer NOT NULL CHECK (seq >= 1),
    state          text   NOT NULL CHECK (state IN ('capturing','verified','interrupted','failed')),
    ack_state      text   NOT NULL DEFAULT 'none' CHECK (ack_state IN
                   ('none','pending','acknowledged','lost')),
    content_sha256 text   CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'),
    byte_size      bigint CHECK (byte_size IS NULL OR byte_size > 0),
    mime_type      text   NOT NULL DEFAULT '',
    codec          text   NOT NULL DEFAULT '',
    container      text   NOT NULL DEFAULT '',
    start_ms       bigint NOT NULL CHECK (start_ms >= 0),
    end_ms         bigint NOT NULL CHECK (end_ms > start_ms),
    wall_start_unix_ms bigint NOT NULL,
    wall_end_unix_ms   bigint NOT NULL,
    interrupt_reason text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    -- Truthful completeness: only a verified segment claims bytes; a
    -- verified segment MUST carry digest+size+ack (MR-01 source
    -- completeness — an unsupported complete-record claim has no home).
    CONSTRAINT meeting_semantic_segments_verified_complete_chk CHECK (
        (state = 'verified') = (content_sha256 IS NOT NULL AND byte_size IS NOT NULL
                                AND ack_state = 'acknowledged'
                                AND mime_type <> '' AND codec <> '' AND container <> '')),
    CONSTRAINT meeting_semantic_segments_interrupt_reason_chk CHECK (
        state NOT IN ('interrupted','failed') OR interrupt_reason IS NOT NULL),
    CONSTRAINT meeting_semantic_segments_wall_chk CHECK (wall_end_unix_ms >= wall_start_unix_ms)
);

CREATE UNIQUE INDEX meeting_semantic_segments_seq_uq
    ON public.meeting_semantic_segments (recording_id, seq);

-- The no-duplicate-media belt at the storage layer (the blobs.ref_count
-- genre: trigger-maintained invariant). The ingest reducer's overlap
-- refusal is the authority — every ingest serializes on its recording's
-- FOR UPDATE row lock, so it is race-free by construction — and this
-- trigger is the belt that fires even for a writer that bypassed the
-- reducer. Two VERIFIED segments of one recording can never share media
-- time (MR-01/never duplicate media); capturing/interrupted/failed rows
-- are exempt (their intervals are provisional or partially observed).
CREATE OR REPLACE FUNCTION meeting_semantic_segments_no_overlap_trg()
RETURNS trigger AS $$
DECLARE
    v_other integer;
BEGIN
    IF NEW.state = 'verified' THEN
        SELECT s.seq INTO v_other
          FROM meeting_semantic_segments s
         WHERE s.recording_id = NEW.recording_id
           AND s.id <> NEW.id
           AND s.state = 'verified'
           AND s.start_ms < NEW.end_ms AND NEW.start_ms < s.end_ms
         LIMIT 1;
        IF v_other IS NOT NULL THEN
            RAISE EXCEPTION 'verified segments % and % overlap — duplicate media fails closed',
                v_other, NEW.seq
                USING ERRCODE='BZ279',
                      HINT='{"type":"conflict","detail":"duplicate media interval"}';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER meeting_semantic_segments_no_overlap
    BEFORE INSERT OR UPDATE ON public.meeting_semantic_segments
    FOR EACH ROW EXECUTE FUNCTION meeting_semantic_segments_no_overlap_trg();

-- ════════════════════════════════════════════════════════════════════════
-- §C — the expected child set (the delete sweep's receipt ledger).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_semantic_children (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recording_id bigint NOT NULL REFERENCES public.meeting_semantic_recordings(id) ON DELETE CASCADE,
    child        text   NOT NULL CHECK (child IN
                 ('manifest.json','timeline.ndjson','presentations/<presentation-id>.json',
                  'captions/<language>.vtt','media/audio-<segment>',
                  'media/legacy-video-reference.json','annotations/<snapshot>.json',
                  'integrity/sha256.json')),
    child_state  text   NOT NULL DEFAULT 'absent' CHECK (child_state IN
                 ('embedded','retained','absent','expired')),
    required     boolean NOT NULL DEFAULT true,
    released     boolean NOT NULL DEFAULT false,
    release_generation bigint CHECK (release_generation IS NULL OR release_generation >= 0),
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX meeting_semantic_children_child_uq
    ON public.meeting_semantic_children (recording_id, child);
CREATE INDEX meeting_semantic_children_recording_idx
    ON public.meeting_semantic_children (recording_id, released);

-- ════════════════════════════════════════════════════════════════════════
-- §D — idempotent export receipts. One (recording, generation) identity:
-- the unique index IS the no-duplicate-Drive-version guarantee's root.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_semantic_exports (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recording_id bigint NOT NULL REFERENCES public.meeting_semantic_recordings(id) ON DELETE CASCADE,
    generation   bigint NOT NULL CHECK (generation >= 1),
    state        text   NOT NULL DEFAULT 'pending' CHECK (state IN
                 ('pending','composing','ready','failed')),
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    bounds       jsonb,
    exclusions   jsonb,
    error        text,
    drive_node_id    bigint,
    drive_version_id bigint,
    claimed_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT meeting_semantic_exports_ready_identity_chk CHECK (
        state <> 'ready' OR (drive_node_id IS NOT NULL AND drive_version_id IS NOT NULL))
);
CREATE UNIQUE INDEX meeting_semantic_exports_receipt_uq
    ON public.meeting_semantic_exports (recording_id, generation);
CREATE INDEX meeting_semantic_exports_pending_idx
    ON public.meeting_semantic_exports (state)
    WHERE state IN ('pending','composing');

-- ════════════════════════════════════════════════════════════════════════
-- §E — FORCE RLS (R4). Same posture as V265: participant-scoped read
-- backstops via the SECURITY DEFINER helpers, reducer-admitting write
-- backstops, fail-closed with no GUC. The worker plane (segment ingest,
-- child release, export claim/complete) reaches these tables ONLY through
-- SECURITY DEFINER reducers (the meeting_recording_event precedent), so
-- every policy can stay participant-scoped without a worker bypass.
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_semantic_recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_semantic_recordings FORCE  ROW LEVEL SECURITY;
CREATE POLICY meeting_semantic_recordings_read ON public.meeting_semantic_recordings FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY meeting_semantic_recordings_insert ON public.meeting_semantic_recordings FOR INSERT TO public
  WITH CHECK (started_by = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     AND meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));
CREATE POLICY meeting_semantic_recordings_update ON public.meeting_semantic_recordings FOR UPDATE TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL)
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

ALTER TABLE public.meeting_semantic_segments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_semantic_segments FORCE  ROW LEVEL SECURITY;
CREATE POLICY meeting_semantic_segments_read ON public.meeting_semantic_segments FOR SELECT TO public
  USING (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_segments.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY meeting_semantic_segments_insert ON public.meeting_semantic_segments FOR INSERT TO public
  WITH CHECK (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_segments.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY meeting_semantic_segments_update ON public.meeting_semantic_segments FOR UPDATE TO public
  USING (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_segments.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL))
  WITH CHECK (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_segments.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));

ALTER TABLE public.meeting_semantic_children ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_semantic_children FORCE  ROW LEVEL SECURITY;
CREATE POLICY meeting_semantic_children_read ON public.meeting_semantic_children FOR SELECT TO public
  USING (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_children.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY meeting_semantic_children_all ON public.meeting_semantic_children FOR INSERT TO public
  WITH CHECK (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_children.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY meeting_semantic_children_update ON public.meeting_semantic_children FOR UPDATE TO public
  USING (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_children.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL))
  WITH CHECK (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_children.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));

ALTER TABLE public.meeting_semantic_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_semantic_exports FORCE  ROW LEVEL SECURITY;
CREATE POLICY meeting_semantic_exports_read ON public.meeting_semantic_exports FOR SELECT TO public
  USING (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_exports.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
CREATE POLICY meeting_semantic_exports_insert ON public.meeting_semantic_exports FOR INSERT TO public
  WITH CHECK (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_exports.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost')));
CREATE POLICY meeting_semantic_exports_update ON public.meeting_semantic_exports FOR UPDATE TO public
  USING (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_exports.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL))
  WITH CHECK (EXISTS (SELECT 1 FROM meeting_semantic_recordings r
                  WHERE r.id = meeting_semantic_exports.recording_id
                    AND meeting_member_role(r.meeting_id,
                          (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (266, now())
    ON CONFLICT (version) DO NOTHING;
