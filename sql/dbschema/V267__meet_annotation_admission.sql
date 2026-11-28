-- V267__meet_annotation_admission.sql — MEET plan M4: the durable annotation
-- admission (docs/superpowers/plans/2026-08-25-meet-document-presentation-
-- semantic-recording.md, M4 "annotation snapshots"; the M2 reservation's
-- BZ277 flip). This migration ADDS the admission path; it does NOT remove
-- the guard:
--   · The V265 events kind CHECK is widened to admit exactly the two
--     reserved envelope kinds (`annotation.committed`, `annotation.cleared`)
--     — a COMMITTED annotation is admitted. Every other path stays
--     fail-closed: the only writer is the reducer
--     meeting_presentation_annotation_commit's admitted shape gate, and the
--     reducer refuses BZ277 every annotation-shaped call that does not carry
--     a well-formed snapshot (the M2 always-refusal narrows to
--     admitted-path semantics; no code renumbering).
--   · §A adds the durable snapshot ledger the admission commits into: the
--     exact serialized snapshot bytes, bound to the presentation checkpoint
--     (id + checkpoint seq + presenter generation) — the `.sjrec`
--     SJRecAnnotationBinding's durable twin (sjrec.go: "binds one durable
--     annotation snapshot: the exact presentation checkpoint the snapshot
--     rendered"). Content identity is DERIVED in-database from the stored
--     bytes (never request-trusted — the R2 posture): sha256 + byte size
--     are CHECK-verified against `content` itself, so a row can never carry
--     a digest that its bytes do not hash to.
--   · The snapshot path is the `.sjrec` stable-ref path grammar
--     (`annotations/<snapshot>.json`, V266 §C's child literal), derived by
--     the reducer from (presentation, checkpoint) — never request-owned.
--   · §B FORCE RLS (R4) in the V265/V266 posture: the read backstop scopes
--     through meeting_attendee_role — the HISTORICAL helper the meet DOX
--     prescribes for every post-end surface, because durable annotation
--     snapshots are RETAINED material a post-end replay read converges on
--     (the meeting_recordings posture, not the live-rail one).
--   · No new feature toggle: annotation commits ride the existing
--     feature.meet_document_presentation gate (V265 §D) — an admitted
--     presentation session's own verb family — and the replay read is
--     committed-state drain (D11), reachable with any flag OFF.

-- ════════════════════════════════════════════════════════════════════════
-- §A — the durable annotation snapshot ledger (one row per committed
-- snapshot; the (presentation, checkpoint_seq) unique index IS the emit
-- rail's own belt — a snapshot binds exactly one durable event).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_presentation_annotations (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    presentation_id      bigint NOT NULL REFERENCES public.meeting_presentations(id) ON DELETE CASCADE,
    meeting_id           bigint NOT NULL REFERENCES public.meetings(id) ON DELETE CASCADE,
    checkpoint_seq       bigint NOT NULL CHECK (checkpoint_seq > 0),
    presenter_generation bigint NOT NULL CHECK (presenter_generation > 0),
    actor_user_id        bigint,
    actor_participant_id bigint,
    snapshot_path        text   NOT NULL CHECK (snapshot_path ~ '^annotations/p[0-9]+-s[0-9]+\.json$'),
    -- The EXACT serialized snapshot bytes (the durable convergence payload a
    -- reconnecting attendee reads back through the authorized bounded
    -- reference/read path). Bounded at the stored-object 16 KiB limit — a
    -- larger snapshot has no home here (BZ277 at the reducer); it needs the
    -- separately designed reference-storage contract, never fragmentation.
    content              text   NOT NULL CHECK (content <> ''),
    content_sha256       text   NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    byte_size            integer NOT NULL CHECK (byte_size > 0 AND byte_size <= 16384),
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- Content identity is derived from the stored bytes, in-database: the
    -- digest and size a row claims are ITS BYTES' digest and size, or the
    -- row cannot exist.
    CONSTRAINT meeting_presentation_annotations_content_identity_chk CHECK (
        octet_length(convert_to(content, 'UTF8')) = byte_size
        AND encode(sha256(convert_to(content, 'UTF8')), 'hex') = content_sha256)
);

CREATE UNIQUE INDEX meeting_presentation_annotations_seq_uq
    ON public.meeting_presentation_annotations (presentation_id, checkpoint_seq);
CREATE INDEX meeting_presentation_annotations_meeting_idx
    ON public.meeting_presentation_annotations (meeting_id, id);

-- ════════════════════════════════════════════════════════════════════════
-- §B — FORCE RLS (R4): the V265 posture. Read backstop through the
-- HISTORICAL attendee gate (retained material — see header); write
-- backstops admit the reducer's legitimate app-pool write and stay
-- participant-scoped (the verb authority ladder is the reducer's, ARCH-006).
-- Fail-closed: no GUC ⇒ NULL ⇒ no arm is true.
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_presentation_annotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_presentation_annotations FORCE  ROW LEVEL SECURITY;

CREATE POLICY meeting_presentation_annotations_read ON public.meeting_presentation_annotations FOR SELECT TO public
  USING (meeting_attendee_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY meeting_presentation_annotations_insert ON public.meeting_presentation_annotations FOR INSERT TO public
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY meeting_presentation_annotations_update ON public.meeting_presentation_annotations FOR UPDATE TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL)
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- ════════════════════════════════════════════════════════════════════════
-- §C — the events CHECK widening: the closed durable vocabulary admits the
-- two annotation kinds NOW, because a committed annotation is admitted —
-- through exactly one writer, the reducer's admitted shape gate (BZ277
-- narrows from always-refused to admitted-path semantics; the un-admitted
-- paths — malformed, oversized, or reference-less annotation shapes — still
-- refuse BZ277 and now have NO belt-less landing zone either: the table
-- identity CHECK and the reducer's own gates fence them).
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_presentation_events
    DROP CONSTRAINT meeting_presentation_events_kind_check;
ALTER TABLE public.meeting_presentation_events
    ADD CONSTRAINT meeting_presentation_events_kind_check CHECK (kind IN
        ('start','ready','page.changed','presenter.granted','presenter.takeover',
         'annotation.committed','annotation.cleared',
         'source.switched','fallback.changed','end'));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (267, now())
    ON CONFLICT (version) DO NOTHING;
