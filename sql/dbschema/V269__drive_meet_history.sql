-- V269__drive_meet_history.sql — the MEET Drive-History emitter's receipt
-- ledger (the named M4/M1 follow-up: "Drive History events" — the M1
-- rendition history-facts emitter, attached at the linkage point
-- mailserver/internal/meet/DOX.md documents).
--
-- The authority shape (the Drive lane's own prescription):
--   · Drive History stays the SOLE timeline owner. The only Drive-side
--     history surfaces are `drive_audit_log` (V114 §9.3 — the per-space
--     TAMPER-EVIDENT CHAIN, checksum in after_state, maintained exclusively
--     by Drive's own reducers) and the `drive_changes` feed. A meet-side
--     writer appending into Drive's chain would be exactly the
--     second-coordinator move the MEET plan forbids.
--   · The emitter is therefore a DRIVE-side reducer (reducers/
--     drive_meet_history_emit.sql): the one ingest that turns meet semantic
--     facts into drive_audit_log entries THROUGH drive_access_audit — the
--     owning chain writer — and records its receipt HERE. Meet contributes
--     ordered human events (the meet worker leg calls the ingest at the
--     three frozen lifecycle points: package stopped, annotation committed,
--     presentation pinned); it never touches Drive tables directly.
--   · Observational only: no meet state machine reads this table, no M0–M4
--     behavior changes, no bulk backfill (the worker leg converges committed
--     facts forward; it is the sweepSemanticPackages drain genre, not a
--     historical migration).
--
-- §A drive_meet_history_events — the idempotent emit receipt: ONE row per
--     meet fact (UNIQUE (source_kind, source_id) — the belt that makes a
--     retried emit re-enter the same receipt instead of minting a second
--     chain entry). `state='emitted'` rows carry the exact chain attachment
--     (space/node/version + the per-space drive_audit_log id); `state=
--     'absent'` rows record the truthful no-home answer for a fact with no
--     Drive attachment (a stopped recording whose package never exported —
--     nothing to attach a history entry to), so the worker leg converges
--     instead of retrying forever. Meet identity columns (meeting_id,
--     recording_id) are plain bigints, deliberately NOT foreign keys: this
--     is observational metadata about a meet fact, and Drive's schema does
--     not take relational authority over meet tables (the drive_node_id
--     columns in meeting_semantic_exports set the same precedent).
--
-- §B FORCE RLS (R4): the drive_audit_log posture verbatim — member-scoped
--     read backstop through drive_member_role, plus the drive.view admin
--     arm; NO write policies (the SECURITY DEFINER ingest is the only
--     writer; like drive_audit_log this ledger is append-only from the
--     app plane's perspective). Fail-closed: no GUC ⇒ NULL ⇒ no arm is
--     true; 'absent' rows (space_id NULL) are invisible to every policy —
--     internal bookkeeping, never exposed.
--
-- Feature flag: NONE seeded here (the V266 posture): the emitter adds no
-- route and no user-visible behavior of its own — entries surface through
-- the EXISTING drive_file_history_query read model (the audit source),
-- which carries its own gating.

-- ════════════════════════════════════════════════════════════════════════
-- §A — the emit receipt ledger.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.drive_meet_history_events (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The closed source-kind catalog — exactly the three lifecycle points
    -- the emitter contracts freeze. The audit action is derived per kind by
    -- the ingest (meet.<kind>), never request-owned (R2).
    source_kind      text   NOT NULL CHECK (source_kind IN
                     ('recording.stopped','annotation.committed','presentation.pinned')),
    -- The meet fact's own id (recording / annotation / presentation row).
    source_id        bigint NOT NULL,
    state            text   NOT NULL DEFAULT 'emitted' CHECK (state IN ('emitted','absent')),
    -- The chain attachment (emitted rows only — see the pairing CHECK).
    space_id         bigint REFERENCES public.drive_spaces(id),
    drive_node_id    bigint REFERENCES public.drive_nodes(id),
    drive_version_id bigint REFERENCES public.drive_file_versions(id),
    audit_id         bigint,
    audit_action     text,
    -- Observational meet metadata (plain ids, deliberately not FKs — see
    -- the header). recording_id is set exactly for recording.stopped.
    meeting_id       bigint NOT NULL,
    recording_id     bigint,
    actor_user_id    bigint,
    created_at       timestamptz NOT NULL DEFAULT now(),
    -- One receipt per meet fact: the idempotency root. A replayed emit
    -- re-enters this row; a second chain entry can never be minted for the
    -- same fact (the ingest serializes on it under its per-fact advisory
    -- lock, and drive_access_audit keeps the chain itself collision-free).
    CONSTRAINT drive_meet_history_events_fact_uq UNIQUE (source_kind, source_id),
    -- state/content pairing: an emitted receipt names its FULL chain
    -- attachment; an absent receipt carries none of it.
    CONSTRAINT drive_meet_history_events_state_chk CHECK (
        (state = 'emitted' AND space_id IS NOT NULL AND drive_node_id IS NOT NULL
            AND drive_version_id IS NOT NULL AND audit_id IS NOT NULL
            AND audit_action IS NOT NULL)
        OR (state = 'absent' AND space_id IS NULL AND drive_node_id IS NULL
            AND drive_version_id IS NULL AND audit_id IS NULL AND audit_action IS NULL)),
    -- recording.stopped receipts always name their recording.
    CONSTRAINT drive_meet_history_events_recording_chk CHECK (
        source_kind <> 'recording.stopped' OR recording_id IS NOT NULL)
);

CREATE INDEX drive_meet_history_events_space_idx
    ON public.drive_meet_history_events (space_id, created_at);

-- ════════════════════════════════════════════════════════════════════════
-- §B — FORCE RLS (R4): the drive_audit_log posture verbatim.
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.drive_meet_history_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_meet_history_events FORCE  ROW LEVEL SECURITY;

CREATE POLICY drive_meet_history_events_read ON public.drive_meet_history_events
  FOR SELECT TO public
  USING (public.drive_member_role(space_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR public.drive_has_admin_perm((SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.view'));
-- No INSERT/UPDATE/DELETE policies: the SECURITY DEFINER ingest
-- (drive_meet_history_emit, setjoin_worker-owned) is the ONLY writer; from
-- the app plane this ledger is append-only and invisible to write paths
-- (the drive_audit_log Task-3 posture).

INSERT INTO public.schema_migrations (version, applied_at) VALUES (269, now())
    ON CONFLICT (version) DO NOTHING;
