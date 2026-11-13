-- V268__meet_local_capture.sql — MEET plan M5 slice 2: the Electron
-- local-first capture lease + truthful local-package registration
-- (docs/superpowers/plans/2026-08-25-meet-document-presentation-semantic-
-- recording.md, M5), over the frozen contracts in
-- mailserver/internal/meet/presentation/ (acquisition.go's CaptureLease —
-- "the short-lived, reducer-issued authority a capture runs under" whose
-- lifecycle reducers own its truth — policy.go's
-- InvariantLeaseAfterReducerCommit + FailCaptureLeaseExpired, segment.go's
-- segment binding contract) and the slice-1 client substrate in
-- clients/desktop/electron/src/meet/ (the sjrec-local-v1 descriptor,
-- meet-local-heartbeat-v1 frames, the non-dismissible consent machine).
--
-- §A meeting_local_capture_leases — the capture lease: ONE live lease per
--     (meeting, device). Every lease binds the live local_registered
--     meeting_semantic_recordings row it captures under (the
--     reducer-commit-before-capture invariant: the recording row + banner
--     commit BEFORE the lease exists), the version-pinned producer
--     identity, the captured surfaces, and the heartbeat cadence the
--     client proposed (the server may tighten it, never loosen the local
--     stall stop). Lifecycle: live → stopped (user_stop | revoked |
--     meeting_ended | device_stopped | recording_ended) | expired.
--     Revocation/meeting-end stop and expiry are reducer-owned facts; a
--     lease never outlives its recording and a recording never outlives
--     its meeting (the meeting_end same-txn arm).
-- §B meeting_semantic_recordings gains the truthful local-registration
--     receipt columns: the sealed descriptor's integrity digest (sha256)
--     and registered_at. Registration stores the receipt — never a claim
--     of centrally retained bytes (local_only rows export nothing, BZ281).
-- §C FORCE RLS on the lease table (R4), the V266 §E posture verbatim:
--     participant-scoped read/update backstops through the
--     SECURITY DEFINER helpers, reducer-admitting insert backstop,
--     fail-closed with no GUC.
--
-- Feature flag: NONE seeded here. `feature.meet_local_recording` already
-- exists DEFAULT OFF in the V264 registry projection; the HTTP surface
-- (internal/meet/localcapture.go) 404s while it is OFF and the Electron
-- substrate ships inert (rollout mode 'off'), so rows exist only through
-- the reducers.

-- ════════════════════════════════════════════════════════════════════════
-- §A — the capture lease (one live lease per (meeting, device)).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE public.meeting_local_capture_leases (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id   bigint NOT NULL REFERENCES public.meetings(id),
    recording_id bigint NOT NULL REFERENCES public.meeting_semantic_recordings(id),
    -- Client-stable capture-device identity (e.g. install/hostname label).
    -- NOT an ownership credential: ownership is p_user_id/auth context (R2);
    -- this key only scopes the one-live-lease-per-(meeting, device) rule.
    device_id    text   NOT NULL CHECK (length(device_id) BETWEEN 1 AND 256),
    lease_state  text   NOT NULL DEFAULT 'live' CHECK (lease_state IN
                 ('live','stopped','expired')),
    -- Fencing generation: re-acquire after a stop mints generation N+1, so
    -- a stale heartbeat from the previous capture fails closed (BZ282).
    generation   bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
    -- Surfaces actually captured (the preflight's CaptureSurfaceId set:
    -- microphone / systemAudio). Non-empty by contract (a capture captures
    -- something) and never a video surface (B2 MP4 keeps that role).
    surfaces     jsonb  NOT NULL CHECK (jsonb_typeof(surfaces) = 'array'
                 AND jsonb_array_length(surfaces) BETWEEN 1 AND 2),
    -- The version-pinned producer identity the capture runs under (the
    -- 2026-09-06 composition amendment: a platform/provider version change
    -- re-qualifies the capture profile — recorded here, never mutated).
    producer     jsonb  NOT NULL CHECK (jsonb_typeof(producer) = 'object'),
    -- The heartbeat cadence the client proposed, server-clamped at acquire
    -- (5..60s). TTL = 3 × cadence: three full missed slots and the lease is
    -- dead server-side — never looser than the client's own stall stop.
    heartbeat_seconds integer NOT NULL CHECK (heartbeat_seconds BETWEEN 5 AND 60),
    expires_at   timestamptz NOT NULL,
    last_seq     bigint CHECK (last_seq IS NULL OR last_seq >= 1),
    last_seen_at timestamptz,
    last_disk_free_bytes bigint,
    stop_reason  text CHECK (stop_reason IN
                 ('user_stop','revoked','meeting_ended','device_stopped','recording_ended')),
    started_by   bigint NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    stopped_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    -- Truthful stop shape: a terminal lease names WHY and WHEN it stopped;
    -- a live lease carries no stop claim.
    CONSTRAINT meeting_local_capture_leases_stopped_chk CHECK (
        (lease_state = 'live') = (stop_reason IS NULL AND stopped_at IS NULL)),
    -- The lease cannot outlive its recording's active window by more than
    -- bookkeeping: an active recording's lease is live, a stopped/expired
    -- recording's lease is terminal (the stop arms keep both in step).
    CONSTRAINT meeting_local_capture_leases_last_seen_chk CHECK (
        last_seen_at IS NULL OR last_seen_at >= started_at)
);

-- One LIVE lease per (meeting, device) — the plan's uniqueness shape. A
-- second device cannot hold a second lease for the same meeting because the
-- underlying recording start refuses a second live recording (BZ278
-- single-primary-mode); this index is the belt.
CREATE UNIQUE INDEX meeting_local_capture_leases_live_uq
    ON public.meeting_local_capture_leases (meeting_id, device_id)
    WHERE lease_state = 'live';
-- One live lease per recording — the lease IS that recording's capture
-- authority; re-acquire after a stop is a new generation, never a twin.
CREATE UNIQUE INDEX meeting_local_capture_leases_recording_live_uq
    ON public.meeting_local_capture_leases (recording_id)
    WHERE lease_state = 'live';
CREATE INDEX meeting_local_capture_leases_recording_idx
    ON public.meeting_local_capture_leases (recording_id, generation);
CREATE INDEX meeting_local_capture_leases_live_expiry_idx
    ON public.meeting_local_capture_leases (expires_at)
    WHERE lease_state = 'live';

-- ════════════════════════════════════════════════════════════════════════
-- §B — the truthful local-registration receipt on the recording row.
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_semantic_recordings
    ADD COLUMN local_descriptor_digest text
        CHECK (local_descriptor_digest IS NULL OR local_descriptor_digest ~ '^[0-9a-f]{64}$'),
    ADD COLUMN registered_at timestamptz,
    ADD CONSTRAINT meeting_semantic_recordings_local_receipt_chk
        CHECK (registered_at IS NULL OR capture_mode = 'local_registered');

-- ════════════════════════════════════════════════════════════════════════
-- §C — FORCE RLS (R4), the V266 §E posture verbatim: participant-scoped
-- read/update backstops via the SECURITY DEFINER helpers, a
-- reducer-admitting insert backstop (started_by pinned to the GUC user +
-- host/cohost floor, exactly the acquire path), fail-closed with no GUC.
-- ════════════════════════════════════════════════════════════════════════
ALTER TABLE public.meeting_local_capture_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_local_capture_leases FORCE  ROW LEVEL SECURITY;
CREATE POLICY meeting_local_capture_leases_read ON public.meeting_local_capture_leases FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY meeting_local_capture_leases_insert ON public.meeting_local_capture_leases FOR INSERT TO public
  WITH CHECK (started_by = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
     AND meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('host', 'cohost'));
CREATE POLICY meeting_local_capture_leases_update ON public.meeting_local_capture_leases FOR UPDATE TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL)
  WITH CHECK (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (268, now())
    ON CONFLICT (version) DO NOTHING;
