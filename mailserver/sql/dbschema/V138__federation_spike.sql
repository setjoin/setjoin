-- V138__federation_spike.sql — Pillar C0 cross-org federation de-risking
-- SPIKE (mailserver/internal/federation). BRANCH-ONLY: this migration lives
-- on pillar-c0-federation-spike and does NOT merge to main as part of C0
-- (Global Constraints / Task 6 — renumber at promotion if main advances).
--
-- Every table this migration adds is per-domain federation infrastructure,
-- not user data — there is no membership axis to scope, so the correct RLS
-- posture is the chat_audit_log/chat_link_previews shape: FORCE RLS + ZERO
-- policies (deny-all to setjoin_app), reducer/worker-only writes. This is a
-- disposition, not a gap: recording it here IS the ARCH-018 scope-helper
-- matrix review outcome for this table family (Global Constraints).

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.federation', false,
   'Cross-org setjoin<->setjoin s2s federation (Pillar C0 spike). Seeded OFF — Dial/Listen (and the per-peer sender drain, Task 2) each no-op while off (D11).')
ON CONFLICT (key) DO NOTHING;

-- federation_allowlist (Task 1, E1): the bilateral, default-OFF, mutual
-- opt-in trust list (Global Constraints — Teams model). peer_anchor pins the
-- peer's trust root at allow-listing time — a PEM-encoded CA certificate in
-- this spike (gen-certs.sh's one-CA-per-domain shape; a leaf SPKI pin is a
-- named C1 alternative, not built here) — exchanged human-to-human, never
-- auto-trusted and never derived from the wire itself. Task 1's Dial/Listen
-- anchor validation (stream.go) reads this row; Task 3 (E4) adds the
-- scope/enabled/rate columns + the federation_peer_authorize SECURITY
-- DEFINER writer that actually gates the handshake on `enabled` — this
-- migration only carries the shape Task 1 needs to exist against.
--
-- No user axis — FORCE RLS + ZERO policies (deny-all), the chat_audit_log
-- precedent. Every read in Task 1 goes through an injected AnchorLookup
-- (production impl on DB_WORKER_DSN/BYPASSRLS, landing alongside Task 3's
-- writer); the table itself grants nothing to setjoin_app.
CREATE TABLE public.federation_allowlist (
    peer_domain  text        PRIMARY KEY,
    peer_anchor  text        NOT NULL,   -- PEM CA cert (or a leaf SPKI pin, C1 alternative)
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.federation_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_allowlist FORCE  ROW LEVEL SECURITY;
-- federation_allowlist: ZERO policies (deny-all to setjoin_app) — same shape
-- as chat_link_previews/chat_audit_log (V122/V126). Task 3 (E4) adds the
-- federation_peer_authorize SECURITY DEFINER writer + scope/enabled/rate
-- columns; denial pgTAP lands with that writer (scripts/rls-denial-allowlist.txt
-- carries this table as PENDING until then).

-- ─────────────────────────────────────────────────────────────────────────
-- Task 2 (E2, THE crux): the per-peer commit-ordered outbox/inbox rail.
--
-- All four tables below are per-domain federation transport infrastructure,
-- same as federation_allowlist above — no user/membership axis, so the
-- correct RLS posture (Global Constraints, ARCH-018 matrix review outcome
-- for this family) is: FORCE RLS + ZERO policies (deny-all to setjoin_app),
-- reducer/worker-only writes. Recording that disposition here IS the matrix
-- review — no scope helper — no membership axis — deny-all app,
-- worker/reducer writes.
-- ─────────────────────────────────────────────────────────────────────────

-- federation_peers: per-outbound-peer sequencing state. last_seq is the
-- OUTBOUND cursor high-water mark — the last peer_seq assigned to THIS
-- peer's outbox, bumped under this row's own lock inside federation_enqueue
-- (UPDATE ... RETURNING, the chat_message.sql change_seq rail — NOT a
-- bigserial: a bigserial's nextval() is non-transactional and burns a value
-- on rollback, producing a permanent gap the receiver can never fill).
-- last_acked_seq is the peer-confirmed delivery high-water mark, advanced by
-- federation_ack — the sender's resume point after a crash/reconnect
-- (Hello.ResumeFromSeq in wire.go).
CREATE TABLE public.federation_peers (
    peer_domain     text        PRIMARY KEY,
    last_seq        bigint      NOT NULL DEFAULT 0,
    last_acked_seq  bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.federation_peers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_peers FORCE  ROW LEVEL SECURITY;

-- federation_outbox: one row per outbound stanza, keyed by the gap-free
-- (peer_domain, peer_seq) assigned by federation_enqueue. acked_at is set by
-- federation_ack once the peer's transport ack (KindAck) arrives — the
-- spike's stand-in delivery receipt (XEP-0184 mapping is a named C1 item,
-- wire.go's KindReceipt doc comment).
CREATE TABLE public.federation_outbox (
    peer_domain   text        NOT NULL REFERENCES public.federation_peers(peer_domain),
    peer_seq      bigint      NOT NULL,
    stanza_id     text        NOT NULL,
    content_type  text        NOT NULL,
    payload       jsonb       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    acked_at      timestamptz,
    PRIMARY KEY (peer_domain, peer_seq)
);
-- sender.go's cursor drain reads exactly this shape: unacked rows for one
-- peer, in seq order.
CREATE INDEX federation_outbox_unacked_idx
    ON public.federation_outbox (peer_domain, peer_seq) WHERE acked_at IS NULL;
ALTER TABLE public.federation_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_outbox FORCE  ROW LEVEL SECURITY;

-- federation_inbox_cursor: per-inbound-peer sequencing state — the INBOUND
-- direction's independent sequence space (each side of a stream assigns its
-- own peer_seq for what IT sends; the inbound cursor here tracks what THIS
-- side has applied from the PEER's outbox, unrelated to federation_peers'
-- outbound last_seq/last_acked_seq above).
CREATE TABLE public.federation_inbox_cursor (
    peer_domain      text        PRIMARY KEY,
    last_applied_seq bigint      NOT NULL DEFAULT 0,
    updated_at       timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.federation_inbox_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_inbox_cursor FORCE  ROW LEVEL SECURITY;

-- federation_inbox: the spike's apply target (NOT chat_messages — that would
-- need a channel + change_seq bump this spike doesn't provide; a C1 item).
-- Idempotent on (peer_domain, peer_seq): federation_apply_inbound's PK-EXISTS
-- check is what makes a duplicate apply a safe, ack-still-sent no-op.
CREATE TABLE public.federation_inbox (
    peer_domain   text        NOT NULL REFERENCES public.federation_inbox_cursor(peer_domain),
    peer_seq      bigint      NOT NULL,
    stanza_id     text        NOT NULL,
    content_type  text        NOT NULL,
    payload       jsonb       NOT NULL,
    applied_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (peer_domain, peer_seq)
);
ALTER TABLE public.federation_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_inbox FORCE  ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────────
-- Task 3 (E4): allow-list default-off + mutual opt-in + spam/rate at ingress.
--
-- scope/enabled turn federation_allowlist from "a row exists" (Task 1's
-- anchor-lookup shape) into "a row exists AND the LOCAL admin has explicitly
-- switched it on for a given traffic class" (Global Constraints: bilateral,
-- default-OFF, mutual opt-in, per-domain SCOPE). scope='room' is a superset
-- of 'dm' (a room-scoped peer may also DM) — federation_peer_authorize.sql is
-- the ONE place that superset rule is encoded.
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE public.federation_allowlist
    ADD COLUMN scope   text    NOT NULL DEFAULT 'dm' CHECK (scope IN ('dm','room')),
    ADD COLUMN enabled boolean NOT NULL DEFAULT false;

-- federation_ingress_counters: the per-peer-DOMAIN rate-limit shape, reusing
-- chat_send_counters' genre (V126 §H / chat_message.sql's per-minute window
-- counter) with a per-peer-domain key instead of per-user. Composite
-- (peer_domain, window_start) PK instead of chat's single-row-per-user
-- reset-on-stale-window upsert: a domain's count for a given minute window is
-- just one more row, ON CONFLICT DO UPDATE bumping msg_count — no "is this
-- still the current window" branch needed, the window IS the key.
-- No user axis (per-domain transport infrastructure, same posture as every
-- other federation_* table) — FORCE RLS + ZERO policies (deny-all).
CREATE TABLE public.federation_ingress_counters (
    peer_domain  text        NOT NULL,
    window_start timestamptz NOT NULL,
    msg_count    integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (peer_domain, window_start)
);
ALTER TABLE public.federation_ingress_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_ingress_counters FORCE  ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────────
-- Task 4 (E3): 3-org room — hub-per-room. The hub domain is the single
-- fan-out point for room traffic (Global Constraints: hub-per-room, not
-- P2P-room — the MUC-shaped model); non-hub members route room sends TO the
-- hub, never peer-to-peer. C0 does not runtime-enforce "this instance IS
-- room_id's hub" (no "local domain" concept exists at the SQL layer — each
-- fedharness daemon only knows its own domain via FEDHARNESS_DOMAIN, a Go-side
-- env var) — federation_room_fanout.sql is trusted to be invoked ONLY by
-- hub-side code. Naming this a C1 gap, not silently assuming it away: C1's
-- production wiring must self-check hub_domain against the local instance's
-- own configured domain before calling it.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE public.federation_rooms (
    room_id     text        PRIMARY KEY,
    hub_domain  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.federation_rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_rooms FORCE  ROW LEVEL SECURITY;

CREATE TABLE public.federation_room_members (
    room_id       text NOT NULL REFERENCES public.federation_rooms(room_id),
    member_domain text NOT NULL,
    PRIMARY KEY (room_id, member_domain)
);
ALTER TABLE public.federation_room_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.federation_room_members FORCE  ROW LEVEL SECURITY;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (138, now()) ON CONFLICT DO NOTHING;
