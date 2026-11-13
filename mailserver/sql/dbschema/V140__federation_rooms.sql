-- V140__federation_rooms.sql — Pillar C2 Task 1: room binding, roster
-- promotion, and THE DEDUP FIX (the stanza-dedup cross-org collision, seam
-- map risk 1 — bravo's msg 42 and charlie's msg 42 silently colliding in one
-- channel). Read docs/superpowers/plans/archive/2026-07-17-pillar-C2-rooms-presence-
-- federation.md's "Rooms, roster, and the relay trust contract" section
-- before touching this file.
--
-- No new toggle (rides feature.federation, V138, seeded OFF).

-- ── chat_channels: room binding + kicked-mirror marker ─────────────────────
ALTER TABLE public.chat_channels
    ADD COLUMN federated_room_id         text NULL,
    ADD COLUMN federated_room_removed_at timestamptz NULL;
CREATE UNIQUE INDEX chat_channels_federated_room_uk ON public.chat_channels
    (federated_room_id) WHERE federated_room_id IS NOT NULL;      -- one mirror per room per org
ALTER TABLE public.chat_channels
    ADD CONSTRAINT chat_channels_room_shape_ck CHECK (
        federated_room_id IS NULL
        OR (kind = 'channel' AND federated_local_key IS NULL AND federated_remote_id IS NULL)),
    ADD CONSTRAINT chat_channels_room_removed_ck CHECK (
        federated_room_removed_at IS NULL OR federated_room_id IS NOT NULL);

-- federation_rooms: bind to the local channel (hub: the real channel; spoke: the mirror)
ALTER TABLE public.federation_rooms
    ADD COLUMN channel_id bigint NULL UNIQUE REFERENCES public.chat_channels(id) ON DELETE SET NULL;

-- federation_room_members: roster promotion (domain-level, Q4; Q9 split posture)
-- parked_reason carries ONLY 'backpressure' — scope failure is not a park, it
-- is visible REVOCATION (left_at + left_reason='revoked', the ratified Q9 split).
-- coverage_epochs: append-only [{parkedAt, resumedAt, reason}] gap history
-- (reason 'backpressure'|'revoked'|'removed'; resumedAt absent while the gap is open) —
-- feeds the Task 8 manifest coverage facts + the Task 5 re-admit gap marker.
ALTER TABLE public.federation_room_members
    ADD COLUMN invited_at      timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN parked_at       timestamptz NULL,
    ADD COLUMN parked_reason   text NULL CHECK (parked_reason IN ('backpressure')),
    ADD COLUMN left_at         timestamptz NULL,
    ADD COLUMN left_reason     text NULL CHECK (left_reason IN ('removed','revoked')),
    ADD COLUMN coverage_epochs jsonb NOT NULL DEFAULT '[]';
ALTER TABLE public.federation_room_members
    ADD CONSTRAINT federation_room_members_left_ck CHECK (left_reason IS NULL OR left_at IS NOT NULL);

-- msg_type 'system': the LOCAL federation gap marker (Q9 coverage epochs) —
-- applier-inserted only; chat_message_send REFUSES it as user input (Task 3).
-- The V125/V130 widening precedent.
ALTER TABLE public.chat_messages DROP CONSTRAINT chat_messages_msg_type_check;
ALTER TABLE public.chat_messages ADD CONSTRAINT chat_messages_msg_type_check
  CHECK (msg_type IN ('text', 'voice', 'poll', 'call', 'question', 'system'));

-- THE DEDUP FIX (order matters: column -> NO FORCE -> backfill -> FORCE -> CHECK -> re-scope index)
--
-- RLS TRAP (do not "simplify" this away): chat_messages + chat_channels are
-- FORCE RLS (V119) with policies keyed on app.current_user_id, and the
-- PRODUCTION runner is `mailctl schema apply` over DB_OWNER_DSN —
-- setjoin_owner is NOBYPASSRLS (provision-roles.sql), so FORCE constrains the
-- owner too. Without the NO FORCE window below, the backfill UPDATE matches
-- ZERO rows, and the ADD CONSTRAINT that follows (constraint validation
-- bypasses RLS) then FAILS the whole migration on any DB carrying C1
-- federated-DM traffic. The test lane CANNOT catch this: load-test-schema.sh
-- applies as superuser (BYPASSRLS), where the naked UPDATE works fine. The
-- wrap is load-bearing despite green tests. Same-txn: NO FORCE never leaks
-- past this migration's transaction.
ALTER TABLE public.chat_messages ADD COLUMN federated_origin_domain text NULL;
ALTER TABLE public.chat_messages NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.chat_channels NO FORCE ROW LEVEL SECURITY;
UPDATE public.chat_messages m SET federated_origin_domain = c.federated_peer_domain
  FROM public.chat_channels c
 WHERE c.id = m.channel_id AND m.federated_stanza_id IS NOT NULL;
ALTER TABLE public.chat_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE public.chat_channels FORCE ROW LEVEL SECURITY;
ALTER TABLE public.chat_messages ADD CONSTRAINT chat_messages_fed_origin_ck
    CHECK (federated_stanza_id IS NULL OR federated_origin_domain IS NOT NULL);
DROP INDEX public.chat_messages_fed_stanza_uk;
CREATE UNIQUE INDEX chat_messages_fed_stanza_uk ON public.chat_messages
    (channel_id, federated_origin_domain, federated_stanza_id) WHERE federated_stanza_id IS NOT NULL;

-- Why the two-way link (chat_channels.federated_room_id AND
-- federation_rooms.channel_id) is not drift, it's the RLS split:
-- chat_message_send runs invoker-rights and can only see chat-RLS columns —
-- federated_room_id is its branch discriminator; federation_rooms is
-- FORCE-RLS deny-all, readable only by the DEFINER fan-out/applier.
-- federation_room_create (Task 2) writes both in one txn; the partial-UNIQUE
-- + the FK keep them 1:1.

INSERT INTO public.schema_migrations (version, applied_at) VALUES (140, now())
    ON CONFLICT (version) DO NOTHING;
