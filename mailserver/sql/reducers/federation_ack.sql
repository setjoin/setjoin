-- federation_ack.sql — Pillar C0 spike Task 2 (E2, THE crux): advances the
-- sender's confirmed-delivery cursor.
--
-- Called by internal/federation/sender.go on EVERY KindAck frame it reads
-- back from a peer — including the ack for a peer_seq the peer reports as a
-- duplicate (federation_apply_inbound returned applied=false). The transport
-- ack doubles as the spike's delivery receipt (the real XEP-0184 stanza-ID
-- mapping is a named C1 item — wire.go's KindReceipt doc comment).
--
-- Idempotent: acking the same peer_seq twice (a redundant/late ack arriving
-- after federation_peers.last_acked_seq already advanced past it) is a
-- harmless no-op via the WHERE guards below — never an error, never a
-- regression of last_acked_seq.
--
-- SECURITY DEFINER + apply_worker_ownership + pinned search_path, matching
-- federation_enqueue/federation_apply_inbound: federation_peers/
-- federation_outbox are FORCE RLS deny-all-to-setjoin_app.
--
-- Pillar C1 Task 6 — ack-as-receipt (XEP-0184-equivalent): the transport ack
-- ALREADY fires only after federation_apply_chat commits on the peer's end
-- (i.e. after the message is durably in the recipient org's chat) — so this
-- reducer is where a chat send's `delivered_at` gets set, no new stanza
-- kind needed. Fires ONLY on the acked_at IS NULL transition above (a
-- re-ack is a no-op — the UPDATE...RETURNING below simply finds no row and
-- FOUND stays false, so the whole receipt block skips).
--
-- The join from outbox row -> chat_messages is DOUBLE-scoped, both MANDATORY
-- (plan "Identity, keys, and the one poison-proof invariant" precedent):
--   (a) content_type = 'application/x-setjoin-chat' — a non-chat outbox
--       frame's stanza_id is never a chat_messages.id in the first place,
--       but this keeps the cast+join scoped to the one content_type that
--       ever means "stanza_id IS a chat_messages.id".
--   (b) the target chat_messages row's channel must have
--       chat_channels.federated_peer_domain = p_peer_domain — belt-and-
--       suspenders even though federation_outbox rows are already peer-
--       scoped by construction (federation_enqueue only ever writes
--       p_peer_domain's own rows): WITHOUT this scope, any future caller
--       or bug that lets stanza_id drift from "this peer's own enqueue"
--       would let a receipt for peer A silently stamp delivered_at on a
--       message that lives in a channel bound to a DIFFERENT peer — this
--       predicate is the one place that trust is pinned shut, not assumed.
--
-- seq re-stamp: chat_messages_since replays by seq (the chat_message.sql
-- send/edit/delete rail) — a change_seq bump WITHOUT re-stamping the row's
-- own seq leaves the delivered tick unreachable by that cursor and by
-- reconnect replay, visible only on a cold reload. So the receipt bumps the
-- channel's change_seq under its own row lock (the same rail, verbatim) and
-- re-stamps chat_messages.seq from it, then emits notify_chat_state so the
-- tick pushes live over the existing chat:{user_id} channel.
--
-- Pillar C2 Task 3 (Q10 — no delivered ticks in rooms, the Slack posture):
-- the `v_content_type = 'application/x-setjoin-chat'` guard above already
-- excludes every room-content ack MECHANICALLY, not by a separate check —
-- room frames ride `content_type = 'application/x-setjoin-room'`, so they
-- can never enter the receipt block at all. This is deliberate, pinned by
-- federation_receipt.pg §4/§5, not an oversight to "fix" by widening the
-- content_type match.
--
-- ER6 residual rollup — belt-and-braces future-ack guard (the sender-side
-- guard is occ_642310eee5108ebbcdd9780a / sender.go applyAck, which refuses
-- p_peer_seq beyond its in-memory send cursor BEFORE the database is ever
-- reached; this reducer-side twin refuses it even if a future caller skips
-- that seam). An ack names a seq the peer DURABLY APPLIED, so it can never
-- legitimately name anything above the highest seq this side ever enqueued:
-- a future ack would mark unsent outbox rows acked (every later reconnect
-- resumes PAST them — silent message loss) and regress the ordered-rail
-- invariants, so it raises BZ202 — the federation family's existing
-- out-of-sequence-window code (federation_apply_inbound/chat/room gap guard;
-- ClassConflict → 409), reused rather than minting a new code. The window is
-- GREATEST(federation_peers.last_seq, max(federation_outbox.peer_seq)):
--   - last_seq is the enqueue rail's monotonic high-water mark (never
--     regresses), so it alone would suffice against forgery;
--   - max(outbox.peer_seq) additionally admits the
--     federation_receipt.pg §3 shape — a directly-seeded outbox row beyond
--     the rail (the "forged/buggy enqueue" fixture) is ackable, matching the
--     named `p_peer_seq ≤ max(outbox.peer_seq)` bound;
--   - GREATEST of the two keeps the header contract above intact that a
--     redundant/late ack is NEVER an error: federation_reap deletes acked
--     rows after 7 days, so a late duplicate ack of a reaped seq can sit
--     above max(outbox.peer_seq) while remaining at-or-below last_seq — and
--     every reaped row was acked (reap's WHERE acked_at IS NOT NULL), hence
--     at-or-below last_acked_seq, so admitting it is a provable no-op, while
--     refusing it would spuriously halt the sender's stream.
-- NULL/negative p_peer_seq are malformed for the same reason (they can name
-- no real frame) and raise identically. The RAISE unwinds the whole call:
-- a refused ack marks nothing and advances nothing.
CREATE OR REPLACE FUNCTION federation_ack(
    p_peer_domain text,
    p_peer_seq    bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_stanza_id    text;
  v_content_type text;
  v_message_id   bigint;
  v_channel_id   bigint;
  v_seq          bigint;
  v_ack_window   bigint;
BEGIN
  -- Belt-and-braces future-ack refusal (doc block above): the ack window is
  -- the durable high-water mark of seqs this side ever enqueued for the peer.
  SELECT GREATEST(
           COALESCE((SELECT last_seq FROM federation_peers
                      WHERE peer_domain = p_peer_domain), 0),
           COALESCE((SELECT MAX(peer_seq) FROM federation_outbox
                      WHERE peer_domain = p_peer_domain), 0)
         ) INTO v_ack_window;

  IF p_peer_seq IS NULL OR p_peer_seq < 0 OR p_peer_seq > v_ack_window THEN
    RAISE EXCEPTION 'federation: ack for peer % names seq % outside the enqueued window (0..%) — forged/future ack refused',
      p_peer_domain, p_peer_seq, v_ack_window
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"ack sequence outside the enqueued outbox window"}';
  END IF;

  UPDATE federation_outbox SET acked_at = now()
    WHERE peer_domain = p_peer_domain AND peer_seq = p_peer_seq AND acked_at IS NULL
    RETURNING stanza_id, content_type INTO v_stanza_id, v_content_type;

  UPDATE federation_peers SET last_acked_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain AND last_acked_seq < p_peer_seq;

  -- Receipt: only on the first (acked_at IS NULL -> acked) transition, and
  -- only for a chat-kind stanza whose id parses as a bigint (defensive —
  -- content_type already guarantees this in practice).
  IF FOUND AND v_content_type = 'application/x-setjoin-chat' THEN
    BEGIN
      v_message_id := v_stanza_id::bigint;
    EXCEPTION WHEN invalid_text_representation THEN
      v_message_id := NULL;
    END;

    IF v_message_id IS NOT NULL THEN
      SELECT m.channel_id INTO v_channel_id
        FROM chat_messages m
        JOIN chat_channels c ON c.id = m.channel_id
       WHERE m.id = v_message_id
         AND c.federated_peer_domain = p_peer_domain;

      IF v_channel_id IS NOT NULL THEN
        UPDATE chat_channels SET change_seq = change_seq + 1
          WHERE id = v_channel_id RETURNING change_seq INTO v_seq;

        UPDATE chat_messages SET seq = v_seq, delivered_at = now()
          WHERE id = v_message_id;

        PERFORM notify_chat_state(v_channel_id, 'message_delivered', v_message_id, v_seq);
      END IF;
    END IF;
  END IF;
END;
$$;
SELECT apply_worker_ownership('federation_ack(text,bigint)'::regprocedure);
