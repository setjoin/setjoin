-- federation_reap.sql — Pillar C2 Task 8 Step 3: the federation_inbox/
-- federation_outbox residue reaper (seam map risk 7, multiplied by room
-- fan-out — both tables grow forever today).
--
-- Safe by protocol: the sender never legally resends below last_acked_seq,
-- and an applied inbox row can never legally be replayed below the peer's
-- cursor either — federation_inbox's PK-EXISTS dup check makes an OLD seq a
-- 'dup' today. Inbox rows are envelope-only for the chat/room content types
-- C1/C2 dispatch into chat_messages — but federation_apply_inbound (the C0
-- generic entry point, still the ONLY writer) stores p_payload VERBATIM for
-- any content_type, so an unknown/未来 type sits in federation_inbox as its
-- own copy until a funnel lands to move it elsewhere; nothing
-- compliance-bearing is destroyed here for the dispatched types, but that
-- caveat does not yet cover every content_type.
--
-- The cursor-regression guard (Task 8 Step 2) is what makes this reap SAFE:
-- `IF p_peer_seq <= v_last THEN RETURN 'dup'/false; END IF;`, immediately
-- after reading v_last under the cursor row lock in all three appliers
-- (federation_apply_chat.sql / federation_apply_room.sql /
-- federation_apply_inbound.sql) — a replayed/malicious seq at-or-below the
-- cursor dups instead of falling through the (now reap-thinned) PK-EXISTS
-- check and moving the cursor backward. The cursor, not federation_inbox's
-- row presence, is the arbiter of "already applied" — the reaper deletes
-- rows freely because that arbiter never depended on them staying around.
--
-- Service leg: a 1-hour ticker (internal/federation/reap.go's ReapWorker,
-- wired in cmd/mailserverd/main.go) calls this UNCONDITIONALLY — the D11
-- unconditional-drain posture: residue reaps even while feature.federation
-- is OFF, the same posture as drive.NewWorker's chunk GC.
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership): federation_inbox/
-- federation_outbox are FORCE RLS deny-all-to-setjoin_app.
CREATE OR REPLACE FUNCTION federation_reap(p_keep interval DEFAULT '7 days') RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_inbox_n  int;
  v_outbox_n int;
  -- ponytail: one bounded pass per tick, not a loop — the 1-hour ticker
  -- (internal/federation/reap.go) absorbs any backlog over successive
  -- ticks; raise this ceiling if a single org's residue routinely exceeds
  -- it between ticks.
  c_batch    CONSTANT int := 5000;
BEGIN
  WITH victims AS (
    SELECT ctid FROM federation_inbox WHERE applied_at < now() - p_keep LIMIT c_batch
  ), gone AS (
    DELETE FROM federation_inbox WHERE ctid IN (SELECT ctid FROM victims) RETURNING 1
  )
  SELECT count(*)::int INTO v_inbox_n FROM gone;

  WITH victims AS (
    SELECT ctid FROM federation_outbox
     WHERE acked_at IS NOT NULL AND acked_at < now() - p_keep LIMIT c_batch
  ), gone AS (
    DELETE FROM federation_outbox WHERE ctid IN (SELECT ctid FROM victims) RETURNING 1
  )
  SELECT count(*)::int INTO v_outbox_n FROM gone;

  RETURN jsonb_build_object('inboxReaped', v_inbox_n, 'outboxReaped', v_outbox_n);
END;
$$;
SELECT apply_worker_ownership('federation_reap(interval)'::regprocedure);
