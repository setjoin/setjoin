-- federation_room_enqueue_member.sql — Pillar C2 Task 2: the ONE per-member
-- discipline home shared by every room fan-out (this task's control-op
-- fan-outs in federation_room_invite/federation_room_remove, and Task 3's
-- message fan-out, federation_room_fanout) — one choke, no drift between the
-- two loops.
--
-- LOCK-ORDER LAW PRECONDITION (enforced by callers, not here): the caller
-- MUST have already taken a sorted `FOR UPDATE ORDER BY member_domain`
-- snapshot of this room's `federation_room_members` rows (roster locks
-- FIRST, `federation_peers` locks — taken inside federation_enqueue below —
-- SECOND) before calling this function for any member in that room. This
-- function's own UPDATEs below re-touch a row the caller already holds
-- locked; it never independently acquires a NEW roster lock out of order.
--
-- Per-member disposition (Q9 split, ratified at the domain grill):
--   1. parked (backpressure) -> skip, return false. A parked member is not
--      re-tried per-send; it waits for an explicit re-invite (re-admit).
--   2. federation_peer_authorize(member, 'room') fails (BZ203, a per-send,
--      never-cached check — risk 5: the stream layer does not reflect
--      scope) -> REVOKE, never park (scope failure is not a capacity
--      problem): left_at/left_reason='revoked', an open 'revoked' coverage
--      epoch, an admin_audit_log act, and a best-effort DM-scoped
--      'application/x-setjoin-advisory' room_revoked frame to the very peer
--      being revoked (streams are floor-'dm' by design, Task 5's spoke
--      applier renders it read-only) — return false.
--   3. unacked outbox depth over federation.outbox_cap -> PARK
--      ('backpressure'), an open coverage epoch, an audit act -> false.
--   4. pre-cap warn: the enqueue crossing federation.outbox_warn_pct% of the
--      cap (DEFAULT 80) fires an admin-visible depth_warn act + notify
--      BEFORE the park lands — edge-triggered (fires exactly once at the
--      crossing; re-arms once acks drain the depth back below the
--      threshold, since the next call re-evaluates depth fresh).
--   5. otherwise: federation_enqueue (system frame, BZ205-exempt by
--      construction — no p_user_initiated arg) -> true.
--
-- A park/revoke here never aborts the caller's loop (RETURN false, never
-- RAISE) — the room stays alive for every other member, the Q9 disposition
-- of the C0 all-or-nothing fan-out problem.
CREATE OR REPLACE FUNCTION federation_room_enqueue_member(
    p_room_id      text,
    p_channel_id   bigint,
    p_member_domain text,
    p_stanza_id    text,
    p_content_type text,
    p_payload      jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_parked_at timestamptz;
  v_last_seq       bigint;
  v_last_acked_seq bigint;
  v_depth bigint;
  v_cap   bigint;
  v_warn_pct int;
  v_warn  bigint;
BEGIN
  SELECT parked_at INTO v_parked_at FROM federation_room_members
   WHERE room_id = p_room_id AND member_domain = p_member_domain AND left_at IS NULL;
  IF v_parked_at IS NOT NULL THEN
    RETURN false;
  END IF;

  BEGIN
    PERFORM federation_peer_authorize(p_member_domain, 'room');
  EXCEPTION WHEN SQLSTATE 'BZ203' THEN
    -- FOUND-guarded (Task 2 review finding): a concurrent remove/revoke
    -- already in progress on this exact member (left_at just got set by
    -- another transaction between our caller's snapshot and this UPDATE)
    -- must not still fire a spurious act + advisory naming an
    -- already-removed member — the left_at IS NULL guard makes the UPDATE
    -- itself a no-op in that race, so gate the side-effects on FOUND too.
    UPDATE federation_room_members
       SET left_at = now(), left_reason = 'revoked', parked_at = NULL, parked_reason = NULL,
           coverage_epochs = coverage_epochs || jsonb_build_object('parkedAt', now(), 'reason', 'revoked')
     WHERE room_id = p_room_id AND member_domain = p_member_domain AND left_at IS NULL;

    IF FOUND THEN
      PERFORM audit_write(NULL, 'federation.room_member_revoked', 'federation_room', NULL, NULL,
        jsonb_build_object('roomId', p_room_id, 'memberDomain', p_member_domain, 'reason', 'scope'),
        NULL, p_room_id, 'core');

      -- best-effort: a revoked peer stays dm-allow-listed and streams are
      -- floor-'dm', so this normally flows; if the peer's transport rows are
      -- already gone (a full federation_peer_delete mid-flight, not a mere
      -- downgrade), the revocation above must still commit regardless.
      BEGIN
        PERFORM federation_enqueue(p_member_domain, p_room_id || ':room_revoked:' || gen_random_uuid()::text,
          'application/x-setjoin-advisory',
          jsonb_build_object('op', 'room_revoked', 'roomId', p_room_id, 'reason', 'scope'));
      EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'federation: room_revoked advisory to % for room % failed: %',
          p_member_domain, p_room_id, SQLERRM;
      END;

      PERFORM notify_chat_state(p_channel_id, 'federation_roster');
    END IF;
    RETURN false;
  END;

  SELECT last_seq, last_acked_seq INTO v_last_seq, v_last_acked_seq
    FROM federation_peers WHERE peer_domain = p_member_domain;
  v_depth := COALESCE(v_last_seq, 0) - COALESCE(v_last_acked_seq, 0);
  v_cap   := COALESCE((SELECT value::int FROM system_config WHERE key = 'federation.outbox_cap'), 10000);

  IF v_depth > v_cap THEN
    -- FOUND-guarded (Task 2 review finding): a remove/revoke racing this
    -- exact member between the parked_at peek above and this UPDATE leaves
    -- left_at IS NULL false, so the UPDATE matches zero rows — without the
    -- FOUND guard the act + notify below would still fire, naming a member
    -- that is no longer in the roster at all.
    UPDATE federation_room_members
       SET parked_at = now(), parked_reason = 'backpressure',
           coverage_epochs = coverage_epochs || jsonb_build_object('parkedAt', now(), 'reason', 'backpressure')
     WHERE room_id = p_room_id AND member_domain = p_member_domain AND left_at IS NULL;

    IF FOUND THEN
      PERFORM audit_write(NULL, 'federation.room_member_parked', 'federation_room', NULL, NULL,
        jsonb_build_object('roomId', p_room_id, 'memberDomain', p_member_domain, 'reason', 'backpressure'),
        NULL, p_room_id, 'core');
      PERFORM notify_chat_state(p_channel_id, 'federation_roster');
    END IF;
    RETURN false;
  END IF;

  -- pre-cap warn (Q9): edge-triggered on THIS enqueue crossing the
  -- threshold — v_depth is the depth BEFORE this send; v_depth+1 is the
  -- depth this send will produce (federation_enqueue below bumps last_seq
  -- by exactly one). Fires once per crossing; a depth already at/above the
  -- threshold from a PRIOR call does not re-fire (v_depth < v_warn is
  -- false), and drains back below re-arm it naturally.
  v_warn_pct := COALESCE((SELECT value::int FROM system_config WHERE key = 'federation.outbox_warn_pct'), 80);
  v_warn := v_cap * v_warn_pct / 100;
  IF v_depth < v_warn AND v_depth + 1 >= v_warn THEN
    PERFORM audit_write(NULL, 'federation.room_member_depth_warn', 'federation_room', NULL, NULL,
      jsonb_build_object('roomId', p_room_id, 'memberDomain', p_member_domain,
                          'depth', v_depth + 1, 'cap', v_cap),
      NULL, p_room_id, 'core');
    PERFORM notify_chat_state(p_channel_id, 'federation_roster');
  END IF;

  PERFORM federation_enqueue(p_member_domain, p_stanza_id, p_content_type, p_payload);
  RETURN true;
END;
$$;
SELECT apply_worker_ownership('federation_room_enqueue_member(text,bigint,text,text,text,jsonb)'::regprocedure);
