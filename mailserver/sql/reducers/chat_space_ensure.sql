-- mailserver/sql/reducers/chat_space_ensure.sql
-- Chat A2 Task 2 — lazy org-governed Drive space per chat channel.
--
-- SECURITY DEFINER + worker-owned (apply_worker_ownership): the INSERT into
-- drive_spaces must NOT trip drive_spaces_insert's `owner_user_id = current
-- GUC` WITH CHECK at the native-RLS flip — chat_space_ensure runs the INSERT
-- as setjoin_worker regardless of who called it (plan Decision Audit #6).
-- Membership-gated (BZ163) BEFORE any drive work, same shape as
-- chat_message_send/chat_read/chat_roster.
--
-- NOT via drive_space_create: that reducer's G6 space-creation gate,
-- owner-is-caller assumption, and self-seed drive_space_members INSERT are
-- all wrong here — a chat-bound space's membership is DERIVED (drive_member_
-- role v2, V120); this reducer writes ZERO drive_space_members rows
-- (DES-009 D2).
--
-- Race-safe: two concurrent first-attachments on the same channel race on
-- the V120 partial UNIQUE index (drive_spaces_chat_channel_uq), not on a
-- lookup-then-insert TOCTOU — the loser's INSERT is a no-op (bare ON
-- CONFLICT DO NOTHING) and it re-selects the winner's row.
CREATE OR REPLACE FUNCTION chat_space_ensure(
  p_user_id bigint, p_channel_id bigint
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_space_id  bigint;
  v_kind      text;
  v_name      text;
  v_created_by bigint;
  v_class     text;
  v_ret       integer;
  v_worm      text;
BEGIN
  PERFORM chat_require_role(p_channel_id, p_user_id);

  -- already provisioned (the common case after the first attachment).
  SELECT id INTO v_space_id FROM drive_spaces WHERE chat_channel_id = p_channel_id;
  IF FOUND THEN
    RETURN v_space_id;
  END IF;

  -- Chat A4a Task 8: a gxp channel's Drive space is gxp FROM BIRTH (spec-delta
  -- 2/6) — no re-classification pass ever runs on it later. An EXISTING
  -- regular space bound to a channel upgraded to gxp AFTER its space already
  -- exists keeps classification='regular' (spec-delta 6); it stays protected
  -- via BZ175 (chat-referenced nodes cannot be trashed/moved/renamed/
  -- re-versioned) plus the retain_until high-water mark
  -- chat_channel_set_classification stamps on its chunks.
  SELECT kind, name, created_by, classification, retention_days, worm_mode
    INTO v_kind, v_name, v_created_by, v_class, v_ret, v_worm
    FROM chat_channels WHERE id = p_channel_id;

  -- dm/group_dm channels carry no name (V119) — derive one from the
  -- participants' display names for admin/eDiscovery legibility (DES-009
  -- D5); users never browse this space, so a comma-joined list is enough.
  IF v_kind IN ('dm', 'group_dm') THEN
    SELECT string_agg(u.display_name, ', ' ORDER BY u.display_name)
      INTO v_name
      FROM chat_channel_members m JOIN users u ON u.id = m.user_id
     WHERE m.channel_id = p_channel_id;
  END IF;
  v_name := left(btrim(COALESCE(v_name, 'DM ' || p_channel_id)), 200);
  IF v_name = '' THEN
    v_name := 'DM ' || p_channel_id;  -- the space-name CHECK is 1-200, never empty
  END IF;

  INSERT INTO drive_spaces (name, classification, owner_user_id, chat_channel_id,
                            retention_days, worm_mode, quota_bytes, export_policy)
  VALUES (v_name, v_class, v_created_by, p_channel_id,
          CASE WHEN v_class = 'gxp' THEN v_ret ELSE NULL END,
          CASE WHEN v_class = 'gxp' THEN v_worm ELSE NULL END,
          NULL,  -- unlimited server quota; per-channel admin knob is A3/A4
          -- ponytail: 100 MiB default per-upload cap so a chat-bound space is
          -- capped, not unlimited-and-invisible; an admin per-channel override
          -- UI is out of scope for A2 (plan's own scope fence).
          jsonb_build_object('upload_max_bytes', 104857600))
  ON CONFLICT (chat_channel_id) WHERE chat_channel_id IS NOT NULL DO NOTHING
  RETURNING id INTO v_space_id;

  IF v_space_id IS NULL THEN
    -- lost the race: another concurrent ensure() won it first.
    SELECT id INTO v_space_id FROM drive_spaces WHERE chat_channel_id = p_channel_id;
    RETURN v_space_id;
  END IF;

  PERFORM drive_access_audit(p_user_id, v_space_id, 'space.create', 'space', v_space_id, NULL,
    jsonb_build_object('name', v_name, 'classification', v_class, 'chatChannelId', p_channel_id),
    NULL, NULL);
  PERFORM drive_notify_change(v_space_id, 0, 'space');  -- node_id 0 sentinel (R3), drive_space_create parity
  RETURN v_space_id;
END;
$$;
SELECT apply_worker_ownership('chat_space_ensure(bigint,bigint)'::regprocedure);
