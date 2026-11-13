-- federation_room_create.sql — Pillar C2 Task 2: the hub-side room binder.
-- The ONLY place a `chat_channels` row becomes the HUB shape of a federated
-- room (`federated_room_id` set, `federated_peer_domain` NULL — the spoke
-- mirror shape is created ONLY by Task 5's `federation_apply_room` op
-- 'invite' branch, never here).
--
-- SECURITY DEFINER, worker-owned — the deny-all-writer precedent is
-- `federation_dm_ensure`/`federation_enqueue` (the C1 DEFINER reducers that
-- write `federation_*` tables; `chat_dm_open` is NOT the precedent, it
-- writes only chat tables): `federation_rooms` is FORCE RLS deny-all to
-- setjoin_app.
--
-- R1 proof first: `p_user_id` must be a member of `p_channel_id` at all
-- (BZ163 — the existing chat "not a channel member" code, chat_message_send/
-- chat_mark_read/chat_typing_signal's own raiser list, extended here) AND
-- specifically owner/admin (BZ209 — this reducer's own family, since "member
-- but wrong role" is a bind-eligibility fact, not the generic chat
-- not-a-member signal).
--
-- v_domain normalization: `lower(btrim(p_local_domain))` — the
-- `federation_peer_set` convention — BEFORE minting the roomId `@`-suffix
-- and storing `federation_rooms.hub_domain`. An un-normalized (e.g.
-- uppercase) config value would otherwise make Task 5's
-- `split_part(roomId,'@',2) = lower(p_peer_domain)` hijack guard FALSE-
-- refuse every invite this hub ever sends — the confirm review's
-- self-poison trap.
--
-- Refusals (BZ209, the bind-refusal family — channel not eligible to become
-- a federated room in its current shape/state): not kind='channel'; already
-- room-bound; archived; a federated-DM-shaped row (federated_local_key/
-- federated_remote_id/federated_peer_domain already set — mirrors
-- chat_channels_room_shape_ck's own conjuncts, defense in depth); an
-- org-default channel (Q14 arm 1 — an org-default channel federates every
-- employee's messages with no individual opt-out, refused deliberately
-- rather than by omission); empty p_local_domain (a reducer can't see
-- process config, so an empty value here is always a caller bug, refused
-- the same as any other bind-ineligibility). `classification='gxp'` gets
-- its OWN code, BZ210 (Q7 arm 1) — a WORM claim unenforceable on remote
-- copies would be a false compliance claim, worth its own signal.
CREATE OR REPLACE FUNCTION federation_room_create(
    p_user_id      bigint,
    p_channel_id   bigint,
    p_local_domain text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_role     text;
  v_domain   text;
  v_kind     text;
  v_room_id  text;
  v_fed_peer text;
  v_fed_local text;
  v_fed_remote text;
  v_archived boolean;
  v_classification text;
  v_new_room_id text;
BEGIN
  SELECT role INTO v_role FROM chat_channel_members
   WHERE channel_id = p_channel_id AND user_id = p_user_id;
  IF v_role IS NULL THEN
    RAISE EXCEPTION 'not a member of channel %', p_channel_id
      USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
  ELSIF v_role NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION 'owner/admin required to bind a federated room'
      USING ERRCODE='BZ209', HINT='{"type":"forbidden","detail":"owner/admin required"}';
  END IF;

  v_domain := lower(btrim(COALESCE(p_local_domain, '')));
  IF v_domain = '' THEN
    RAISE EXCEPTION 'federation: local domain is required to bind a room'
      USING ERRCODE='BZ209', HINT='{"type":"invalidArguments","detail":"local domain required"}';
  END IF;

  -- P12 arm 2 (BZ199 genre): lock the channel row so a concurrent
  -- chat_member_add cannot race this bind — arm 1 and arm 2 are checked
  -- under the SAME row lock.
  SELECT kind, federated_room_id, federated_peer_domain, federated_local_key,
         federated_remote_id, is_archived, classification
    INTO v_kind, v_room_id, v_fed_peer, v_fed_local, v_fed_remote, v_archived, v_classification
    FROM chat_channels WHERE id = p_channel_id FOR UPDATE;

  IF v_kind IS DISTINCT FROM 'channel' THEN
    RAISE EXCEPTION 'only a channel may be bound to a federated room'
      USING ERRCODE='BZ209', HINT='{"type":"invalidArguments","detail":"channel kind must be channel"}';
  END IF;
  IF v_room_id IS NOT NULL THEN
    RAISE EXCEPTION 'channel % is already bound to a federated room', p_channel_id
      USING ERRCODE='BZ209', HINT='{"type":"conflict","detail":"channel already room-bound"}';
  END IF;
  IF v_archived THEN
    RAISE EXCEPTION 'an archived channel cannot be bound to a federated room'
      USING ERRCODE='BZ209', HINT='{"type":"conflict","detail":"channel is archived"}';
  END IF;
  IF v_fed_local IS NOT NULL OR v_fed_remote IS NOT NULL OR v_fed_peer IS NOT NULL THEN
    RAISE EXCEPTION 'a federated-DM-shaped channel cannot be bound to a federated room'
      USING ERRCODE='BZ209', HINT='{"type":"invalidArguments","detail":"channel is federated-DM-shaped"}';
  END IF;
  IF EXISTS (SELECT 1 FROM org_default_channels WHERE channel_id = p_channel_id) THEN
    RAISE EXCEPTION 'an org-default channel cannot be bound to a federated room'
      USING ERRCODE='BZ209', HINT='{"type":"conflict","detail":"channel is an org-default channel"}';
  END IF;
  -- P12 arm 2 (BZ199 genre, under the SAME row lock as arm 1): a channel
  -- containing a guest account can never gain a federation binding — a
  -- guest's content must never leave the tenant via a federation peer
  -- (spec §4A residency promise).
  IF EXISTS (SELECT 1 FROM chat_channel_members m
              WHERE m.channel_id = p_channel_id AND is_guest_account(m.user_id)) THEN
    RAISE EXCEPTION 'a channel containing guest accounts cannot be bound to a federated room'
      USING ERRCODE='BZ216', HINT='{"type":"forbidden","detail":"guest members present; guests are excluded from federation (residency)"}';
  END IF;
  IF v_classification = 'gxp' THEN
    RAISE EXCEPTION 'a gxp-classified channel cannot be bound to a federated room'
      USING ERRCODE='BZ210', HINT='{"type":"conflict","detail":"channel classification is gxp"}';
  END IF;

  v_new_room_id := gen_random_uuid()::text || '@' || v_domain;

  INSERT INTO federation_rooms (room_id, hub_domain, channel_id)
    VALUES (v_new_room_id, v_domain, p_channel_id);
  UPDATE chat_channels SET federated_room_id = v_new_room_id WHERE id = p_channel_id;

  PERFORM audit_write(p_user_id, 'federation.room_create', 'federation_room', NULL, NULL,
    jsonb_build_object('roomId', v_new_room_id, 'channelId', p_channel_id),
    NULL, v_new_room_id, 'core');
  PERFORM notify_chat_state(p_channel_id, 'federation_roster');

  RETURN v_new_room_id;
END;
$$;
SELECT apply_worker_ownership('federation_room_create(bigint,bigint,text)'::regprocedure);
