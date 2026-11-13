-- federation_apply_room.sql — Pillar C2 Task 4 (message op) + Task 5
-- (control-op arms): the inbound room<->federation bridge.
-- federation_apply_chat's SIBLING — SAME exactly-once/poison contract, but a
-- RELAY trust contract (Q2: the hub may assert origin for roster members —
-- the MUC/Slack-Connect posture) instead of a flat 1:1 anti-spoof. Runs on
-- the worker/BYPASSRLS pool, called by internal/federation/receiver.go's
-- handleRoom for every inbound KindMsg frame whose content_type is
-- 'application/x-setjoin-room' OR 'application/x-setjoin-advisory'.
--
-- ── THE POISON-PROOF INVARIANT (federation_apply_chat.sql's header,
--    verbatim law here too) ──
--
-- Step 1 (exactly-once/in-order bookkeeping) is COPIED, not reinvented,
-- from federation_apply_chat: dedup on (peer_domain, peer_seq), BZ202 on a
-- gap — the ONLY RAISE in this whole function — cursor advance under the
-- row lock, ALL of it BEFORE a single byte of p_payload is interpreted.
-- Every trust/scope/shape failure from Step 2 onward returns 'poison'
-- through the ordinary function-return path — never an exception — because
-- the seq/cursor are already committed-in-this-txn by the time any content
-- check runs; escalating to RAISE EXCEPTION there would unwind THAT too,
-- and the sender would resend the identical poisoned frame forever (the
-- exact livelock federation_apply_chat's header explains). This law binds
-- Task 5's control-op arms below exactly as hard as Task 4's message arm:
-- every guard is a poison-shaped RETURN, and (the invite arm's own rule)
-- every guard runs BEFORE any write — a malformed/hijacking control frame
-- must leave ZERO side effects beyond the Step 1 bookkeeping.
--
-- ── op dispatch (Task 4 'message' + Task 5 control ops) ──
--
-- 'message' (Task 4): the relay-trust content arm, unchanged below.
-- 'invite'/'remove'/'roster'/'room_revoked' (Task 5): the SPOKE-side
-- control-op arms — a channel that resolves HUB-shaped locally means a
-- peer is sending US control ops, which only a hub may originate, so every
-- non-invite control op first re-proves "this room already resolves
-- spoke-shaped here, bound to the stream peer as hub" before doing
-- anything else. 'invite' is the one exception (it is the mirror
-- CONSTRUCTOR — there may be no local row yet) and carries its OWN
-- structural/hub-binding guards instead (below). Any other op value is
-- still a poison stub.
--
-- ── the relay trust contract (Q2, contract section) ──
--
-- HUB side (the bound channel's federated_peer_domain IS NULL): the stream
-- peer must be a non-left roster member (a REVOKED member is left — its
-- in-flight frames poison here, unchanged poison discipline); C1 anti-spoof
-- holds VERBATIM (fromAddr's domain must equal the stream-authenticated
-- peer); origin is DERIVED from the stream peer, NEVER trusted from the
-- payload (a spoke never asserts its own origin — the hub is the one
-- authority for "who said this").
--
-- SPOKE side (federated_peer_domain IS NOT NULL — the mirror's bound hub):
-- the stream peer must EQUAL that bound hub (only the hub may relay into a
-- mirror); the mirror must not be kicked/closed (federated_room_removed_at
-- IS NULL); the payload's asserted originDomain is TRUSTED here — but ONLY
-- because it was already authenticated by SOME hub upstream, and only when
-- it names a roster member this spoke's own hub-maintained roster mirror
-- says is non-left, or the hub itself (the MUC posture: the hub asserts
-- origin for roster members, and the spoke trusts the HUB, not the payload
-- in isolation).
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership) — matching every
-- other federation_* reducer: federation_inbox/federation_inbox_cursor/
-- federation_rooms/federation_room_members are FORCE RLS deny-all, and this
-- call writes chat_channels/chat_messages/chat_channel_members on behalf of
-- a user who is NOT the invoking role (there is no "invoking user" here —
-- this runs off the wire).
--
-- p_spam_quarantined/p_spam_reason mirror federation_apply_chat's Task 4B
-- shape verbatim: the Go receiver runs the shared/spam TEXT-APPLICABLE
-- detectors on the decoded body BEFORE this call (a reducer can't call Go)
-- and hands the verdict in, landed on the SAME chat_messages INSERT the
-- valid-apply branch already does — quarantine is orthogonal to the
-- exactly-once/poison contract, never a skip and never a poison. DEFAULTed
-- so a poison/control-op stub call site never needs to pass them.
--
-- p_content_type (review fold, F3) carries the ACTUAL wire content_type
-- (roomContentType OR advisoryContentType — receiver.go's handleRoom
-- dispatches both here) into the federation_inbox envelope row, which
-- previously hardcoded 'application/x-setjoin-room' even for an advisory
-- frame. DEFAULTed to the room content type so every existing poison/
-- control-op-stub call site (including this whole file's own pgTAP suite,
-- which predates this parameter and calls the 6-arg form) keeps working
-- byte-for-byte. CREATE OR REPLACE cannot change an existing function's
-- parameter list — Postgres identifies a function by name+input-arg-types
-- — so a bare CREATE OR REPLACE here would silently leave the OLD 6-arg
-- federation_apply_room(text,bigint,text,jsonb,boolean,text) lingering as a
-- second overload instead of replacing it (the federation_apply_chat.sql/
-- federation_room_fanout.sql widening precedent). Drop it first.
DROP FUNCTION IF EXISTS federation_apply_room(text, bigint, text, jsonb, boolean, text);

CREATE OR REPLACE FUNCTION federation_apply_room(
    p_peer_domain       text,
    p_peer_seq          bigint,
    p_stanza_id         text,
    p_payload           jsonb,
    p_spam_quarantined  boolean DEFAULT false,
    p_spam_reason       text    DEFAULT NULL,
    p_content_type      text    DEFAULT 'application/x-setjoin-room'
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_last            bigint;
  v_op              text;
  v_room_id         text;
  v_from_raw        text;
  v_from_addr       text;
  v_body            text;
  v_client_msg_id   text;
  v_channel_id      bigint;
  v_room_hub_domain text;
  v_ch_peer_domain  text;
  v_ch_removed_at   timestamptz;
  v_origin          text;
  v_seq             bigint;
  v_msg_id          bigint;
  v_landed_now      boolean;
  v_relay_payload   jsonb;
  -- Task 5: control-op locals.
  v_existing_hub        text;
  v_existing_channel_id bigint;
  v_contact_raw         text;
  v_contact_addr        text;
  v_contact_user_id     bigint;
  v_title               text;
  v_roster              jsonb;
  v_roster_domains      text[];
  v_domain              text;
  v_state               text;
  v_gap_from            timestamptz;
  v_gap_to              timestamptz;
BEGIN
  -- ══════════════════════════════════════════════════════════════════════
  -- Step 1: exactly-once bookkeeping FIRST, verbatim from
  -- federation_apply_chat — before any content is even parsed.
  -- ══════════════════════════════════════════════════════════════════════
  IF EXISTS (
    SELECT 1 FROM federation_inbox
     WHERE peer_domain = p_peer_domain AND peer_seq = p_peer_seq
  ) THEN
    RETURN 'dup';
  END IF;

  INSERT INTO federation_inbox_cursor (peer_domain) VALUES (p_peer_domain)
    ON CONFLICT (peer_domain) DO NOTHING;

  SELECT last_applied_seq INTO v_last FROM federation_inbox_cursor
    WHERE peer_domain = p_peer_domain FOR UPDATE;

  -- Task 8 Step 2 (the cursor-regression guard) — verbatim from
  -- federation_apply_chat.sql, see that file for the full rationale: once
  -- federation_reap deletes an old federation_inbox row, the PK-EXISTS dup
  -- check above no longer catches a replay of that reaped seq; this guard
  -- closes it so the cursor can never move backward.
  IF p_peer_seq <= v_last THEN
    RETURN 'dup';
  END IF;

  IF p_peer_seq > v_last + 1 THEN
    RAISE EXCEPTION 'federation: sequence gap for peer % — got % expected %',
      p_peer_domain, p_peer_seq, v_last + 1
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"sequence gap — replay required"}';
  END IF;

  -- envelope-only inbox row — same rationale as federation_apply_chat: the
  -- body lives in chat_messages, this is a deny-all infra archive, never a
  -- second copy of user content.
  INSERT INTO federation_inbox (peer_domain, peer_seq, stanza_id, content_type, payload)
    VALUES (p_peer_domain, p_peer_seq, p_stanza_id, p_content_type,
            jsonb_build_object('op', p_payload->>'op',
                                'roomId', p_payload->>'roomId',
                                'originDomain', p_payload->>'originDomain',
                                'clientMsgId', p_payload->>'clientMsgId'));

  UPDATE federation_inbox_cursor SET last_applied_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain;

  -- (review fold, MINOR #4 — self-federation belt) a stream peer whose OWN
  -- domain is one of this org's own local domains can only mean a
  -- self-federation misconfiguration (this org allow-listed and is now
  -- receiving a stream FROM itself) — reuses the F2 predicate verbatim (the
  -- same "is this a local domain" check every other reducer uses:
  -- classify_focus.sql/deliver_group_vacation.sql/send.sql), placed once
  -- here so it protects every op (message AND every control op) rather than
  -- being duplicated per arm.
  IF EXISTS (SELECT 1 FROM domains WHERE lower(name) = lower(p_peer_domain) AND is_local) THEN
    RAISE NOTICE 'federation: poison — stream peer % is one of this org''s own local domains (self-federation misconfig)',
      p_peer_domain;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 2: op dispatch. Task 4 implements 'message'; Task 5 implements
  -- 'invite'/'remove'/'roster'/'room_revoked' (the spoke-side control-op
  -- arms) below. Any other op is still a poison stub — the seq/cursor
  -- above already committed this call exactly once either way.
  -- ══════════════════════════════════════════════════════════════════════
  v_op := p_payload->>'op';
  IF v_op NOT IN ('message', 'invite', 'remove', 'roster', 'room_revoked') THEN
    RAISE NOTICE 'federation: poison — unknown/unimplemented room op % from peer % seq %',
      v_op, p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 3: scope, per-payload (Q12 apply-side) — poison-shaped, NEVER a
  -- raise (risk 3). Runs for 'message' and the control ops 'invite'/
  -- 'remove'/'roster'. 'room_revoked' SKIPS this — the ONE deliberate skip
  -- (contract section): this org's room scope was just withdrawn, so the
  -- dm-floor advisory that EXPLAINS the revocation must still apply —
  -- running the authorize check here would poison the very frame telling
  -- the user why they're read-only. Keyed on the op, not the content type.
  -- ══════════════════════════════════════════════════════════════════════
  IF v_op <> 'room_revoked' THEN
    BEGIN
      PERFORM federation_peer_authorize(p_peer_domain, 'room');
    EXCEPTION WHEN SQLSTATE 'BZ203' THEN
      RAISE NOTICE 'federation: poison — peer % not authorized at scope room (seq %, op %)',
        p_peer_domain, p_peer_seq, v_op;
      RETURN 'poison';
    END;
  END IF;

  IF v_op = 'message' THEN
    -- ════════════════════════════════════════════════════════════════════
    -- Step 4 (message op): resolve + trust. From here on, every failure is
    -- 'poison'.
    -- ════════════════════════════════════════════════════════════════════
    v_room_id       := NULLIF(btrim(p_payload->>'roomId'), '');
    v_from_raw      := NULLIF(btrim(p_payload->>'fromAddr'), '');
    v_body          := p_payload->>'body';
    v_client_msg_id := NULLIF(btrim(p_payload->>'clientMsgId'), '');

    IF v_room_id IS NULL OR v_from_raw IS NULL OR v_body IS NULL OR v_client_msg_id IS NULL THEN
      RAISE NOTICE 'federation: poison — malformed room message payload from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    -- (review fold, F1) clientMsgId feeds chat_messages_fed_stanza_uk, a
    -- PARTIAL btree index on (channel_id, federated_origin_domain,
    -- federated_stanza_id) — an attacker-controlled value with no length cap
    -- can blow past Postgres's ~2.7KB btree index-row ceiling ("index row size
    -- exceeds btree maximum", SQLSTATE 54000). That failure is NOT a
    -- poison-shaped return: it fires deep inside the INSERT in Step 5, AFTER
    -- the seq/cursor advance in Step 1 already committed, so it aborts and
    -- unwinds that advance too — a permanent stream livelock (the sender
    -- resends the identical oversized frame forever). Capped well under the
    -- ceiling; poison, never a raise.
    IF octet_length(v_client_msg_id) > 512 THEN
      RAISE NOTICE 'federation: poison — clientMsgId over 512 octets (btree index ceiling) from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    -- fromAddr feeds federated_sender_addr — not itself index-bound today,
    -- but an unbounded attacker-controlled address is already nonsensical
    -- wire content; cap at the RFC address ceiling, poison-shaped, same
    -- defensive posture as the clientMsgId cap above.
    IF octet_length(v_from_raw) > 320 THEN
      RAISE NOTICE 'federation: poison — fromAddr over 320 octets (RFC address ceiling) from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    v_from_addr := lower(v_from_raw);

    -- THE ORDERING GUARANTEE (contract section): invite always precedes the
    -- first message an org should apply, so a message for a room this org
    -- holds no live mirror of is 'poison' (not invited / kicked / hub bug) —
    -- NEVER a blind mirror-ensure.
    SELECT channel_id, hub_domain INTO v_channel_id, v_room_hub_domain
      FROM federation_rooms WHERE room_id = v_room_id;

    IF v_channel_id IS NULL THEN
      RAISE NOTICE 'federation: poison — unknown/unbound room % from peer % seq %',
        v_room_id, p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    IF octet_length(v_body) > 65536 THEN
      RAISE NOTICE 'federation: poison — room body over 64KiB from peer % seq %',
        p_peer_domain, p_peer_seq;
      RETURN 'poison';
    END IF;

    SELECT federated_peer_domain, federated_room_removed_at
      INTO v_ch_peer_domain, v_ch_removed_at
      FROM chat_channels WHERE id = v_channel_id;

    IF v_ch_peer_domain IS NULL THEN
      -- ── HUB side ──────────────────────────────────────────────────────
      -- stream peer must be a non-left roster member of this room (a
      -- REVOKED member is left — its in-flight room frames poison here,
      -- unchanged poison discipline; the Q9 advisory means its users already
      -- saw read-only before they'd send).
      IF NOT EXISTS (
        SELECT 1 FROM federation_room_members
         WHERE room_id = v_room_id AND member_domain = lower(p_peer_domain) AND left_at IS NULL
      ) THEN
        RAISE NOTICE 'federation: poison — % is not a non-left roster member of room % (hub side)',
          p_peer_domain, v_room_id;
        RETURN 'poison';
      END IF;

      -- C1 anti-spoof VERBATIM: fromAddr's domain must equal the
      -- stream-authenticated peer. originDomain is NEVER trusted from the
      -- payload on the hub side — it is DERIVED from the stream peer (Q2).
      IF split_part(v_from_addr, '@', 2) <> lower(p_peer_domain) THEN
        RAISE NOTICE 'federation: poison — spoofed fromAddr domain (got %, stream peer %)',
          split_part(v_from_addr, '@', 2), p_peer_domain;
        RETURN 'poison';
      END IF;

      v_origin := lower(p_peer_domain);
    ELSE
      -- ── SPOKE side ────────────────────────────────────────────────────
      -- the stream peer must EQUAL the mirror's bound hub — only the true
      -- hub may relay into a mirror.
      IF v_ch_peer_domain <> lower(p_peer_domain) THEN
        RAISE NOTICE 'federation: poison — room frame from non-hub stream peer % (mirror bound to %)',
          p_peer_domain, v_ch_peer_domain;
        RETURN 'poison';
      END IF;

      -- a kicked/closed mirror is archive-read-only — stragglers drop (Q3).
      IF v_ch_removed_at IS NOT NULL THEN
        RAISE NOTICE 'federation: poison — room frame for removed/closed mirror (room %)', v_room_id;
        RETURN 'poison';
      END IF;

      v_origin := NULLIF(lower(btrim(p_payload->>'originDomain')), '');
      IF v_origin IS NULL THEN
        RAISE NOTICE 'federation: poison — room message missing originDomain (room %, peer %)',
          v_room_id, p_peer_domain;
        RETURN 'poison';
      END IF;

      -- (review fold, F2) reflected-self origin: legit traffic can NEVER carry
      -- origin == this org's own local domain — federation_room_fanout's own
      -- origin-skip (member_domain <> v_origin) guarantees a spoke never
      -- receives a relay whose origin is itself. A malicious/compromised hub
      -- could otherwise plant this org's own domain in the roster mirror
      -- (which the hub authors) and assert it as originDomain here, landing
      -- author_id NULL + federated_sender_addr naming a LOCAL address —
      -- internal impersonation of a real local user. Checked before the
      -- roster-mirror trust below (the same predicate every other reducer
      -- uses to test "is this a local domain" — classify_focus.sql/
      -- deliver_group_vacation.sql/send.sql).
      IF EXISTS (SELECT 1 FROM domains WHERE lower(name) = v_origin AND is_local) THEN
        RAISE NOTICE 'federation: poison — asserted originDomain % is one of this org''s own local domains (room %, peer %)',
          v_origin, v_room_id, p_peer_domain;
        RETURN 'poison';
      END IF;

      -- the hub asserts origin for roster members (Q2, MUC posture): trust it
      -- only when it names a non-left roster member of THIS org's own
      -- hub-maintained roster mirror, or the hub itself.
      IF v_origin <> lower(v_room_hub_domain) AND NOT EXISTS (
        SELECT 1 FROM federation_room_members
         WHERE room_id = v_room_id AND member_domain = v_origin AND left_at IS NULL
      ) THEN
        RAISE NOTICE 'federation: poison — asserted originDomain % not in room %''s roster mirror (nor the hub)',
          v_origin, v_room_id;
        RETURN 'poison';
      END IF;

      -- cheap consistency re-check of what the hub already enforced at
      -- ingest: fromAddr's domain must equal the (now-trusted) origin.
      IF split_part(v_from_addr, '@', 2) <> v_origin THEN
        RAISE NOTICE 'federation: poison — fromAddr domain % does not match originDomain % (room %)',
          split_part(v_from_addr, '@', 2), v_origin, v_room_id;
        RETURN 'poison';
      END IF;
    END IF;

    -- ══════════════════════════════════════════════════════════════════════
    -- Step 5: land (both sides). Dedup pre-check on
    -- (channel_id, origin, clientMsgId) BEFORE bumping change_seq — a resend
    -- under a new peer_seq (already ruled safe above) must not burn a
    -- change_seq value for a row that will never be inserted. The
    -- ON CONFLICT arbiter below remains the hard backstop regardless.
    -- ══════════════════════════════════════════════════════════════════════
    SELECT id INTO v_msg_id FROM chat_messages
     WHERE channel_id = v_channel_id AND federated_origin_domain = v_origin
       AND federated_stanza_id = v_client_msg_id;
    v_landed_now := (v_msg_id IS NULL);

    IF v_landed_now THEN
      UPDATE chat_channels SET change_seq = change_seq + 1
        WHERE id = v_channel_id RETURNING change_seq INTO v_seq;

      INSERT INTO chat_messages (channel_id, seq, author_id, federated_sender_addr, federated_origin_domain, federated_stanza_id, body, spam_quarantined, spam_reason)
        VALUES (v_channel_id, v_seq, NULL, v_from_raw, v_origin, v_client_msg_id, v_body, COALESCE(p_spam_quarantined, false), p_spam_reason)
        ON CONFLICT (channel_id, federated_origin_domain, federated_stanza_id) WHERE federated_stanza_id IS NOT NULL DO NOTHING
        RETURNING id INTO v_msg_id;

      -- a concurrent racer may have landed the SAME row between this call's
      -- precheck and its own INSERT — the ON CONFLICT DO NOTHING then returns
      -- no row, v_msg_id stays NULL, and v_landed_now must NOT relay a second
      -- time (the concurrent winner's own call already will/did).
      v_landed_now := (v_msg_id IS NOT NULL);

      IF v_landed_now THEN
        PERFORM notify_chat_state(v_channel_id, 'message_created', v_msg_id, v_seq);
      END IF;
    END IF;

    -- ══════════════════════════════════════════════════════════════════════
    -- Step 6: relay (HUB side only, SAME txn, ONLY on a genuinely fresh land).
    -- A content-level dedup (clientMsgId resend under a brand-new peer_seq —
    -- already ruled safe/no-op above) must NOT relay a second time: this
    -- content already relayed the first time it landed, and federation_enqueue
    -- assigns a fresh peer_seq per call with no stanza_id-level idempotency of
    -- its own — re-running the fanout here would hand every other member a
    -- genuine SECOND outbox row for content they already received. The payload
    -- is REBUILT from validated fields — NEVER the inbound payload forwarded
    -- verbatim. The fan-out's own origin-skip (member_domain <> v_origin)
    -- prevents re-relaying to the sender; parked/left/revoke discipline is
    -- entirely federation_room_enqueue_member's job (Task 2/3), unchanged here.
    -- ══════════════════════════════════════════════════════════════════════
    IF v_ch_peer_domain IS NULL AND v_landed_now THEN
      v_relay_payload := jsonb_build_object(
        'op', 'message',
        'roomId', v_room_id,
        'fromAddr', v_from_raw,
        'body', v_body,
        'clientMsgId', v_client_msg_id);

      -- (review fold, F5) sentAt is forwarded ONLY when it's a plausible
      -- timestamp-shaped string (<=64 octets) — otherwise omitted entirely
      -- from the rebuilt payload, never a bare forward of the inbound value:
      -- an unbounded, attacker-controlled sentAt here would get copied
      -- verbatim into every OTHER room member's outbox row by the fan-out
      -- below, amplifying a single oversized string ×N members. Spokes never
      -- parse/store sentAt out of this payload (informational only), so its
      -- absence is tolerated structurally, not just by convention.
      IF p_payload->>'sentAt' IS NOT NULL AND octet_length(p_payload->>'sentAt') <= 64 THEN
        v_relay_payload := v_relay_payload || jsonb_build_object('sentAt', p_payload->>'sentAt');
      END IF;

      PERFORM federation_room_fanout(v_room_id, v_origin || '/' || v_client_msg_id,
        'application/x-setjoin-room', v_relay_payload, v_origin);
    END IF;

    RETURN 'applied';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Task 5: control-op arms — spoke-side only. A channel that resolves
  -- HUB-shaped locally means a peer is sending US control ops, which only a
  -- hub may originate — enforced per-op below (invite carries its OWN
  -- structural/hub-binding guards instead, since there may be no local row
  -- for it yet; remove/roster/room_revoked all require an EXISTING
  -- spoke-shaped local room bound to the stream peer).
  -- ══════════════════════════════════════════════════════════════════════
  v_room_id := NULLIF(btrim(p_payload->>'roomId'), '');
  IF v_room_id IS NULL THEN
    RAISE NOTICE 'federation: poison — control op % missing roomId from peer % seq %',
      v_op, p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- (review fold, B1 BLOCKER) roomId feeds TWO btree structures the invite
  -- arm below writes into: chat_channels.federated_room_id (a partial-UNIQUE
  -- btree index, V140) and federation_rooms.room_id (a text PRIMARY KEY,
  -- also btree) — an attacker-controlled roomId with no length cap can blow
  -- past Postgres's ~2.7KB btree index-row ceiling ("index row size exceeds
  -- btree maximum", SQLSTATE 54000), the SAME F1/54000 livelock as
  -- clientMsgId/fromAddr in the message arm above: it would fire deep inside
  -- an INSERT below, AFTER Step 1's cursor advance already committed,
  -- permanently wedging the stream. Checked once here, before dispatch to
  -- any control-op arm, since remove/roster/room_revoked also look v_room_id
  -- up against these same btree structures.
  IF octet_length(v_room_id) > 512 THEN
    RAISE NOTICE 'federation: poison — roomId over 512 octets (btree index ceiling) from peer % seq % op %',
      p_peer_domain, p_peer_seq, v_op;
    RETURN 'poison';
  END IF;

  IF v_op = 'invite' THEN
    -- ── the mirror constructor — the ONLY spoke-side mirror-creation path.
    -- Every guard below runs BEFORE ANY WRITE (the eng-review BLOCKER):
    -- without them, any allow-listed org that learned a roomId from relayed
    -- payloads could hijack another hub's mirror on a shared spoke.
    -- ────────────────────────────────────────────────────────────────────

    -- 1. Structural: only the domain that minted a roomId may introduce it
    --    (the roomId contract, contract section) — makes cross-hub roomId
    --    hijack structurally impossible.
    IF lower(split_part(v_room_id, '@', 2)) <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — invite roomId % does not belong to stream peer % (structural hijack guard)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- 2. Hub-binding belt: an existing local room row bound to a DIFFERENT
    --    hub must never be resurrected/rewritten by another peer — belt for
    --    any legacy/free-text roomId that predates the structural rule
    --    above (guard 1 already makes this practically unreachable for a
    --    roomId minted under the current scheme, kept as defense in depth).
    SELECT hub_domain, channel_id INTO v_existing_hub, v_existing_channel_id
      FROM federation_rooms WHERE room_id = v_room_id;
    IF v_existing_hub IS NOT NULL AND lower(v_existing_hub) <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — invite for room % is already bound to a DIFFERENT hub % (peer % is not it)',
        v_room_id, v_existing_hub, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- 3. hubDomain (payload) must equal the stream-authenticated peer.
    IF lower(btrim(COALESCE(p_payload->>'hubDomain', ''))) <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — invite hubDomain does not match stream peer % (room %)',
        p_peer_domain, v_room_id;
      RETURN 'poison';
    END IF;

    -- resolve contactAddr to a real, enabled local user (the
    -- federation_apply_chat toAddr join, verbatim). Unresolvable is a
    -- disclosed v1 limitation — no invite-NACK back to the hub (Task 10
    -- ledger); silence is the only symptom.
    v_contact_raw := NULLIF(btrim(p_payload->>'contactAddr'), '');
    IF v_contact_raw IS NULL THEN
      RAISE NOTICE 'federation: poison — invite missing contactAddr (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;
    v_contact_addr := lower(v_contact_raw);
    SELECT mb.user_id INTO v_contact_user_id
      FROM mailboxes mb JOIN users u ON u.id = mb.user_id
     WHERE lower(mb.email) = v_contact_addr
       AND mb.enabled AND mb.receive_enabled AND u.enabled
     LIMIT 1;
    IF v_contact_user_id IS NULL THEN
      RAISE NOTICE 'federation: poison — invite contactAddr % does not resolve to a real enabled local user (room %)',
        v_contact_addr, v_room_id;
      RETURN 'poison';
    END IF;

    -- validate the roster payload shape BEFORE any write — a malformed
    -- invite must leave zero side effects, same law as every other guard.
    v_roster := p_payload->'roster';
    IF v_roster IS NULL OR jsonb_typeof(v_roster) <> 'array' THEN
      RAISE NOTICE 'federation: poison — invite missing/malformed roster array (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- (review fold, M1 MAJOR) cap roster cardinality BEFORE any write — an
    -- allow-listed-but-malicious hub could otherwise hand a 16MiB frame
    -- ~10^5 roster elements, each landing as a permanent never-DELETEd
    -- federation_room_members row (the roster mirror is read history, never
    -- pruned) — a multi-GB write primitive from a single frame.
    IF jsonb_array_length(v_roster) > 4096 THEN
      RAISE NOTICE 'federation: poison — invite roster exceeds 4096 elements (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    v_title := left(p_payload->>'title', 256);
    -- (review fold, MINOR #1) truncate, don't poison — a long title is not a
    -- trust/shape violation, just cosmetic. left() counts CHARACTERS, not
    -- octets; capping at 256 characters bounds worst-case UTF-8 (4 octets/
    -- char) at 1024 octets without ever splitting a multibyte codepoint.

    -- create the mirror IDEMPOTENTLY (ON CONFLICT on the partial-UNIQUE
    -- federated_room_id index, the federation_apply_chat DM-mirror
    -- precedent) — a re-invite/re-admit reuses the SAME mirror channel,
    -- never a second row. visibility='private' is pinned deliberately:
    -- V119's default is 'public' and DES-008 makes public channels
    -- self-joinable — a public mirror would let any local user join the
    -- cross-org room before the contact owner acts.
    IF v_existing_channel_id IS NULL THEN
      INSERT INTO chat_channels (kind, name, visibility, federated_room_id, federated_peer_domain, created_by)
        VALUES ('channel', v_title, 'private', v_room_id, lower(p_peer_domain), v_contact_user_id)
        ON CONFLICT (federated_room_id) WHERE federated_room_id IS NOT NULL DO NOTHING
        RETURNING id INTO v_channel_id;
      IF v_channel_id IS NULL THEN
        SELECT id INTO v_channel_id FROM chat_channels WHERE federated_room_id = v_room_id;
      END IF;
      INSERT INTO federation_rooms (room_id, hub_domain, channel_id)
        VALUES (v_room_id, lower(p_peer_domain), v_channel_id)
        ON CONFLICT (room_id) DO NOTHING;
    ELSE
      v_channel_id := v_existing_channel_id;
    END IF;

    -- the contact user as (at least) an owner of the mirror, idempotently —
    -- they add local colleagues via normal chat membership (Q3/Q4). A
    -- re-invite naming a new contact simply adds them alongside whoever
    -- already joined; it never demotes/removes an existing owner.
    INSERT INTO chat_channel_members (channel_id, user_id, role)
      VALUES (v_channel_id, v_contact_user_id, 'owner')
      ON CONFLICT (channel_id, user_id) DO NOTHING;

    -- resurrect a previously kicked/revoked mirror — reachable only past
    -- guards 1-3 above, so only the true hub can resurrect it; join-forward,
    -- no backfill (Q9).
    UPDATE chat_channels SET federated_room_removed_at = NULL WHERE id = v_channel_id;
  ELSE
    -- remove / roster / room_revoked: the room must ALREADY resolve
    -- spoke-shaped locally, bound to the stream peer as hub.
    SELECT fr.channel_id, c.federated_peer_domain INTO v_channel_id, v_ch_peer_domain
      FROM federation_rooms fr JOIN chat_channels c ON c.id = fr.channel_id
     WHERE fr.room_id = v_room_id;

    IF v_channel_id IS NULL THEN
      RAISE NOTICE 'federation: poison — control op % for unknown/unbound room % from peer %',
        v_op, v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    IF v_ch_peer_domain IS NULL THEN
      RAISE NOTICE 'federation: poison — control op % arrived for a HUB-shaped room % — only a hub may originate control ops',
        v_op, v_room_id;
      RETURN 'poison';
    END IF;

    IF v_ch_peer_domain <> lower(p_peer_domain) THEN
      RAISE NOTICE 'federation: poison — control op % from non-hub stream peer % (mirror bound to %)',
        v_op, p_peer_domain, v_ch_peer_domain;
      RETURN 'poison';
    END IF;

    IF v_op IN ('remove', 'room_revoked') THEN
      -- the kicked-mirror machinery, reused verbatim by BOTH: archive-
      -- read-only + banner (notify_chat_state's 'federation_removed' event,
      -- Task 7); sends refuse BZ213 from here on (chat_message.sql, Task
      -- 3); straggler inbound message frames poison (the message arm's
      -- v_ch_removed_at check above). No roster rewrite, no message
      -- destruction — retention/hold/purge continue to govern the LOCAL
      -- copy only (Q6). TRULY idempotent (review fold, MINOR #5): only
      -- stamps federated_room_removed_at on the FIRST transition (the WHERE
      -- guard below), and only fires the banner notify on that same first
      -- transition (IF FOUND on the guarded UPDATE) — a re-delivery must
      -- never keep pushing removed_at forward or re-notify.
      UPDATE chat_channels SET federated_room_removed_at = now()
        WHERE id = v_channel_id AND federated_room_removed_at IS NULL;
      IF FOUND THEN
        PERFORM notify_chat_state(v_channel_id, 'federation_removed');
      END IF;
      RETURN 'applied';
    END IF;

    -- v_op = 'roster': validate the payload shape before any write.
    v_roster := p_payload->'roster';
    IF v_roster IS NULL OR jsonb_typeof(v_roster) <> 'array' THEN
      RAISE NOTICE 'federation: poison — roster op missing/malformed roster array (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;

    -- (review fold, M1 MAJOR) same cardinality cap as the invite arm above —
    -- op:'roster' hits the SAME shared roster-replace loop below.
    IF jsonb_array_length(v_roster) > 4096 THEN
      RAISE NOTICE 'federation: poison — roster op array exceeds 4096 elements (room %, peer %)',
        v_room_id, p_peer_domain;
      RETURN 'poison';
    END IF;
  END IF;

  -- (review fold, B2 BLOCKER) validate EVERY roster element's domain in its
  -- OWN pass, before the mutating loop below touches a single row: member_domain
  -- feeds federation_room_members's (room_id, member_domain) btree PRIMARY
  -- KEY — same 54000 btree-row-ceiling livelock as B1/F1 above — and a
  -- garbage domain mid-frame must never partially apply the rest of the
  -- roster (a mutating per-element CONTINUE/poison split here would leave
  -- the earlier elements' upserts committed with no way to unwind them
  -- short of a RAISE, which would re-livelock the exact way this whole
  -- file's header forbids). Whole-frame poison, not a silent per-element
  -- skip — a hub sending malformed domains is not a partial-trust
  -- situation. 255 octets is the DNS name ceiling; this also catches a
  -- missing/empty domain (previously a silent CONTINUE).
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(v_roster) elem
     WHERE COALESCE(octet_length(elem->>'domain'), 0) = 0
        OR octet_length(elem->>'domain') > 255
  ) THEN
    RAISE NOTICE 'federation: poison — roster element with empty/oversized (>255 octets, DNS ceiling) domain (room %, peer %, op %)',
      v_room_id, p_peer_domain, v_op;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- SHARED roster-mirror replace — reached only by 'invite' (after its own
  -- setup writes above) and 'roster' (validated above); 'remove'/
  -- 'room_revoked' already returned. Upsert each {domain,state}; set
  -- left_at on local rows absent from the payload (NEVER DELETE — the
  -- roster mirror is also read history, contract section).
  -- ══════════════════════════════════════════════════════════════════════
  FOR v_domain, v_state IN
    SELECT lower(elem->>'domain'), elem->>'state' FROM jsonb_array_elements(v_roster) elem
  LOOP
    IF v_domain IS NULL OR v_domain = '' THEN
      CONTINUE;
    END IF;
    IF v_state = 'parked' THEN
      INSERT INTO federation_room_members (room_id, member_domain, parked_at, parked_reason)
        VALUES (v_room_id, v_domain, now(), 'backpressure')
        ON CONFLICT (room_id, member_domain) DO UPDATE
          SET parked_at     = COALESCE(federation_room_members.parked_at, now()),
              parked_reason = COALESCE(federation_room_members.parked_reason, 'backpressure'),
              left_at = NULL, left_reason = NULL;
    ELSE
      INSERT INTO federation_room_members (room_id, member_domain)
        VALUES (v_room_id, v_domain)
        ON CONFLICT (room_id, member_domain) DO UPDATE
          SET parked_at = NULL, parked_reason = NULL, left_at = NULL, left_reason = NULL;
    END IF;
  END LOOP;

  SELECT array_agg(lower(elem->>'domain')) INTO v_roster_domains
    FROM jsonb_array_elements(v_roster) elem WHERE elem->>'domain' IS NOT NULL;

  UPDATE federation_room_members
     SET left_at = now()
   WHERE room_id = v_room_id AND left_at IS NULL
     AND NOT (member_domain = ANY (COALESCE(v_roster_domains, ARRAY[]::text[])));

  -- the gap marker (Q9 coverage epochs, invite only): ONE local system
  -- message when the payload carries gapFrom/gapTo (the re-admit UPSERT
  -- closing an open epoch on the hub side) — a purely LOCAL record, never
  -- wire content: no federated_stanza_id/origin. A malformed/garbled
  -- gapFrom/gapTo must never raise mid-transaction (poison discipline) —
  -- caught locally and treated as absent.
  IF v_op = 'invite' THEN
    v_gap_from := NULL;
    v_gap_to   := NULL;
    IF p_payload ? 'gapFrom' AND p_payload ? 'gapTo' THEN
      BEGIN
        v_gap_from := (p_payload->>'gapFrom')::timestamptz;
        v_gap_to   := (p_payload->>'gapTo')::timestamptz;
      EXCEPTION WHEN OTHERS THEN
        v_gap_from := NULL;
        v_gap_to   := NULL;
      END;
    END IF;

    IF v_gap_from IS NOT NULL AND v_gap_to IS NOT NULL THEN
      UPDATE chat_channels SET change_seq = change_seq + 1
        WHERE id = v_channel_id RETURNING change_seq INTO v_seq;
      INSERT INTO chat_messages (channel_id, seq, author_id, msg_type, body)
        VALUES (v_channel_id, v_seq, NULL, 'system',
                jsonb_build_object('kind', 'federation_gap', 'from', v_gap_from, 'to', v_gap_to)::text)
        RETURNING id INTO v_msg_id;
      PERFORM notify_chat_state(v_channel_id, 'message_created', v_msg_id, v_seq);
    END IF;
  END IF;

  PERFORM notify_chat_state(v_channel_id, 'federation_roster');
  RETURN 'applied';
END;
$$;
SELECT apply_worker_ownership('federation_apply_room(text,bigint,text,jsonb,boolean,text,text)'::regprocedure);
