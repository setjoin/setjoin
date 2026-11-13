-- chat_message.sql: message mutation + read reducers (Pillar A1 Task 5).
--
-- Producers: chat_message_send, chat_message_edit, chat_message_delete,
-- chat_message_to_json (single-source row projection, message_to_jmap_email
-- pattern — list/thread/since all build off the SAME jsonb shape so the
-- reactions/mentionsMe/replyCount aggregates can never drift between them),
-- chat_messages_list, chat_thread_list, chat_messages_since. A3 QoL Task 10
-- widens chat_messages_list with an optional p_around_seq — the
-- jump-to-message substrate consumed by search hits/pins/saves/My-Threads
-- click-throughs (see the function's own comment below); it adds no new BZ
-- code (same BZ163 membership guard as every other read here).
--
-- BZ block (chat = BZ160-BZ175, this file's slice): BZ163 not a channel
-- member, BZ164 post restricted to admins (announcement channel), BZ165
-- invalid thread parent (missing / other channel / soft-deleted — one code,
-- all three shapes, no oracle on WHY), BZ166 @channel/@all restricted to
-- owner/admin UNLESS the channel's broadcast_permission = 'all' (V122,
-- Pillar A3 QoL Task 8 — chat_channel_update flips it, BZ161-gated there),
-- BZ167 edit/delete forbidden (non-author, non-owner/admin,
-- the acting user no longer a channel member, the message already deleted
-- (no double-delete), OR the message id doesn't exist — one code for all
-- of these so a client can't probe for the existence of a message it can't
-- otherwise see, or distinguish "removed from channel" from "not the
-- author"), BZ168 message body empty or over the 64KiB cap (NOT raised when
-- attachments are present — Chat A2 Task 3, Design decision D2 "attachment-
-- only messages are legal"), BZ171 mutation (send/edit/delete) attempted
-- against an archived channel — archive is read-only (Task 4 interface,
-- grill Q6b, decision-audit row 24). Chat A2 Task 3 adds BZ172 (attachment
-- payload invalid: bad shape/name or over the 8-per-message cap) and BZ173
-- (attachments attempted while feature.drive is OFF — reducer-level
-- defense; the route gate is primary). BZ144/BZ148 (chunk-claim anti-oracle,
-- quota) surface unchanged through drive_file_put_version; BZ260
-- (opaque name-unavailable collision) is caught and auto-suffixed, never
-- surfaced. Chat A3
-- QoL Task 6 adds BZ178 (voice message durationMs over the 300000ms cap).
-- Task 3 (pin/save) adds no new codes here — chat_message_to_json gains a
-- 'pinned' projection field read from chat_pin.sql's chat_message_pins.
--
-- A3.5 Task 2 — mobile-push enqueue: chat_message_send writes ONE
-- chat_push_intents row per message (V124), gated by feature.chat_push
-- (real COALESCE feature_toggles pattern — no toggle_enabled() helper exists
-- in reducers/). Per-member fan-out + the notif_level/DND gate
-- (chat_push_should_notify, sql/reducers/chat_push_should_notify.sql) are
-- the pushjobs worker's job at drain time, not this reducer's.
--
-- A4a Task 10 — per-user send rate limit: chat_message_send raises BZ196
-- (own standalone registration, NOT part of the BZ160-175 A1/A2 slice above)
-- when system_config['chat.send_rate_per_minute'] (default 60, 0=disabled)
-- is exceeded in the current minute window (chat_send_counters, V126 §H).
-- Deliberately NOT gated on feature.chat_compliance — abuse control, ships
-- live to every deployment on merge, independently revertable.
--
-- Pillar C1 Task 2 — outbound chat<->federation bridge: chat_message_send
-- raises BZ206 (own standalone registration, like BZ196 above) when the
-- target is a federated DM (chat_channels.federated_peer_domain IS NOT
-- NULL, V139) and EITHER feature.federation is OFF OR the body exceeds the
-- 64KiB cap — both checked BEFORE the generic BZ168/BZ173 guards so a
-- federated-compose client gets the federation-specific code. On success,
-- the local chat_messages write is followed, in the SAME transaction, by
-- one federation_enqueue call (federation_dm_ensure.sql creates the
-- channel; federation_enqueue.sql, C0, is the outbox writer).
--
-- Pillar C1 Task 3 — user-facing surface: chat_message_to_json projects
-- federatedSenderAddr/deliveredAt/spamQuarantined (all V139 columns, all
-- NULL/false on an ordinary message) plus authorId, which reads NULL for a
-- federated inbound row (Task 4 is the reducer that writes one; this file
-- only projects the shape).
--

-- App-level-primary (ARCH-006): every reducer here scopes membership/
-- authorship via a direct SELECT, not the chat_member_role() DEFINER helper
-- (that helper exists solely for the latent FORCE-RLS policy).
--
-- Seq rail (the load-bearing invariant): send/edit/delete ALL bump the
-- channel's change_seq under its row lock and re-stamp the affected row's
-- seq. Because that UPDATE...RETURNING serializes on the channel row, seq
-- order == commit order for every mutation kind — a reconnecting client's
-- chat_messages_since(seq) replay can never skip a late-committing row, and
-- editing/deleting an old message re-surfaces it at the FRONT of a replay
-- instead of leaving a stale copy behind (chat_seq_cursor.pg is the pinning
-- test for this).
--
-- Chat A2 Task 3 — attachments land ATOMICALLY inside chat_message_send:
-- message row first (chat_message_attachments.message_id is NOT NULL —
-- Eng L1), then chat_space_ensure (lazy per-channel space, first attachment
-- provisions it), then one drive_node_create + drive_file_put_version per
-- attachment, then the link row. No separate land-then-send API exists, so
-- the only way a send can fail partway is a RAISE from deep inside this
-- call — and because the whole thing runs as one statement/transaction, that
-- unwinds the message insert and the seq bump too: an unsent message never
-- orphans a chat_message_attachments row (plan's atomicity invariant).
--
-- A3 Task 6 — msg_type/payload send seam: p_msg_type/p_payload widen every
-- structured-message kind (voice today, poll in Task 9) through the SAME
-- send/projection path attachments already use, instead of a bespoke insert
-- per kind. Voice = msg_type='voice' + payload {durationMs} + one audio/*
-- attachment on the A2 rail above; BZ178 caps durationMs at 300000ms (5 min).
-- The attachment BYTE-SIZE ceiling is deliberately NOT re-implemented here —
-- it already rides drive_file_put_version's own BZ148 quota/upload_max_bytes
-- check in the attachment loop above, for every attachment kind including
-- audio (ponytail: one size gate, not two).
--
-- Pillar C1 Task 2 — the outbound chat<->federation bridge: when the target
-- channel is a federated DM (chat_channels.federated_peer_domain IS NOT
-- NULL, V139), a send ALSO enqueues an outbound stanza in the SAME
-- transaction as the local chat_messages write (federation_enqueue, C0 —
-- EXECUTE-granted to setjoin_app via apply_worker_ownership, so this
-- invoker-rights reducer can call it directly). Two federation-specific
-- guards run BEFORE the generic BZ168 body checks below — via an early,
-- membership-independent peek at the target channel's federated_peer_domain
-- (chat_channels_read's policy already admits it: a federated channel's sole
-- member is always its own creator, so a legitimate caller can always see
-- their own channel; an illegitimate caller targeting someone else's
-- federated channel id sees zero rows here and falls through unharmed to
-- the ordinary BZ163 membership check below — no oracle, no bypass) — both
-- raise BZ206, NOT the generic BZ168/BZ173, so a federated-compose client
-- can tell "this failed because of federation" apart from "invalid in
-- general": (a) feature.federation OFF (the BZ173 toggle-refuse pattern —
-- never a silent queue) and (b) body over the SAME 64KiB cap the inbound
-- applier (Task 4) treats as poison — mirrored here so a compliant local
-- sender can't author a message the peer would silently discard (a
-- self-poison that would falsely tick "delivered").
--
-- Pillar C2 Task 3 — the room arm, a three-way split on the same choke
-- point: v_room_id/v_room_removed (chat_channels.federated_room_id/
-- federated_room_removed_at, V140) let this reducer tell a DM channel
-- (v_fed_domain set, v_room_id NULL) apart from a room channel (v_room_id
-- set, either shape). BZ213 = the kicked/closed-mirror send refusal (a
-- spoke whose federated_room_removed_at is set is archive-read-only — the
-- Q3/Q9 machinery, enforced here, not just in the UI). BZ212 = the Q11
-- content-scope refusal — attachments and non-'text' msg_type cannot
-- propagate to a federated room, so they're refused at send rather than
-- silently desyncing every member org's copy. The enqueue arm below is a
-- three-way split: DM unchanged, SPOKE enqueues one user-initiated frame to
-- the bound hub, HUB fans the same send out to the whole roster via
-- federation_room_fanout (the local land already happened above — this is
-- purely the relay leg).
DROP FUNCTION IF EXISTS chat_message_send(bigint,bigint,text,bigint,bigint[],text,jsonb);
CREATE OR REPLACE FUNCTION chat_message_send(
    p_user_id bigint, p_channel_id bigint, p_body text,
    p_parent_id bigint DEFAULT NULL, p_mentions bigint[] DEFAULT '{}',
    p_broadcast text DEFAULT NULL, p_attachments jsonb DEFAULT '[]',
    p_msg_type text DEFAULT 'text', p_payload jsonb DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_role      text;
    v_can_post  boolean;
    v_history_floor bigint;
    v_joined_at timestamptz;
    v_post      text;
    v_archived  boolean;
    v_seq       bigint;
    v_id        bigint;
    v_natt      int;
    v_att       jsonb;
    v_space_id  bigint;
    v_ord       int := 0;
    v_base      text;
    v_ext       text;
    v_candidate text;
    v_suffix    int;
    v_node_id   bigint;
    v_put       jsonb;
    v_msg_type  text;
    v_broadcast_perm text;
    v_rate      int;
    v_sent      int;
    v_fed_domain text;
    v_fed_remote text;
    v_room_id      text;
    v_room_removed timestamptz;
    v_channel_kind text;
    v_rec          record;
    v_payload      jsonb;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    v_msg_type := COALESCE(p_msg_type, 'text');
    -- C2 Task 1 (V140 msg_type widening — the forge guard the widening
    -- requires): 'system' is reserved for the federation applier's own
    -- LOCAL gap-marker insert (Q9 coverage epochs, Task 5) — never a
    -- user-settable value. Without this refusal, V140's widened CHECK would
    -- let any user forge a 'system' row through the ordinary send path.
    -- Runs for EVERY channel, federated or not.
    IF v_msg_type = 'system' THEN
        RAISE EXCEPTION 'msg_type ''system'' is reserved for federation gap markers'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments","detail":"msg_type ''system'' is not user-settable"}';
    END IF;
    -- C1 Task 2 / C2 Task 3: federation branch guards run FIRST, ahead of
    -- the generic BZ168 body checks below, so a federated channel's
    -- oversized/toggle-off/closed-room/wrong-content send surfaces a
    -- federation-specific code instead. v_room_id/v_room_removed cover BOTH
    -- room shapes (hub: federated_peer_domain NULL; spoke mirror:
    -- federated_peer_domain = the bound hub) — a spoke mirror carries BOTH
    -- v_fed_domain and v_room_id, so the toggle/body checks below fire off
    -- either condition alone (harmlessly redundant for a spoke send).
    SELECT federated_peer_domain, federated_remote_id, federated_room_id, federated_room_removed_at
      INTO v_fed_domain, v_fed_remote, v_room_id, v_room_removed
      FROM chat_channels WHERE id = p_channel_id;
    IF v_fed_domain IS NOT NULL OR v_room_id IS NOT NULL THEN
        IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.federation'), FALSE) THEN
            RAISE EXCEPTION 'federated messaging unavailable (feature.federation is disabled)'
                USING ERRCODE='BZ206', HINT='{"type":"forbidden","detail":"feature.federation is disabled"}';
        END IF;
        -- BZ213: the kicked/closed-mirror choke, enforced at the send
        -- checkpoint (Q3/Q9's advisory reuses the SAME field) — never just
        -- a UI affordance. A hub channel never carries removed_at (only
        -- Task 5's spoke applier ever sets it), so this only ever fires for
        -- a spoke mirror.
        IF v_room_removed IS NOT NULL THEN
            RAISE EXCEPTION 'this federated room was closed (kicked or revoked) — archive-read-only'
                USING ERRCODE='BZ213', HINT='{"type":"forbidden","detail":"federated room removed/closed"}';
        END IF;
        IF p_body IS NOT NULL AND octet_length(p_body) > 65536 THEN
            RAISE EXCEPTION 'federated message body over 64KiB'
                USING ERRCODE='BZ206',
                      HINT='{"type":"invalidArguments","detail":"federated messages are capped at 64KiB, mirroring the inbound poison cap"}';
        END IF;
        -- BZ212 (Q11 content scope): a federated room propagates plain text
        -- messages only — an attachment or a non-'text' msg_type (poll/
        -- voice/call/etc.) could never propagate to the other member orgs'
        -- copies, structurally desyncing them. DM sends are unaffected
        -- (v_room_id IS NULL there). Computed inline (not v_natt, which is
        -- assigned further below) since this guard runs first.
        IF v_room_id IS NOT NULL AND (
             jsonb_array_length(COALESCE(p_attachments, '[]'::jsonb)) > 0
             OR v_msg_type <> 'text') THEN
            RAISE EXCEPTION 'federated rooms carry plain text messages only'
                USING ERRCODE='BZ212',
                      HINT='{"type":"invalidArguments","detail":"attachments and non-text msg_type cannot propagate to a federated room"}';
        END IF;
    END IF;
    -- BZ178: voice cap. A missing/non-numeric durationMs is left for the
    -- caller's own reducer (Task 9's poll wrapper, a future voice route) to
    -- shape-validate — this is strictly the numeric cap, same posture as
    -- BZ172's "cap first, shape second" split.
    IF v_msg_type = 'voice' AND jsonb_typeof(p_payload -> 'durationMs') = 'number'
       AND (p_payload ->> 'durationMs')::numeric > 300000 THEN
        RAISE EXCEPTION 'voice message exceeds the 5-minute (300000ms) cap'
            USING ERRCODE='BZ178', HINT='{"type":"invalidArguments","detail":"voice messages are capped at 300000ms"}';
    END IF;
    v_natt := jsonb_array_length(COALESCE(p_attachments, '[]'::jsonb));
    -- attachment-only messages are legal (Design C2/D2): empty/whitespace
    -- body is fine iff at least one attachment rides along.
    IF v_natt = 0 AND coalesce(btrim(p_body), '') = '' THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_body IS NOT NULL AND octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    -- BZ172: cap + basic shape (per-item deep manifest validation is
    -- drive_file_put_version's own BZ141 job — not duplicated here).
    IF v_natt > 8 THEN
        RAISE EXCEPTION 'too many attachments (max 8 per message)'
            USING ERRCODE='BZ172', HINT='{"type":"invalidArguments","detail":"max 8 attachments per message"}';
    END IF;
    IF v_natt > 0 AND EXISTS (
         SELECT 1 FROM jsonb_array_elements(p_attachments) a
          WHERE jsonb_typeof(a) <> 'object'
             OR NULLIF(btrim(a->>'sha256'), '') IS NULL
             OR NULLIF(btrim(a->>'name'), '') IS NULL
             OR (a->>'size') IS NULL OR (a->>'size')::bigint < 0
             OR jsonb_typeof(COALESCE(a->'manifest', '[]'::jsonb)) <> 'array') THEN
        RAISE EXCEPTION 'invalid attachment payload'
            USING ERRCODE='BZ172', HINT='{"type":"invalidArguments","detail":"bad attachment name/size/manifest"}';
    END IF;
    SELECT m.role, m.can_post, m.history_floor_seq, m.joined_at,
           c.post_permission, c.is_archived, c.broadcast_permission, c.kind
      INTO v_role, v_can_post, v_history_floor, v_joined_at,
           v_post, v_archived, v_broadcast_perm, v_channel_kind
      FROM chat_channel_members m JOIN chat_channels c ON c.id = m.channel_id
     WHERE m.channel_id = p_channel_id AND m.user_id = p_user_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    -- Guest G2: NULL is legacy-member inheritance only. A pre-V145 guest
    -- membership has no trustworthy posting snapshot, so it fails closed;
    -- ordinary members retain the historical NULL=allowed behavior. This
    -- check precedes every send-side write (rate counter, state, message,
    -- mention, intent, and notify).
    IF v_can_post IS FALSE OR (v_can_post IS NULL AND is_guest_account(p_user_id)) THEN
        RAISE EXCEPTION 'channel membership is read-only'
            USING ERRCODE='BZ220', HINT='{"type":"forbidden","detail":"channel membership is read-only"}';
    END IF;
    -- A4a Task 10 rate limit (send.sql BZ004 genre, per-minute window).
    -- 60/min default: a hard abuse ceiling no human sustains for a minute, while
    -- leaving CJK short-burst chat (好的/收到/嗯) unimpeded — 30/min is one message
    -- every 2s sustained and a lively 讨论 with IME quick-sends crosses it.
    -- Deliberately NOT gated on feature.chat_compliance — this is abuse
    -- control, not a compliance feature, and ships live to every deployment.
    -- ponytail: single-row upsert counter; per-channel or token-bucket limits
    -- only if a real deployment outgrows the flat per-user cap.
    v_rate := COALESCE((SELECT (value #>> '{}')::int FROM system_config
                         WHERE key = 'chat.send_rate_per_minute'), 60);
    IF v_rate > 0 THEN
      INSERT INTO chat_send_counters AS c (user_id, window_start, sent_count)
      VALUES (p_user_id, date_trunc('minute', now()), 1)
      ON CONFLICT (user_id) DO UPDATE SET
        sent_count   = CASE WHEN c.window_start = date_trunc('minute', now())
                            THEN c.sent_count + 1 ELSE 1 END,
        window_start = date_trunc('minute', now())
      RETURNING sent_count INTO v_sent;
      IF v_sent > v_rate THEN
        RAISE EXCEPTION 'chat send rate exceeded'
          USING ERRCODE='BZ196',
                HINT=jsonb_build_object('type','sending_quota_exceeded',
                        'detail','per-user chat send rate',
                        'retryAfterSeconds',
                        GREATEST(1, 60 - EXTRACT(SECOND FROM now())::int))::text;
      END IF;
    END IF;
    -- archive = read-only (Task 4 interface, decision-audit row 24): no new
    -- posts once a channel is archived.
    IF v_archived THEN
        RAISE EXCEPTION 'channel % is archived (read-only)', p_channel_id
            USING ERRCODE='BZ171', HINT='{"type":"forbidden"}';
    END IF;
    IF v_post = 'admins' AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'announcement channel: post restricted to admins'
            USING ERRCODE='BZ164', HINT='{"type":"forbidden"}';
    END IF;
    -- Pillar A3 QoL Task 8: the gate now reads the channel's OWN
    -- broadcast_permission (V122, default 'admins') instead of a hard-coded
    -- owner/admin-only rule — chat_channel_update lets an owner/admin flip it
    -- to 'all' so any member may @channel/@all in that specific channel.
    IF p_broadcast IS NOT NULL AND v_broadcast_perm = 'admins' AND v_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION '@channel/@all restricted to channel admins'
            USING ERRCODE='BZ166', HINT='{"type":"forbidden"}';
    END IF;
    -- One code for every unusable parent, including a remembered pre-floor
    -- id after a guest is removed/re-added. A caller may only create a reply
    -- to a parent they can currently read; otherwise the write itself would
    -- confirm hidden history and create a permanent covert thread edge.
    IF p_parent_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM chat_messages
          WHERE id = p_parent_id AND channel_id = p_channel_id AND deleted_at IS NULL
            -- GUEST_HISTORY_FLOOR: chat_message_send
            AND seq > COALESCE(v_history_floor, 0)
            AND (v_history_floor IS NULL OR created_at >= v_joined_at)) THEN
        RAISE EXCEPTION 'thread parent not in this channel (or deleted)'
            USING ERRCODE='BZ165', HINT='{"type":"invalidArguments"}';
    END IF;
    -- BZ173: reducer-level defense (route gate is primary) — membership has
    -- already been proven above, so this fires strictly after BZ163.
    IF v_natt > 0 AND NOT COALESCE(
         (SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'), FALSE) THEN
        RAISE EXCEPTION 'attachments unavailable (feature.drive is disabled)'
            USING ERRCODE='BZ173', HINT='{"type":"forbidden","detail":"feature.drive is disabled"}';
    END IF;
    -- commit-ordered seq: the channel row lock serializes concurrent
    -- senders, so seq order == commit order and since(seq) can never skip a
    -- row (the raw-identity cursor provably can — review C2/F2).
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = p_channel_id RETURNING change_seq INTO v_seq;
    -- Trusted-preview provenance (med-chat-unfurl-href-001): payload.preview
    -- is EXCLUSIVELY the unfurl worker's write — chat_message_unfurl_apply
    -- copying the chat_link_previews record that internal/chat/unfurl.go
    -- fetched server-side (SSRF-hardened) for the message's own URL. A
    -- sender-supplied preview used to be stored verbatim, handing every
    -- future renderer an attacker-chosen anchor href plus fully
    -- attacker-authored title/description inside the trusted enrichment
    -- chrome (an HTTPS allowlist alone would still admit forged HTTPS
    -- cards). Stripping the key here binds the rendered card to the
    -- authoritative unfurl result: title/body/image can only ever come from
    -- the server-side unfurl record, never from attacker-authored payload
    -- fields. Sanitize (not RAISE): preview is best-effort enrichment, so a
    -- forged preview degrades to a plain message, the same silent posture as
    -- every unfurl failure mode (chat_unfurl.sql) — and the jsonb_typeof
    -- guard covers the non-object payload shapes (NULL / scalar / array)
    -- that `- 'preview'` cannot delete from.
    v_payload := p_payload;
    IF jsonb_typeof(v_payload) = 'object' THEN
        v_payload := v_payload - 'preview';
    END IF;
    -- message row FIRST: chat_message_attachments.message_id is NOT NULL
    -- (Eng L1), and an attachment-only send stores '' for the body (the
    -- projection already treats '' as empty for a soft-deleted row; here
    -- it's simply the literal body of a no-caption attachment message).
    INSERT INTO chat_messages (channel_id, seq, author_id, parent_message_id, body, broadcast, msg_type, payload)
      VALUES (p_channel_id, v_seq, p_user_id, p_parent_id, COALESCE(p_body, ''), p_broadcast, v_msg_type, v_payload)
      RETURNING id INTO v_id;

    -- C1 Task 2 / C2 Task 3: the outbound federation enqueue, SAME
    -- transaction as the local write above — a rollback of this call
    -- unwinds both. author_id stays the local sender here (normal) —
    -- author_id=NULL/federated_sender_addr is exclusively the INBOUND shape
    -- (Task 4), never written on send. clientMsgId = this sender's own
    -- local chat_messages.id (the plan's "Identity, keys, and the one
    -- poison-proof invariant": per-sender-DB, never a global key).
    --
    -- Three-way split (a spoke mirror carries BOTH v_fed_domain and
    -- v_room_id — the DM arm below MUST exclude v_room_id or every spoke
    -- send would double-enqueue as a DM too):
    --   DM      (v_fed_domain set, v_room_id NULL)     -> one federation_enqueue
    --           to the DM peer, application/x-setjoin-chat (C1, unchanged).
    --   SPOKE   (v_room_id set, v_fed_domain set)      -> one user-initiated
    --           federation_enqueue to the bound hub, application/x-setjoin-room.
    --   HUB     (v_room_id set, v_fed_domain NULL)     -> federation_room_fanout
    --           to the whole roster (the local land above already happened;
    --           this is the relay leg), BZ205-exempt system frames.
    IF v_fed_domain IS NOT NULL AND v_room_id IS NULL THEN
        -- C1 Task 7: p_user_initiated=true — this IS the one user-facing send
        -- path (federation_room_fanout.sql's system fanout and the C0
        -- fedharness control endpoint both stay on the DEFAULT false, so the
        -- backpressure/dead-peer cap (BZ205) only ever protects a human
        -- sender, never a system frame).
        PERFORM federation_enqueue(v_fed_domain, v_id::text, 'application/x-setjoin-chat',
          jsonb_build_object(
            'fromAddr', (SELECT email FROM users WHERE id = p_user_id),
            'toAddr', v_fed_remote,
            'body', COALESCE(p_body, ''),
            'sentAt', now(),
            'clientMsgId', v_id::text),
          p_user_initiated := true);
    ELSIF v_room_id IS NOT NULL AND v_fed_domain IS NOT NULL THEN
        -- SPOKE: a single, user-initiated enqueue to the bound hub (Q9 —
        -- BZ205 protects the human; webmail surfaces the stale-hub banner
        -- on refusal, Task 7). NO originDomain in the payload — the hub
        -- stamps origin from the stream peer, never trusts the payload (Q2).
        PERFORM federation_enqueue(v_fed_domain, v_id::text, 'application/x-setjoin-room',
          jsonb_build_object(
            'op', 'message',
            'roomId', v_room_id,
            'fromAddr', (SELECT email FROM users WHERE id = p_user_id),
            'body', COALESCE(p_body, ''),
            'sentAt', now(),
            'clientMsgId', v_id::text),
          p_user_initiated := true);
    ELSIF v_room_id IS NOT NULL THEN
        -- HUB: the local chat_messages row above IS this org's own copy;
        -- fan the SAME message out to every other roster member (the fan-out
        -- stamps originDomain from the room's own hub_domain since
        -- p_origin_domain is NULL here — this is the hub's own send, not a
        -- relay of someone else's). BZ205-exempt (Q9 — system frames).
        PERFORM federation_room_fanout(v_room_id, v_id::text, 'application/x-setjoin-room',
          jsonb_build_object(
            'op', 'message',
            'roomId', v_room_id,
            'fromAddr', (SELECT email FROM users WHERE id = p_user_id),
            'body', COALESCE(p_body, ''),
            'sentAt', now(),
            'clientMsgId', v_id::text),
          NULL);
    END IF;

    IF v_natt > 0 THEN
        -- lazy per-channel space (DES-009): zero drive_space_members rows,
        -- access derives from chat_channel_members via drive_member_role.
        v_space_id := chat_space_ensure(p_user_id, p_channel_id);
        FOR v_att IN SELECT * FROM jsonb_array_elements(p_attachments) LOOP
            -- name split for the collision suffix ("report.pdf" ->
            -- "report (2).pdf"); lower()-compared uniqueness lives in the
            -- drive_nodes_live_name_uniq index (V114), enforced by
            -- drive_node_create raising the opaque BZ260 on collision.
            v_base := left(btrim(v_att->>'name'), 255);
            IF v_base ~ '\.[^./]+$' THEN
                v_ext  := substring(v_base from '\.[^./]+$');
                v_base := left(v_base, length(v_base) - length(v_ext));
            ELSE
                v_ext := '';
            END IF;
            v_candidate := v_base || v_ext;
            v_suffix := 1;
            LOOP
                BEGIN
                    -- btrim: a dotfile base ('' from '.env') or a 255+-char
                    -- truncation can leave the candidate with a leading/
                    -- trailing space, which drive_nodes' `name = btrim(name)`
                    -- CHECK rejects (BZ141) instead of BZ260 auto-suffixing.
                    v_candidate := btrim(v_candidate);
                    v_node_id := drive_node_create(p_user_id, v_space_id, NULL, 'file',
                                                    v_candidate, v_att->>'contentType');
                    EXIT;
                EXCEPTION
                    WHEN SQLSTATE 'BZ260' THEN
                        v_suffix := v_suffix + 1;
                        v_candidate := ' (' || v_suffix || ')';
                        -- cap the WHOLE candidate at 255 (drive_nodes CHECK):
                        -- truncate the base, never the suffix or extension.
                        v_candidate := left(v_base, greatest(255 - length(v_candidate) - length(v_ext), 1))
                                       || v_candidate || v_ext;
                END;
            END LOOP;
            v_put := drive_file_put_version(p_user_id, v_node_id, v_att->>'sha256',
                       (v_att->>'size')::bigint, v_att->>'contentType', NULL,
                       COALESCE(v_att->'manifest', '[]'::jsonb), NULL, 'chat', NULL);
            INSERT INTO chat_message_attachments
                (channel_id, message_id, file_node_id, version_id, filename, content_type, size_bytes, ordinal)
              VALUES (p_channel_id, v_id, v_node_id, (v_put->>'versionId')::bigint,
                      v_candidate, v_att->>'contentType', (v_att->>'size')::bigint, v_ord);
            v_ord := v_ord + 1;
        END LOOP;
    END IF;

    -- R2: mention rows only for verified channel members; non-members
    -- dropped silently — no sentinel row, no oracle (F4/L1).
    INSERT INTO chat_mentions (message_id, mentioned_user_id)
      SELECT v_id, u FROM unnest(p_mentions) u
       WHERE EXISTS (SELECT 1 FROM chat_channel_members
                      WHERE channel_id = p_channel_id AND user_id = u)
      ON CONFLICT DO NOTHING;

    -- Guest G1 digest intents ride the real message transaction. The helper
    -- no-ops for members and while feature.guest_accounts is disabled.
    FOR v_rec IN
        SELECT DISTINCT mentioned_user_id
          FROM chat_mentions WHERE message_id = v_id
    LOOP
        PERFORM guest_notification_intent_enqueue(
            v_rec.mentioned_user_id, 'mention',
            p_channel_id::text || ':' || v_id::text);
    END LOOP;
    IF v_channel_kind = 'dm' THEN
        FOR v_rec IN
            SELECT user_id FROM chat_channel_members
             WHERE channel_id = p_channel_id AND user_id <> p_user_id
        LOOP
            PERFORM guest_notification_intent_enqueue(
                v_rec.user_id, 'dm', p_channel_id::text || ':' || v_id::text);
        END LOOP;
    END IF;

    -- A3.5 Task 2: one enqueue row per MESSAGE (not per member — a 1k-member
    -- channel must not write 1k rows in this txn). ON CONFLICT DO NOTHING is
    -- free insurance (message_id is a fresh identity per call, so the sole
    -- writer can never actually replay one) — see chat_push.pg's direct
    -- duplicate-INSERT test for the UNIQUE(message_id) itself.
    IF COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_push'), FALSE) THEN
        INSERT INTO chat_push_intents (channel_id, message_id, sender_user_id)
          VALUES (p_channel_id, v_id, p_user_id)
          ON CONFLICT (message_id) DO NOTHING;
    END IF;

    PERFORM notify_chat_state(p_channel_id, 'message_created', v_id, v_seq);
    RETURN jsonb_build_object('messageId', v_id, 'seq', v_seq);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chat_message_edit(
    p_user_id bigint, p_message_id bigint, p_body text
) RETURNS bigint AS $$
DECLARE
    v_channel_id bigint;
    v_author_id  bigint;
    v_deleted    timestamptz;
    v_seq        bigint;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    IF coalesce(btrim(p_body), '') = '' OR octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    SELECT channel_id, author_id, deleted_at
      INTO v_channel_id, v_author_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    -- one code for "doesn't exist", "not yours", and "already deleted" — an
    -- author can't tell which of the three happened (BZ167, same anti-oracle
    -- posture as BZ170's channel-join lump).
    IF v_channel_id IS NULL OR v_author_id <> p_user_id OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'only the author may edit this message'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- Resolve history visibility before checking archival state. A remembered
    -- pre-floor id and an absent id must remain the same BZ167 even when the
    -- channel is archived; otherwise BZ171 becomes a hidden-history oracle.
    IF NOT EXISTS (
      SELECT 1 FROM chat_messages m
      JOIN chat_channel_members cm
        ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
     WHERE m.id = p_message_id AND m.author_id = p_user_id AND m.deleted_at IS NULL
       AND m.seq > COALESCE(cm.history_floor_seq, 0)
       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
    ) THEN
        RAISE EXCEPTION 'only the author may edit this message'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- archive = read-only: folded into the SAME row-lock UPDATE as the
    -- membership/authorship checks above it in this file's R3 pattern — a
    -- channel archived concurrently with this call closes the window the
    -- same way a concurrent chat_member_remove does (NOT FOUND below).
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id AND NOT is_archived RETURNING change_seq INTO v_seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'channel is archived (read-only)'
            USING ERRCODE='BZ171', HINT='{"type":"forbidden"}';
    END IF;
    -- grill Q3: the prior body is captured AFTER the change_seq row lock is
    -- held, never from a pre-lock variable. Concurrent edits serialize on
    -- that lock, and this INSERT..SELECT is a new statement under READ
    -- COMMITTED — it re-reads the body the previous editor COMMITTED, so
    -- every committed body appears in the revision chain (an author cannot
    -- scrub a briefly-broadcast body by racing two edits). If the UPDATE
    -- below fails, the whole call unwinds and neither write lands.
    INSERT INTO chat_message_revisions (channel_id, message_id, prior_body, edited_by)
      SELECT channel_id, id, body, p_user_id
        FROM chat_messages WHERE id = p_message_id;
    -- R3: ownership + deleted_at IS NULL + a CURRENT channel membership (a
    -- member removed via chat_member_remove can no longer rewrite their own
    -- history) folded into the mutation's own WHERE — closes the
    -- check-then-act gap between the guard above and this row lock for a
    -- concurrent chat_member_remove or a concurrent delete/edit.
    UPDATE chat_messages m SET body = p_body, edited_at = now(), seq = v_seq
      WHERE m.id = p_message_id AND m.author_id = p_user_id AND m.deleted_at IS NULL
        AND EXISTS (SELECT 1 FROM chat_channel_members cm
                     WHERE cm.channel_id = m.channel_id AND cm.user_id = p_user_id
                       -- GUEST_HISTORY_FLOOR: chat_message_edit
                       AND m.seq > COALESCE(cm.history_floor_seq, 0)
                       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only the author may edit this message'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- A4a Task 3: chained ACT, never message content — the prior body is
    -- already evidenced by the chat_message_revisions insert above; the chain
    -- row just proves an edit act happened, at what seq, by whom. Inert
    -- (zero rows) while feature.chat_compliance is OFF (risk-4 rail: this is
    -- an act write, not a per-send hot-path cost).
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_channel_id, 'message.edit',
          'message', p_message_id, NULL, jsonb_build_object('seq', v_seq), NULL, NULL);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'message_edited', p_message_id, v_seq);
    RETURN v_seq;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chat_message_delete(
    p_user_id bigint, p_message_id bigint
) RETURNS bigint AS $$
DECLARE
    v_channel_id bigint;
    v_deleted    timestamptz;
    v_seq        bigint;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    SELECT channel_id, deleted_at INTO v_channel_id, v_deleted
      FROM chat_messages WHERE id = p_message_id;
    -- one code for "doesn't exist" and "already deleted" (BZ167, same
    -- anti-oracle posture as edit) — a double-delete must not re-stamp seq,
    -- re-fire the message_deleted notify, or clobber the original deleted_at
    -- evidence timestamp with a fresh now().
    IF v_channel_id IS NULL OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'author or channel owner/admin required'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- Same anti-oracle order as edit: authorize the CURRENT, history-visible
    -- target before an archived-channel error may disclose its channel.
    IF NOT EXISTS (
      SELECT 1 FROM chat_messages m
      JOIN chat_channel_members cm
        ON cm.channel_id = m.channel_id AND cm.user_id = p_user_id
     WHERE m.id = p_message_id AND m.deleted_at IS NULL
       AND (m.author_id = p_user_id OR cm.role IN ('owner', 'admin'))
       AND m.seq > COALESCE(cm.history_floor_seq, 0)
       AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
    ) THEN
        RAISE EXCEPTION 'author or channel owner/admin required'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- C1: body RETAINED — only deleted_at is set. A compliance product must
    -- never destroy content at user-delete time; real purge is A4 retention's
    -- job. seq is re-stamped exactly like send/edit so since(seq) replays the
    -- tombstone instead of silently leaving a stale live copy behind.
    -- archive = read-only, same fold-into-the-row-lock treatment as edit.
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id AND NOT is_archived RETURNING change_seq INTO v_seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'channel is archived (read-only)'
            USING ERRCODE='BZ171', HINT='{"type":"forbidden"}';
    END IF;
    -- R3: ownership (author, OR a CURRENT owner/admin — a member removed via
    -- chat_member_remove can no longer delete their own old messages either)
    -- AND deleted_at IS NULL folded into the same WHERE as the mutation — no
    -- check-then-act window where a concurrent chat_member_remove or a
    -- concurrent double-delete/edit could slip a stale authorization through.
    UPDATE chat_messages m SET deleted_at = now(), seq = v_seq
      WHERE m.id = p_message_id
        AND m.deleted_at IS NULL
        AND EXISTS (
          SELECT 1 FROM chat_channel_members cm
           WHERE cm.channel_id = m.channel_id AND cm.user_id = p_user_id
             AND (m.author_id = p_user_id OR cm.role IN ('owner', 'admin'))
             -- GUEST_HISTORY_FLOOR: chat_message_delete
             AND m.seq > COALESCE(cm.history_floor_seq, 0)
             AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)
        );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'author or channel owner/admin required'
            USING ERRCODE='BZ167', HINT='{"type":"forbidden"}';
    END IF;
    -- Review blocker fix (chat_pin.sql Task 3): soft-delete closes any pin,
    -- mirroring the poll-anchor-soft-delete posture (chat_poll.sql, Task 9)
    -- — a pin on a message nobody can see is dead weight, not a curation
    -- record. Without this, chat_pin_toggle's BZ169 "message not
    -- found/deleted" guard fires before the toggle can ever run, so the pin
    -- row survives forever and no member/admin/owner can unpin it (a
    -- routine moderation delete of a pinned message would otherwise leave a
    -- permanently stuck pin — chat_message_pins is current-state-only, so
    -- there is no history to preserve here; the tombstoned message itself
    -- still carries the pin/unpin acts once A4's audit chain lands).
    DELETE FROM chat_message_pins WHERE message_id = p_message_id;
    -- A4a Task 3: chained ACT (same posture as edit above).
    IF COALESCE((SELECT enabled FROM feature_toggles
                 WHERE key = 'feature.chat_compliance'), FALSE) THEN
        PERFORM chat_access_audit(p_user_id, v_channel_id, 'message.delete',
          'message', p_message_id, NULL, jsonb_build_object('seq', v_seq), NULL, NULL);
    END IF;
    PERFORM notify_chat_state(v_channel_id, 'message_deleted', p_message_id, v_seq);
    RETURN v_seq;
END;
$$ LANGUAGE plpgsql;

-- Single-source row projection (message_to_jmap_email pattern): every reader
-- below (list/thread/since) builds the SAME jsonb shape off this one
-- function, so the reactions/mentionsMe/replyCount/body-blanking logic can
-- never drift between callers the way two hand-maintained blocks would.
-- STABLE (not IMMUTABLE): reads chat_message_reactions/chat_mentions/
-- chat_messages, so it depends on more than its own row argument.
CREATE OR REPLACE FUNCTION chat_message_to_json(p_row chat_messages, p_user_id bigint)
RETURNS jsonb AS $$
    SELECT jsonb_build_object(
      'messageId', p_row.id,
      'channelId', p_row.channel_id,
      'seq', p_row.seq,
      -- Pillar C1 Task 3: author_id is nullable since V139 — a federated
      -- inbound message (Task 4) has NO local author, only a remote
      -- address. jsonb_build_object already projects a SQL NULL as a JSON
      -- null here (no CASE needed to be "null-safe" — it always was), so
      -- this line is UNCHANGED; the null-safety is the reader's job below.
      'authorId', p_row.author_id,
      -- Guest G2: identity lifecycle is derived from the durable satellite,
      -- never membership or email-domain inference. Historical authors stay
      -- External after removal; persisted or effective expiry renders Removed.
      'authorExternal', is_guest_account(p_row.author_id),
      'authorRemoved', EXISTS (
        SELECT 1 FROM guest_account_status(p_row.author_id) gs
         WHERE gs.status IN ('disabled','expired')
            OR (gs.expires_at IS NOT NULL AND gs.expires_at <= now())
      ),
      'federatedSenderAddr', p_row.federated_sender_addr,
      'deliveredAt', p_row.delivered_at,
      'spamQuarantined', p_row.spam_quarantined,
      'parentMessageId', p_row.parent_message_id,
      'msgType', p_row.msg_type,
      'broadcast', p_row.broadcast,
      -- soft-deleted messages retain body in the row (C1); the PROJECTION
      -- blanks it for every reader.
      'body', CASE WHEN p_row.deleted_at IS NOT NULL THEN '' ELSE p_row.body END,
      -- A3 Task 6: payload (voice durationMs, poll pollId, …) gets the SAME
      -- soft-delete blanking as body/attachments — without it, a deleted
      -- voice/poll message's structured data would keep leaking through
      -- every read path.
      'payload', CASE WHEN p_row.deleted_at IS NOT NULL THEN NULL ELSE p_row.payload END,
      'editedAt', p_row.edited_at,
      'deletedAt', p_row.deleted_at,
      'createdAt', p_row.created_at,
      -- A3 Task 3: current-state pin flag (chat_message_pins, channel-scoped
      -- curation). Re-stamped seq means a client that missed the live
      -- message_pinned push still heals this via ordinary since(seq) replay.
      'pinned', EXISTS (SELECT 1 FROM chat_message_pins
                          WHERE channel_id = p_row.channel_id AND message_id = p_row.id),
      'reactions', COALESCE((
        SELECT jsonb_agg(jsonb_build_object('emoji', r.emoji, 'count', r.n, 'mine', r.mine)
                          ORDER BY r.emoji)
          FROM (SELECT emoji, count(*) n, bool_or(user_id = p_user_id) mine
                  FROM chat_message_reactions WHERE message_id = p_row.id GROUP BY emoji) r
      ), '[]'::jsonb),
      'mentionsMe', EXISTS (SELECT 1 FROM chat_mentions
                             WHERE message_id = p_row.id AND mentioned_user_id = p_user_id),
      'replyCount', (SELECT count(*) FROM chat_messages c2
                      JOIN chat_channel_members cm
                        ON cm.channel_id = c2.channel_id AND cm.user_id = p_user_id
                     WHERE c2.parent_message_id = p_row.id AND c2.deleted_at IS NULL
                       AND c2.seq > COALESCE(cm.history_floor_seq, 0)
                       AND (cm.history_floor_seq IS NULL OR c2.created_at >= cm.joined_at)),
      'lastReplyAt', (SELECT max(c3.created_at) FROM chat_messages c3
                       JOIN chat_channel_members cm
                         ON cm.channel_id = c3.channel_id AND cm.user_id = p_user_id
                      WHERE c3.parent_message_id = p_row.id AND c3.deleted_at IS NULL
                        AND c3.seq > COALESCE(cm.history_floor_seq, 0)
                        AND (cm.history_floor_seq IS NULL OR c3.created_at >= cm.joined_at)),
      -- Chat A2 Task 3: link rows are retained on soft-delete (C1 evidence
      -- posture — same as the body), but the PROJECTION hides them, same
      -- treatment as the body-blank above.
      'attachments', CASE WHEN p_row.deleted_at IS NOT NULL THEN '[]'::jsonb ELSE COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
                 'id', a.id, 'fileNodeId', a.file_node_id, 'filename', a.filename,
                 'contentType', a.content_type, 'sizeBytes', a.size_bytes)
                ORDER BY a.ordinal)
          FROM chat_message_attachments a WHERE a.message_id = p_row.id
      ), '[]'::jsonb) END
    );
$$ LANGUAGE sql STABLE;

-- Design F8: top-level only (parent_message_id IS NULL) — thread replies
-- never appear in the channel timeline, only via the parent's replyCount /
-- chat_thread_list. Newest-first keyset on seq (p_before_seq, drive_activity_
-- feed's before_id pagination shape).
--
-- A3 QoL Task 10: p_around_seq is the jump-to-message substrate for
-- search/pins/saves/My-Threads click-throughs (Task 14's openChannelAt) — a
-- SEPARATE mode, not a filter combined with p_before_seq. When given, p_limit
-- is read as "N per side" (not a total page size): the window is the target
-- row itself plus up to p_limit rows immediately before it and up to
-- p_limit immediately after, ascending by seq (oldest first, matching a
-- normal scroll-down reading order) so the caller can render it directly
-- without a client-side reverse. A target near either end of the channel
-- returns fewer rows on that side — no phantom padding.
DROP FUNCTION IF EXISTS chat_messages_list(bigint,bigint,bigint,int);
CREATE OR REPLACE FUNCTION chat_messages_list(
    p_user_id bigint, p_channel_id bigint,
    p_before_seq bigint DEFAULT NULL, p_limit int DEFAULT 50,
    p_around_seq bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_lim  int;
    v_floor bigint;
    v_joined_at timestamptz;
BEGIN
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    v_lim := LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);
    IF p_around_seq IS NOT NULL THEN
        RETURN COALESCE((
          SELECT jsonb_agg(chat_message_to_json(m, p_user_id) ORDER BY m.seq ASC)
            FROM (
              (SELECT * FROM chat_messages
                WHERE channel_id = p_channel_id AND parent_message_id IS NULL
                  -- GUEST_HISTORY_FLOOR: chat_messages_list
                  AND seq > COALESCE(v_floor, 0)
                  AND (v_floor IS NULL OR created_at >= v_joined_at)
                  AND seq < p_around_seq
                ORDER BY seq DESC LIMIT v_lim)
              UNION ALL
              (SELECT * FROM chat_messages
                WHERE channel_id = p_channel_id AND parent_message_id IS NULL
                  AND seq > COALESCE(v_floor, 0)
                  AND (v_floor IS NULL OR created_at >= v_joined_at)
                  AND seq = p_around_seq)
              UNION ALL
              (SELECT * FROM chat_messages
                WHERE channel_id = p_channel_id AND parent_message_id IS NULL
                  AND seq > COALESCE(v_floor, 0)
                  AND (v_floor IS NULL OR created_at >= v_joined_at)
                  AND seq > p_around_seq
                ORDER BY seq ASC LIMIT v_lim)
            ) m
        ), '[]'::jsonb);
    END IF;
    RETURN COALESCE((
      SELECT jsonb_agg(chat_message_to_json(m, p_user_id) ORDER BY m.seq DESC)
        FROM (
          SELECT * FROM chat_messages
           WHERE channel_id = p_channel_id
             AND parent_message_id IS NULL
             -- GUEST_HISTORY_FLOOR: chat_messages_list
             AND seq > COALESCE(v_floor, 0)
             AND (v_floor IS NULL OR created_at >= v_joined_at)
             AND (p_before_seq IS NULL OR seq < p_before_seq)
           ORDER BY seq DESC
           LIMIT v_lim
        ) m
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;

-- Root + its replies, ascending. Membership resolved off the PARENT's
-- channel (a thread never crosses channels).
CREATE OR REPLACE FUNCTION chat_thread_list(
    p_user_id bigint, p_parent_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_channel_id bigint;
    v_floor bigint;
    v_joined_at timestamptz;
    v_parent_visible boolean;
BEGIN
    SELECT channel_id INTO v_channel_id FROM chat_messages WHERE id = p_parent_id;
    IF v_channel_id IS NULL THEN
        RAISE EXCEPTION 'thread parent not found'
            USING ERRCODE='BZ165', HINT='{"type":"notFound"}';
    END IF;
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = v_channel_id AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', v_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    SELECT m.seq > COALESCE(v_floor, 0)
           AND (v_floor IS NULL OR m.created_at >= v_joined_at)
      INTO v_parent_visible FROM chat_messages m WHERE m.id = p_parent_id;
    IF NOT v_parent_visible THEN
        RAISE EXCEPTION 'thread parent not found'
            USING ERRCODE='BZ165', HINT='{"type":"notFound"}';
    END IF;
    RETURN COALESCE((
      SELECT jsonb_agg(chat_message_to_json(m, p_user_id) ORDER BY m.seq ASC)
        FROM (
          SELECT * FROM chat_messages WHERE id = p_parent_id
          UNION ALL
          SELECT * FROM chat_messages WHERE parent_message_id = p_parent_id
            -- GUEST_HISTORY_FLOOR: chat_thread_list
            AND seq > COALESCE(v_floor, 0)
            AND (v_floor IS NULL OR created_at >= v_joined_at)
        ) m
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;

-- The reconnect/replay path (H2): ALL rows incl. replies + edit/delete
-- tombstones, seq > p_since_seq ascending. seq order == commit order by
-- construction (send/edit/delete all re-stamp seq under the channel row
-- lock), so this can never skip a late-committing or just-mutated row.
-- Guest G2 cursor contract: a visible post-floor reply whose parent is below
-- the caller's floor is replayed as a DETACHED row (`parentMessageId:null`,
-- `parentUnavailable:true`). The reply's own content and seq are visible,
-- while the parent id/thread remain undisclosed; critically, the client's
-- max-row cursor advances past the committed channel seq instead of polling
-- the same hidden edge forever.
CREATE OR REPLACE FUNCTION chat_messages_since(
    p_user_id bigint, p_channel_id bigint, p_since_seq bigint
) RETURNS jsonb AS $$
DECLARE
    v_floor bigint;
    v_joined_at timestamptz;
BEGIN
    SELECT history_floor_seq, joined_at INTO v_floor, v_joined_at
      FROM chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    RETURN COALESCE((
      SELECT jsonb_agg(
               CASE WHEN m.parent_message_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM chat_messages parent
                     WHERE parent.id = m.parent_message_id
                       AND parent.seq > COALESCE(v_floor, 0)
                       AND (v_floor IS NULL OR parent.created_at >= v_joined_at))
                 THEN chat_message_to_json(m, p_user_id)
                      || jsonb_build_object('parentMessageId', NULL, 'parentUnavailable', true)
                 ELSE chat_message_to_json(m, p_user_id)
               END
               ORDER BY m.seq ASC)
        FROM (
          SELECT * FROM chat_messages
           WHERE channel_id = p_channel_id AND seq > COALESCE(p_since_seq, 0)
             -- GUEST_HISTORY_FLOOR: chat_messages_since
             AND seq > COALESCE(v_floor, 0)
             AND (v_floor IS NULL OR created_at >= v_joined_at)
           ORDER BY seq ASC
        ) m
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE;
