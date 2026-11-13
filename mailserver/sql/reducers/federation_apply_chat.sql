-- federation_apply_chat.sql — Pillar C1 Task 4: the inbound chat<->
-- federation bridge. Runs on the worker/BYPASSRLS pool, called by
-- internal/federation/receiver.go for every inbound KindMsg frame whose
-- content_type is 'application/x-setjoin-chat' (receiver.go dispatches by
-- content_type; anything else still rides federation_apply_inbound, the C0
-- spike path, unchanged).
--
-- ── THE POISON-PROOF INVARIANT (plan's "Identity, keys, and the one
--    poison-proof invariant" section — read it before touching this file) ──
--
-- Two independent contracts share this one function, and they must never be
-- allowed to fight each other:
--
--   1. Exactly-once/in-order bookkeeping (verbatim the C0
--      federation_apply_inbound rail): dedup on (peer_domain, peer_seq),
--      BZ202 on a gap, cursor advance under the row lock. This part is
--      UNCHANGED — copy-pasted, not reinvented — because C0 already proved
--      it live (p50=41ms, exactly-once across crash/reconnect).
--
--   2. Content trust validation (NEW here): fromAddr's domain must match the
--      stream-authenticated p_peer_domain, toAddr must resolve to a real
--      enabled local user, the payload must be well-formed, the body must
--      fit the 64KiB cap. A failure here is POISON — logged, dropped, NEVER
--      escalated to a Postgres exception.
--
-- THE RULE: bookkeeping's gap check (BZ202) is the ONLY RAISE EXCEPTION in
-- this whole function. Every trust-validation failure returns 'poison'
-- through the ORDINARY function-return path, with the peer_seq ALREADY
-- consumed and the cursor ALREADY advanced (both happen before any content
-- is even looked at). Why: a RAISE EXCEPTION aborts the enclosing
-- transaction, which unwinds the cursor advance too — the sender would then
-- resend the exact same poisoned frame forever (it thinks it was never
-- acked), and the receiver would poison it identically forever. That is a
-- permanent livelock, not a security control. Poison-as-a-return-value keeps
-- the message flow moving: the bad frame is consumed exactly once and
-- dropped, the stream stays healthy, and the caller still sends KindAck (a
-- poisoned frame is, from the wire's point of view, successfully processed
-- — it just didn't get to write a chat_messages row).
--
-- The SAME logic applies to a chat_messages federated_stanza_id collision
-- (a resend of a clientMsgId the local side already landed, arriving this
-- time under a genuinely NEW peer_seq — the sender's retry/reconnect logic,
-- not a protocol violation): the insert below is
-- `ON CONFLICT (channel_id, federated_origin_domain, federated_stanza_id)
-- DO NOTHING` (the V140/C2 Task 1 dedup fix — re-scoped from the old
-- 2-column arbiter so two different origins' colliding stanza ids in one
-- channel no longer silently drop one), never a bare INSERT that would let
-- chat_messages_fed_stanza_uk (V140) raise 23505 and abort the transaction
-- — that abort would be the EXACT SAME livelock shape
-- as #2 above, just triggered by a duplicate content id instead of a bad
-- domain. The verdict for this case is 'applied' (the seq/cursor already
-- moved, the row already exists — nothing left to poison), not 'poison'.
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership) — matching every
-- other federation_* reducer: federation_inbox/federation_inbox_cursor are
-- FORCE RLS deny-all-to-setjoin_app, and this call also needs to see
-- mailboxes/users (to resolve toAddr) and write chat_channels/
-- chat_channel_members/chat_messages on behalf of a user who is NOT the
-- invoking role (there is no "invoking user" here at all — this runs off
-- the wire, not an HTTP request).
--
-- Task 4B (inbound spam-scan) adds p_spam_quarantined/p_spam_reason: the
-- Go receiver (receiver.go's handleChat) runs the shared/spam TEXT-
-- APPLICABLE detectors on the decoded body BEFORE this call (a reducer
-- can't call Go) and hands the verdict in. Quarantine-on-apply, never
-- skip-or-poison: the two columns are landed on the SAME chat_messages
-- INSERT the valid-apply branch already does (Step 3 below) — the
-- exactly-once/poison contract above is completely untouched, quarantine
-- is orthogonal, a flag on an otherwise-normal apply. DEFAULTed to
-- false/NULL (not made mandatory-no-default) so the whole Task 4 poison-
-- edge test suite below, which predates this task and calls the 4-arg
-- form, keeps working byte-for-byte — ponytail: the smaller diff over a
-- 9-call-site test rewrite, and functionally identical either way since
-- receiver.go (the one production caller) always passes all six.
-- Task 4B widens the arg list (4 params -> 6): CREATE OR REPLACE cannot
-- change an existing function's parameter list — Postgres identifies a
-- function by name+input-arg-types, so a bare CREATE OR REPLACE here would
-- silently leave the OLD 4-arg federation_apply_chat(text,bigint,text,jsonb)
-- lingering as a second overload instead of replacing it. Drop it first.
DROP FUNCTION IF EXISTS federation_apply_chat(text, bigint, text, jsonb);

CREATE OR REPLACE FUNCTION federation_apply_chat(
    p_peer_domain       text,
    p_peer_seq          bigint,
    p_stanza_id         text,
    p_payload           jsonb,
    p_spam_quarantined  boolean DEFAULT false,
    p_spam_reason       text    DEFAULT NULL
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_last          bigint;
  v_from_raw      text;
  v_to_raw        text;
  v_from_addr     text;   -- lowercased, for domain/key/mailbox comparisons
  v_to_addr       text;   -- lowercased, ditto
  v_body          text;
  v_client_msg_id text;
  v_to_user_id    bigint;
  v_key           text;
  v_channel_id    bigint;
  v_seq           bigint;
  v_msg_id        bigint;
BEGIN
  -- ══════════════════════════════════════════════════════════════════════
  -- Step 1: exactly-once bookkeeping FIRST, unchanged from
  -- federation_apply_inbound — this runs BEFORE any content is even parsed,
  -- so a dup or a gap is decided purely from (peer_domain, peer_seq),
  -- independent of whatever garbage might be sitting in p_payload.
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

  -- Task 8 Step 2 (the cursor-regression guard — federation_reap.sql's
  -- header names this as the gap it closes): the PK-EXISTS check above only
  -- catches a dup whose federation_inbox row still exists. Once the reaper
  -- (federation_reap) deletes old applied rows, a replayed/malicious
  -- p_peer_seq at-or-below the cursor would fall through that check
  -- entirely — and without this guard, the gap check below is silent (it
  -- only fires on p_peer_seq TOO HIGH) and the unconditional cursor SET
  -- further down would move last_applied_seq BACKWARD. Any already-passed
  -- seq (<=, not just <, since an exact match with its row already reaped
  -- must ALSO dup rather than re-apply) is a dup, full stop — cursor left
  -- untouched, no write below this point.
  IF p_peer_seq <= v_last THEN
    RETURN 'dup';
  END IF;

  IF p_peer_seq > v_last + 1 THEN
    RAISE EXCEPTION 'federation: sequence gap for peer % — got % expected %',
      p_peer_domain, p_peer_seq, v_last + 1
      USING ERRCODE='BZ202',
            HINT='{"type":"conflict","detail":"sequence gap — replay required"}';
  END IF;

  -- envelope-only inbox row (C1 delta from federation_apply_inbound): the
  -- body now lives in chat_messages, so storing it a second time here would
  -- be a needless duplicate copy of user content sitting in a deny-all
  -- infra table nobody reads for record-keeping purposes. `->>` on a
  -- key that's missing/wrong-typed returns SQL NULL, never errors — safe to
  -- call before any well-formedness check below.
  INSERT INTO federation_inbox (peer_domain, peer_seq, stanza_id, content_type, payload)
    VALUES (p_peer_domain, p_peer_seq, p_stanza_id, 'application/x-setjoin-chat',
            jsonb_build_object('fromAddr', p_payload->>'fromAddr',
                                'toAddr', p_payload->>'toAddr',
                                'clientMsgId', p_payload->>'clientMsgId'));

  UPDATE federation_inbox_cursor SET last_applied_seq = p_peer_seq, updated_at = now()
    WHERE peer_domain = p_peer_domain;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 2: trust validations. From here on, EVERY failure is 'poison' —
  -- the seq/cursor above are already committed-in-this-txn, so returning
  -- (rather than raising) is what makes the drop durable exactly once.
  -- ══════════════════════════════════════════════════════════════════════
  v_from_raw      := NULLIF(btrim(p_payload->>'fromAddr'), '');
  v_to_raw        := NULLIF(btrim(p_payload->>'toAddr'), '');
  v_body          := p_payload->>'body';
  v_client_msg_id := NULLIF(btrim(p_payload->>'clientMsgId'), '');

  -- (iv) malformed: any required key missing/empty. Checked first — every
  -- later check dereferences one of these values, so a NULL here must never
  -- reach them.
  IF v_from_raw IS NULL OR v_to_raw IS NULL OR v_body IS NULL OR v_client_msg_id IS NULL THEN
    RAISE NOTICE 'federation: poison — malformed chat payload from peer % seq %',
      p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- (review fold, F1) clientMsgId feeds chat_messages_fed_stanza_uk, a
  -- PARTIAL btree index on (channel_id, federated_origin_domain,
  -- federated_stanza_id) — an attacker-controlled value with no length cap
  -- can blow past Postgres's ~2.7KB btree index-row ceiling ("index row size
  -- exceeds btree maximum", SQLSTATE 54000). That failure is NOT caught by
  -- this function's poison-return contract: it fires deep inside the INSERT
  -- in Step 3, AFTER the seq/cursor advance above already committed, so it
  -- aborts and unwinds that advance too — the exact livelock this file's
  -- header explains, just triggered by index-row size instead of a bad
  -- domain. Capped well under the ceiling; poison, never a raise.
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
  v_to_addr   := lower(v_to_raw);

  -- (i) anti-spoof: bravo cannot assert mallory@charlie or ceo@alpha —
  -- fromAddr's domain MUST equal the domain this stream was authenticated
  -- as at handshake time (p_peer_domain, verified against the presented
  -- client cert — stream.go, never trusted from the payload itself).
  IF split_part(v_from_addr, '@', 2) <> lower(p_peer_domain) THEN
    RAISE NOTICE 'federation: poison — spoofed fromAddr domain (got %, stream peer %)',
      split_part(v_from_addr, '@', 2), p_peer_domain;
    RETURN 'poison';
  END IF;

  -- (iii) size cap — mirrors chat_message_send's federated-branch BZ206 cap
  -- (chat_message.sql), so a compliant local sender's own cap and this
  -- side's inbound cap can never disagree about what "too big" means.
  IF octet_length(v_body) > 65536 THEN
    RAISE NOTICE 'federation: poison — body over 64KiB from peer % seq %',
      p_peer_domain, p_peer_seq;
    RETURN 'poison';
  END IF;

  -- (ii) toAddr must resolve to a real, enabled local user — join
  -- mailboxes/users on the lowercased address (mailboxes_email_lower_idx,
  -- the deliver_group_vacation.sql precedent), require the mailbox to be
  -- both enabled and receive_enabled (this IS an inbound-delivery check)
  -- and the user account itself enabled. A shared/resource mailbox with no
  -- owning user_id can never receive a federated DM (mb.user_id IS NOT NULL
  -- is enforced by the JOIN itself since users.id is NOT NULL).
  SELECT mb.user_id INTO v_to_user_id
    FROM mailboxes mb JOIN users u ON u.id = mb.user_id
   WHERE lower(mb.email) = v_to_addr
     AND mb.enabled AND mb.receive_enabled AND u.enabled
   LIMIT 1;

  IF v_to_user_id IS NULL THEN
    RAISE NOTICE 'federation: poison — toAddr % does not resolve to a real enabled local user',
      v_to_addr;
    RETURN 'poison';
  END IF;

  -- ══════════════════════════════════════════════════════════════════════
  -- Step 3: valid — lazily mirror the channel, land the message.
  -- ══════════════════════════════════════════════════════════════════════

  -- federated_local_key recomputed SERVER-SIDE from (toAddr, fromAddr) —
  -- NEVER read from the stanza (the invariant). Identical formula to
  -- federation_dm_ensure.sql's outbound side: least/greatest on the two
  -- lowered addresses gives an order-independent pair, so this side's
  -- "local vs remote" (to vs from) hashes to the SAME key the sender
  -- computed with ITS "local vs remote" (from vs to).
  v_key := encode(digest(
      least(v_to_addr, v_from_addr) || ':' || greatest(v_to_addr, v_from_addr),
      'sha256'), 'hex');

  INSERT INTO chat_channels (kind, federated_peer_domain, federated_remote_id, federated_local_key, member_key, created_by)
    VALUES ('dm', lower(p_peer_domain), v_from_raw, v_key, NULL, v_to_user_id)
    ON CONFLICT (federated_peer_domain, federated_local_key) WHERE federated_peer_domain IS NOT NULL DO NOTHING
    RETURNING id INTO v_channel_id;

  IF v_channel_id IS NULL THEN
    SELECT id INTO v_channel_id FROM chat_channels
     WHERE federated_peer_domain = lower(p_peer_domain) AND federated_local_key = v_key;
  END IF;

  -- sole local member, seeded lazily + idempotently (ON CONFLICT DO NOTHING
  -- — this runs on every inbound message, not just the first, since the
  -- channel may pre-exist from a prior message): the remote party is
  -- identity metadata on the channel row (federated_remote_id) only, never
  -- a chat_channel_members row (Global Constraints).
  INSERT INTO chat_channel_members (channel_id, user_id, role)
    VALUES (v_channel_id, v_to_user_id, 'owner')
    ON CONFLICT (channel_id, user_id) DO NOTHING;

  -- Pre-check the stanza dedup BEFORE bumping change_seq: a clientMsgId
  -- resend under a new peer_seq (already ruled a safe no-op above) should
  -- not burn a change_seq value for a row that will never be inserted. This
  -- pre-check is race-free: the federation_inbox_cursor row lock taken in
  -- Step 1 serializes every call for THIS peer_domain for the duration of
  -- this transaction, and a federated mirror channel only ever receives
  -- writes from the one peer_domain it is bound to. The ON CONFLICT DO
  -- NOTHING below remains as the hard backstop regardless (never a bare
  -- INSERT here — see the file header).
  --
  -- V140 (C2 Task 1, THE DEDUP FIX): scoped on
  -- (channel_id, federated_origin_domain, federated_stanza_id), NOT the old
  -- 2-column (channel_id, federated_stanza_id) pair — a DM's origin IS the
  -- stream peer, so this is a no-op change of VALUE for every C1 DM row,
  -- but it re-aligns the pre-check with the re-scoped partial unique index
  -- below (a stale 2-column arbiter would match NO index and ABORT the
  -- txn on every inbound dup — the exact BZ202 livelock the arbiter exists
  -- to prevent).
  SELECT id INTO v_msg_id FROM chat_messages
   WHERE channel_id = v_channel_id AND federated_origin_domain = lower(p_peer_domain)
     AND federated_stanza_id = v_client_msg_id;

  IF v_msg_id IS NULL THEN
    UPDATE chat_channels SET change_seq = change_seq + 1
      WHERE id = v_channel_id RETURNING change_seq INTO v_seq;

    -- chat_messages_fed_stanza_uk (V140) is a PARTIAL unique index on
    -- (channel_id, federated_origin_domain, federated_stanza_id) WHERE
    -- federated_stanza_id IS NOT NULL — the ON CONFLICT arbiter must repeat
    -- that predicate verbatim, same requirement as federation_dm_ensure's
    -- own partial-UNIQUE arbiter above. federated_origin_domain is stamped
    -- here as the stream-authenticated peer (never trusted from the
    -- payload) — for a DM this origin IS the peer.
    INSERT INTO chat_messages (channel_id, seq, author_id, federated_sender_addr, federated_origin_domain, federated_stanza_id, body, spam_quarantined, spam_reason)
      VALUES (v_channel_id, v_seq, NULL, v_from_raw, lower(p_peer_domain), v_client_msg_id, v_body, COALESCE(p_spam_quarantined, false), p_spam_reason)
      ON CONFLICT (channel_id, federated_origin_domain, federated_stanza_id) WHERE federated_stanza_id IS NOT NULL DO NOTHING
      RETURNING id INTO v_msg_id;

    IF v_msg_id IS NOT NULL THEN
      PERFORM notify_chat_state(v_channel_id, 'message_created', v_msg_id, v_seq);
    END IF;
  END IF;

  RETURN 'applied';
END;
$$;
SELECT apply_worker_ownership('federation_apply_chat(text,bigint,text,jsonb,boolean,text)'::regprocedure);
