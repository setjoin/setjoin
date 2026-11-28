-- federation_dm_ensure.sql — Pillar C1 Task 2: the outbound federated-DM
-- channel constructor. The ONLY place a chat_channels row with
-- federated_peer_domain IS NOT NULL gets created on the SENDING side (Task
-- 4's inbound applier lazily creates the MIRROR channel on the receiving
-- side via the same shape, but that is its own reducer — this file is
-- outbound-only).
--
-- Local refusal gate: reuses federation_peer_authorize (C0, Task 3/E4) for
-- the actual "is this peer domain locally allow-listed+enabled for dm scope"
-- check — never re-reads federation_allowlist directly, because that table
-- is FORCE RLS deny-all to setjoin_app (V138) and a direct SELECT under
-- invoker rights would just silently see zero rows (falsely refusing every
-- domain, allow-listed or not). federation_peer_authorize is SECURITY
-- DEFINER + worker-owned so it can see the table; its raise is BZ203 (the
-- wire-handshake code). This reducer's own caller (chat's DM-compose path,
-- Task 3) needs a DISTINCT code — BZ204 — so catch-and-reraise.
--
-- federated_local_key: hash(lower(sorted(local_addr, remote_addr))) — the
-- SAME symmetric derivation Task 4's inbound applier recomputes from
-- (toAddr, fromAddr) server-side (never trusts a stanza-carried key — the
-- plan's "Identity, keys, and the one poison-proof invariant" section).
-- least()/greatest() on the two lowered addresses gives an order-independent
-- pair regardless of which side initiated.
--
-- Declared PLAIN (invoker rights), NOT SECURITY DEFINER — deliberately NOT
-- the chat_dm_open shape. chat_dm_open needs DEFINER because it writes OTHER
-- people's chat_channel_members rows (cross-member inserts no invoker-rights
-- WITH CHECK can admit). A federated DM has exactly ONE local member: the
-- caller themselves. chat_channels_insert's WITH CHECK (created_by = caller)
-- and chat_members_scope's WITH CHECK (... OR user_id = caller) both already
-- admit a self-only write — the SAME shape chat_channel_create (also plain,
-- also invoker-rights) relies on for its own founding member row. The one
-- FORCE-RLS-gated read (federation_allowlist) is delegated to the existing
-- DEFINER helper above, so no privilege escalation is needed in this file.
--
-- Dedup (H3/F5 genre, chat_dm_open's own TOCTOU-race precedent):
-- chat_channels_federated_key_uk (V139) is the arbiter; ON CONFLICT DO
-- NOTHING + a re-SELECT on a lost race. A losing concurrent call blocks on
-- the unique index until the winner's transaction commits (the winner's own
-- chat_channel_members insert lands in that SAME transaction), so by the
-- time the loser's re-SELECT runs under chat_channels_read's membership-
-- scoped policy, the row is already visible to it — this can only race two
-- calls for the SAME local user (the key is keyed on that user's own
-- address), so the loser is always looking at ITS OWN membership.
CREATE OR REPLACE FUNCTION federation_dm_ensure(
    p_local_user  bigint,
    p_remote_addr text
) RETURNS bigint AS $$
DECLARE
    v_domain      text;
    v_local_addr  text;
    v_key         text;
    v_id          bigint;
BEGIN
    -- P12: a guest may never open a federated DM (denied twice over — the P8
    -- chat_dm_open door and this federation-side refusal; the distinct
    -- POST /chat/dm/federated route reaches only this reducer).
    IF is_guest_account(p_local_user) THEN
        RAISE EXCEPTION 'guest accounts cannot open federated DMs'
            USING ERRCODE='BZ216', HINT='{"type":"forbidden","detail":"guests are excluded from federation (residency)"}';
    END IF;

    v_domain := lower(split_part(COALESCE(p_remote_addr, ''), '@', 2));

    -- reuse federation_peer_authorize's mutual-opt-in check for 'dm' scope;
    -- re-raise its BZ203 as this reducer's own BZ204 (a distinct code for a
    -- distinct caller: BZ203 is the wire-handshake refusal, BZ204 is "you
    -- tried to open a DM to a peer this org hasn't allow-listed").
    BEGIN
        PERFORM federation_peer_authorize(v_domain, 'dm');
    EXCEPTION WHEN SQLSTATE 'BZ203' THEN
        RAISE EXCEPTION 'federation: peer % is not locally allow-listed/enabled for DM', v_domain
            USING ERRCODE='BZ204',
                  HINT='{"type":"forbidden","detail":"peer domain not allow-listed/enabled for federated DM"}';
    END;

    v_local_addr := (SELECT lower(email) FROM users WHERE id = p_local_user);
    v_key := encode(digest(
        least(v_local_addr, lower(p_remote_addr)) || ':' || greatest(v_local_addr, lower(p_remote_addr)),
        'sha256'), 'hex');

    INSERT INTO chat_channels (kind, federated_peer_domain, federated_remote_id, federated_local_key, member_key, created_by)
      VALUES ('dm', v_domain, p_remote_addr, v_key, NULL, p_local_user)
      ON CONFLICT (federated_peer_domain, federated_local_key) WHERE federated_peer_domain IS NOT NULL DO NOTHING
      RETURNING id INTO v_id;
    IF v_id IS NULL THEN
        -- lost the race (or a plain repeat call): re-select the existing row.
        SELECT id INTO v_id FROM chat_channels
         WHERE federated_peer_domain = v_domain AND federated_local_key = v_key;
        RETURN v_id;
    END IF;

    -- sole local member; the remote party is identity metadata on the
    -- channel row itself (federated_remote_id), never a chat_channel_members
    -- row (Global Constraints — the remote party is NEVER a local account,
    -- member row, directory/GAL entry, or users row).
    INSERT INTO chat_channel_members (channel_id, user_id, role)
      VALUES (v_id, p_local_user, 'owner');

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
