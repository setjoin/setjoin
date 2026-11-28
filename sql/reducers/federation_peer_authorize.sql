-- federation_peer_authorize.sql — Pillar C0 spike Task 3 (E4): the LOCAL
-- refusal gate wired into the Listen/AcceptStream handshake
-- (internal/federation/stream.go's authorizePeer), called AFTER anchor
-- validation, BEFORE any non-hello frame is allowed to flow.
--
-- Refuses (BZ203) unless a LOCAL federation_allowlist row for p_peer_domain
-- exists, is enabled=true, AND its scope covers p_scope: scope='room' covers
-- BOTH 'dm' and 'room' requests (a room-scoped peer may also DM); scope='dm'
-- covers ONLY 'dm'.
--
-- ADVISORY NOTE (Global Constraints — mutual opt-in): the peer's own hello
-- may assert "I allow-list you back," but that assertion carries NO
-- authority here — it is the wire-level equivalent of a stranger's say-so.
-- The ONLY authoritative check is THIS side's OWN local, enabled allow-list
-- row. True mutual opt-in emerges from BOTH sides independently running this
-- same check on their own Listen/AcceptStream (each domain refuses inbound
-- from a peer it has not itself locally enabled) — never from trusting what
-- the peer claims about its own allow-list.
--
-- SECURITY DEFINER, worker-owned (apply_worker_ownership): federation_allowlist
-- is FORCE RLS deny-all-to-setjoin_app (Global Constraints — no membership
-- axis), this reducer is the authorizing reader (Task 1's AnchorLookup is a
-- separate, narrower read of the same table, for the anchor column only).
CREATE OR REPLACE FUNCTION federation_peer_authorize(
    p_peer_domain text,
    p_scope       text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_row public.federation_allowlist%ROWTYPE;
BEGIN
  SELECT * INTO v_row FROM federation_allowlist WHERE peer_domain = p_peer_domain;

  IF NOT FOUND OR NOT v_row.enabled THEN
    RAISE EXCEPTION 'federation: peer % is not locally allow-listed/enabled', p_peer_domain
      USING ERRCODE='BZ203',
            HINT='{"type":"forbidden","detail":"peer not allow-listed or not enabled locally — mutual opt-in requires a LOCAL enabled row, the peer''s own claim carries no authority"}';
  END IF;

  IF v_row.scope = 'dm' AND p_scope <> 'dm' THEN
    RAISE EXCEPTION 'federation: peer % is allow-listed for scope dm only, refusing %', p_peer_domain, p_scope
      USING ERRCODE='BZ203',
            HINT='{"type":"forbidden","detail":"peer allow-list scope does not cover the requested scope"}';
  END IF;

  RETURN true;
END;
$$;
SELECT apply_worker_ownership('federation_peer_authorize(text,text)'::regprocedure);
