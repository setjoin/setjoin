-- federation_peer_set.sql — Pillar C1 Task 8: the admin allow-list/anchor
-- console's writer. The ONE place a federation_allowlist row is created or
-- updated (peer_domain/peer_anchor/scope/enabled) from the admin console —
-- writes a tamper-evident admin_audit_log act (anchor FINGERPRINT only,
-- NEVER the PEM) and wakes the (Task 5) federation.Service reconcile loop
-- via app_notify('federation_allowlist_changed', …) so a live peer add/
-- enable/disable takes effect without a restart.
--
-- SECURITY DEFINER + apply_worker_ownership + pinned search_path, matching
-- every other federation_* writer: federation_allowlist is FORCE RLS
-- deny-all-to-setjoin_app (V138) — an invoker-rights UPSERT would silently
-- affect zero rows.
--
-- Validation here is DELIBERATELY SHALLOW — non-empty domain, scope IN
-- ('dm','room'), anchor is PEM-shaped (starts a CERTIFICATE block). The real
-- x509 parse (does it actually decode, is the structure sane) happens
-- Go-side (admin_federation.go) BEFORE this reducer is ever called, the same
-- split chat_message_send's 64KiB mirror of the inbound applier's own cap
-- uses: this is a defense-in-depth backstop for a caller that skips the Go
-- layer, not the primary gate. Self-domain refusal is ALSO Go-side
-- (FEDERATION_LOCAL_DOMAIN is env config, not a DB fact this reducer can
-- see) — deliberately not duplicated here.
CREATE OR REPLACE FUNCTION federation_peer_set(
    p_actor      bigint,
    p_domain     text,
    p_anchor_pem text,
    p_scope      text,
    p_enabled    boolean
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_domain      text := lower(btrim(COALESCE(p_domain, '')));
  v_fingerprint text;
BEGIN
  IF v_domain = '' THEN
    RAISE EXCEPTION 'federation: peer domain is required'
      USING ERRCODE='BZ207',
            HINT='{"type":"invalidArguments","detail":"peer domain is required"}';
  END IF;

  IF p_scope NOT IN ('dm', 'room') THEN
    RAISE EXCEPTION 'federation: invalid scope %', p_scope
      USING ERRCODE='BZ207',
            HINT='{"type":"invalidArguments","detail":"scope must be dm or room"}';
  END IF;

  IF p_anchor_pem IS NULL OR position('-----BEGIN CERTIFICATE-----' IN p_anchor_pem) = 0 THEN
    RAISE EXCEPTION 'federation: anchor is not a PEM-encoded certificate'
      USING ERRCODE='BZ207',
            HINT='{"type":"invalidArguments","detail":"anchor must be a PEM-encoded certificate"}';
  END IF;

  INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
    VALUES (v_domain, p_anchor_pem, p_scope, COALESCE(p_enabled, false))
    ON CONFLICT (peer_domain) DO UPDATE
      SET peer_anchor = EXCLUDED.peer_anchor,
          scope        = EXCLUDED.scope,
          enabled      = EXCLUDED.enabled,
          updated_at   = now();

  -- Fingerprint, never the PEM: audit_write's after_state is a durable,
  -- widely-readable (audit.read) row — the anchor material itself must
  -- never land there.
  v_fingerprint := encode(digest(p_anchor_pem, 'sha256'), 'hex');

  PERFORM audit_write(
    p_actor, 'federation.peer_set', 'federation_peer', NULL,
    NULL,
    jsonb_build_object('domain', v_domain, 'scope', p_scope, 'enabled', COALESCE(p_enabled, false),
                        'anchorFingerprint', v_fingerprint),
    NULL, v_domain, 'core'
  );

  PERFORM app_notify('federation_allowlist_changed',
                      jsonb_build_object('peerDomain', v_domain)::text);
END;
$$;
SELECT apply_worker_ownership('federation_peer_set(bigint,text,text,text,boolean)'::regprocedure);
