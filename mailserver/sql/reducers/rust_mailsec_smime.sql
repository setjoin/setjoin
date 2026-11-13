-- Frozen Go's admin S/MIME trust-anchor writes (admin.TrustAnchorHandler.Import and Delete) as
-- reducers. Go commits each certificate INSERT on its own and then sends the smime_trust_changed
-- notification best effort; here the whole import (every row of the uploaded bundle) and its
-- notification are one transaction. The table is global admin configuration (no RLS); the
-- gateway checks the mail.security grant and resolves the caller's domain scope from the verified
-- token before the call (0 is deployment-wide, as Go's DomainScopeFromContext).

-- One row per certificate: ON CONFLICT (fingerprint, domain_id) renames the existing row.
-- p_certs is a jsonb array of {pem, fingerprint, subject_cn, not_before, not_after} where the
-- validity bounds are Unix seconds. Returns the number of certificates stored.
CREATE OR REPLACE FUNCTION rust_mailsec_smime_anchor_import(
  p_label text, p_certs jsonb, p_domain bigint, p_actor bigint)
RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE c jsonb; n integer := 0;
BEGIN
 FOR c IN SELECT value FROM jsonb_array_elements(p_certs) LOOP
  INSERT INTO smime_trust_anchors (label, cert_pem, subject_cn, fingerprint, domain_id, not_before, not_after, created_by)
  VALUES (p_label, c->>'pem', c->>'subject_cn', c->>'fingerprint', NULLIF(p_domain, 0),
          to_timestamp((c->>'not_before')::bigint), to_timestamp((c->>'not_after')::bigint), p_actor)
  ON CONFLICT (fingerprint, domain_id) DO UPDATE SET label = EXCLUDED.label;
  n := n + 1;
 END LOOP;
 PERFORM pg_notify('smime_trust_changed', '1');
 RETURN n;
END;
$$;

-- Go's DELETE: a scoped admin (p_domain > 0) removes only its own domain's anchors. The
-- notification is sent only when a row was removed. Returns false when no row matched (404).
CREATE OR REPLACE FUNCTION rust_mailsec_smime_anchor_delete(p_id bigint, p_domain bigint)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 DELETE FROM smime_trust_anchors WHERE id = p_id AND (p_domain = 0 OR domain_id = p_domain);
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM pg_notify('smime_trust_changed', '1');
 RETURN true;
END;
$$;
