-- rust_device_secret_reseal(p_id, p_enc, p_key, p_legacy): the lazy re-seal of a legacy
-- plaintext device HMAC secret (frozen Go's GetDeviceSecret compatibility leg) as a
-- credential-maintenance statement. Owner-approved security fix 2026-11-05 (#513 item 1):
-- Go ran the UPDATE on the request pool without a user GUC, so under app RLS
-- (devices_self) it matched no row and the plaintext secret stayed in the table after every
-- successful proof. SECURITY DEFINER under the worker credential (like
-- exchange_assessment_domain_authorized), it is keyed on the device id AND the exact
-- plaintext value the verifier just loaded and proved (R3: a concurrent rotation or revoke
-- makes it a no-op), so it can only replace a secret with its own envelope; it never reads
-- or returns a secret. True when the row was re-sealed.
CREATE OR REPLACE FUNCTION rust_device_secret_reseal(
  p_id bigint, p_enc bytea, p_key text, p_legacy text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF p_id IS NULL OR p_enc IS NULL OR p_key IS NULL OR p_legacy IS NULL THEN RETURN false; END IF;
  UPDATE devices
     SET hmac_secret_enc = p_enc, hmac_secret_key_id = p_key, hmac_secret = NULL
   WHERE id = p_id AND hmac_secret = p_legacy AND hmac_secret_enc IS NULL;
  RETURN FOUND;
END;
$$;
SELECT apply_worker_ownership('rust_device_secret_reseal(bigint,bytea,text,text)'::regprocedure);
