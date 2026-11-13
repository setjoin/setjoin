-- Frozen Go's PUT /settings/signatures (user.SignatureHandler.Put) as one reducer: the
-- per-user row-count admission, the is_default clear, the (user_id, alias_email) upsert and
-- the default_for role flip through set_signature_default, in one transaction. Go counts
-- outside the transaction and commits the rest atomically; the count rides inside here.
--
-- Ownership is p_user (the verified token's user) in every statement (R3). Returns the
-- signature id, or -1 when a NEW alias would exceed the 100-row cap (Go's 400 "signature
-- limit reached"). Field validation (alias present, byte caps, default_for domain) stays in
-- the caller, as in Go.
CREATE OR REPLACE FUNCTION rust_settings_signature_put(
 p_user bigint,p_alias text,p_html text,p_text text,p_is_default boolean,p_default_for text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_others integer; v_id bigint;
BEGIN
 SELECT COUNT(*) INTO v_others FROM user_signatures
  WHERE user_id = p_user AND alias_email <> p_alias;
 IF v_others >= 100 THEN RETURN -1; END IF;
 IF p_is_default THEN
  UPDATE user_signatures SET is_default = FALSE WHERE user_id = p_user;
 END IF;
 INSERT INTO user_signatures (user_id, alias_email, signature_html, signature_text, is_default, default_for)
  VALUES (p_user, p_alias, p_html, p_text, p_is_default, p_default_for)
  ON CONFLICT (user_id, alias_email) DO UPDATE SET
   signature_html = EXCLUDED.signature_html,
   signature_text = EXCLUDED.signature_text,
   is_default     = COALESCE(NULLIF(EXCLUDED.is_default, FALSE), user_signatures.is_default),
   default_for    = EXCLUDED.default_for,
   updated_at     = now()
  RETURNING id INTO v_id;
 IF p_default_for <> 'none' THEN
  PERFORM set_signature_default(p_user, v_id, p_default_for);
 END IF;
 RETURN v_id;
END;
$$;
