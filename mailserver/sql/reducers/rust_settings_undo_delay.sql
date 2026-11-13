-- Frozen Go's PUT /settings/undo-send (user.UndoSendHandler.PutDelay): read users.view_prefs,
-- merge `undoSendDelay` into it (a NULL, JSON null or non-object document starts from {}), and
-- write it back, as one transaction instead of Go's SELECT followed by UPDATE. The caller has
-- already clamped the delay to [5, 30]. p_user is the verified token's user and sits in the
-- UPDATE's WHERE (R3); a missing user row updates nothing, as in Go.
CREATE OR REPLACE FUNCTION rust_settings_undo_delay_put(
 p_user bigint,p_delay bigint
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_prefs jsonb;
BEGIN
 SELECT view_prefs INTO v_prefs FROM users WHERE id = p_user FOR UPDATE;
 IF v_prefs IS NULL OR jsonb_typeof(v_prefs) <> 'object' THEN v_prefs := '{}'::jsonb; END IF;
 UPDATE users SET view_prefs = v_prefs || jsonb_build_object('undoSendDelay', p_delay)
  WHERE id = p_user;
 RETURN p_delay;
END;
$$;
