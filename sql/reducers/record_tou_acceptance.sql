-- record_tou_acceptance.sql — record a user's acceptance of a Terms-of-Use doc.
-- Called by the authserver /terms/accept handler after the user accepts. Rejects
-- a stale version (the doc was bumped since the screen was rendered) or a missing/
-- disabled doc so an acceptance can never be recorded against the wrong text.
-- Self-scoped: the row is keyed on p_account_id (the authenticated user), never a
-- request-supplied user id (R2). The upsert's ON CONFLICT key (user_id, tou_id)
-- enforces ownership scope on the implicit UPDATE path (R3). VOLATILE.
--
-- The caller (authserver) sets app.current_user_id = p_account_id before calling
-- so the toua_self RLS WITH CHECK passes for the setjoin_app runtime role.
--
-- Errors: BZ102 (missing/disabled ToU or stale version).
CREATE OR REPLACE FUNCTION record_tou_acceptance(
  p_account_id bigint,
  p_tou_id     bigint,
  p_version    int,
  p_source_ip  inet
) RETURNS void AS $$
DECLARE
  v_current_version int;
  v_enabled         boolean;
BEGIN
  SELECT version, enabled INTO v_current_version, v_enabled
    FROM public.terms_of_use WHERE id = p_tou_id;

  IF v_current_version IS NULL THEN
    RAISE EXCEPTION 'terms_of_use % not found', p_tou_id
      USING ERRCODE = 'BZ102',
            HINT    = 'the ToU document does not exist; reload the pending-terms list';
  END IF;
  IF v_enabled IS NOT TRUE THEN
    RAISE EXCEPTION 'terms_of_use % is disabled', p_tou_id
      USING ERRCODE = 'BZ102',
            HINT    = 'a disabled ToU cannot be accepted';
  END IF;
  IF p_version <> v_current_version THEN
    RAISE EXCEPTION 'stale ToU version % (current %)', p_version, v_current_version
      USING ERRCODE = 'BZ102',
            HINT    = 're-render the current ToU text and accept the current version';
  END IF;

  -- R2: user_id always from the auth parameter, never from request body.
  -- R3: ON CONFLICT key (user_id, tou_id) scopes the implicit UPDATE to the owner.
  INSERT INTO public.terms_of_use_acceptance (user_id, tou_id, version, accepted_at, source_ip)
  VALUES (p_account_id, p_tou_id, v_current_version, now(), p_source_ip)
  ON CONFLICT (user_id, tou_id)
  DO UPDATE SET version     = EXCLUDED.version,
                accepted_at = EXCLUDED.accepted_at,
                source_ip   = EXCLUDED.source_ip;
END;
$$ LANGUAGE plpgsql VOLATILE;
