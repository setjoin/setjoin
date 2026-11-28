-- chat_channel_set_hold.sql — Chat A4a Task 5: legal hold set/release.
--
-- SECURITY DEFINER + apply_worker_ownership: chat_channels has no UPDATE
-- policy (V119 FORCE-RLS, deny-by-default is the correct fail-closed
-- interim — Global Constraints), so an invoker-rights UPDATE would match 0
-- rows and surface as a bogus "channel missing" (the recurring
-- DEFINER-under-FORCE-RLS trap). Authorization is route-declared
-- (chat.compliance_manage, Task 11a) — this reducer takes the admin id for
-- audit provenance only.
--
-- Hold beats retention/WORM BY CONSTRUCTION: this reducer only flips the
-- legal_hold/legal_hold_reason columns chat_hold_active() (Task 1 §B) reads;
-- the actual destruction-blocking is the V126 trg_chat_message_hold_fn
-- trigger, which this reducer never touches.
--
-- The reason is LOAD-BEARING, not a label (N8): there is exactly ONE
-- legal_hold boolean + ONE legal_hold_reason column per channel, so a naive
-- release could clobber a hold placed for a different matter.
--   SET on an already-held channel with a DIFFERENT reason -> BZ195, never
--   silently overwritten. Idempotent re-set with the SAME reason is a no-op
--   (no duplicate act).
--   RELEASE is reason-scoped: p_reason is REQUIRED and must equal the
--   channel's current legal_hold_reason, or the call is a silent no-op (not
--   an exception) — an admin releasing case-42 can never drop an
--   independent case-99 hold on the same channel. A blank/NULL release
--   reason -> BZ195.
CREATE OR REPLACE FUNCTION chat_channel_set_hold(
  p_admin_user_id BIGINT, p_channel_id BIGINT, p_on BOOLEAN, p_reason TEXT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_held   BOOLEAN;
  v_reason TEXT;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ195',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;

  -- FOR UPDATE (FIX 5): without the row lock, two admins first-time-holding
  -- this channel for DIFFERENT matters both read legal_hold=false, both pass
  -- the conflict guard below, and the last writer clobbers the first with no
  -- BZ195. The lock serializes them so the second sees the first's hold and
  -- is rejected.
  SELECT legal_hold, legal_hold_reason INTO v_held, v_reason
    FROM chat_channels WHERE id = p_channel_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'channel % not found', p_channel_id
      USING ERRCODE='BZ195', HINT='{"type":"invalidArguments","detail":"channel not found"}';
  END IF;

  IF p_on THEN
    IF v_held AND v_reason IS DISTINCT FROM p_reason THEN
      RAISE EXCEPTION 'channel % already held for a different matter', p_channel_id
        USING ERRCODE='BZ195',
              HINT='{"type":"invalidArguments","detail":"channel is already under hold for a different matter"}';
    END IF;
    IF v_held THEN RETURN; END IF;  -- idempotent re-set, same reason: no duplicate act

    UPDATE chat_channels SET legal_hold = true, legal_hold_reason = p_reason WHERE id = p_channel_id;
    PERFORM chat_access_audit(p_admin_user_id, p_channel_id, 'hold.set', 'channel', p_channel_id,
      jsonb_build_object('legalHold', v_held), jsonb_build_object('legalHold', true), NULL, p_reason);
  ELSE
    IF coalesce(btrim(p_reason), '') = '' THEN
      RAISE EXCEPTION 'release requires the matter the hold was placed under'
        USING ERRCODE='BZ195', HINT='{"type":"invalidArguments","detail":"release requires a reason"}';
    END IF;
    IF NOT v_held OR v_reason IS DISTINCT FROM p_reason THEN RETURN; END IF;  -- someone else's case, or not held: silent no-op

    UPDATE chat_channels SET legal_hold = false, legal_hold_reason = NULL WHERE id = p_channel_id;
    PERFORM chat_access_audit(p_admin_user_id, p_channel_id, 'hold.release', 'channel', p_channel_id,
      jsonb_build_object('legalHold', true), jsonb_build_object('legalHold', false), NULL, p_reason);
  END IF;
END;
$$;

SELECT apply_worker_ownership('chat_channel_set_hold(BIGINT, BIGINT, BOOLEAN, TEXT)'::regprocedure);
