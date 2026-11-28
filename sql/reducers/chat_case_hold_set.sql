-- chat_case_hold_set.sql — Chat A4b Task 2: durable case/custodian hold (L3/L4).
--
-- Scope: EXACTLY ONE of p_custodian_user_id / p_channel_id (BZ197 otherwise).
-- Coverage (L4): materialized into chat_case_hold_channels at set time —
-- current memberships UNION channels the custodian AUTHORED in (covers
-- pre-hold departures/offboarding) — and grown by the V127 join trigger.
-- NEVER pruned on leave. Both-miss race: this reducer takes
-- pg_advisory_xact_lock(hashtext('chat_hold_user_' || custodian)) BEFORE the
-- snapshot; the join trigger takes the same lock before its hold lookup.
-- Channel-scoped sets serialize on their own channel key so two identical
-- concurrent sets resolve to one row + one idempotent return, not a 23505.
-- Idempotent re-set of an identical ACTIVE hold returns the existing id, no
-- new acts. One hold.set act per newly-covered channel
-- (payload {caseId, holdId, scope}).
-- Authorization is route-declared (chat.compliance_manage + admin_can_reach,
-- Task 5); p_admin_user_id is audit provenance only.
CREATE OR REPLACE FUNCTION chat_case_hold_set(
  p_admin_user_id BIGINT, p_case_id BIGINT,
  p_custodian_user_id BIGINT, p_channel_id BIGINT, p_reason TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status  TEXT;
  v_hold_id BIGINT;
  v_ch      RECORD;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;
  IF (p_custodian_user_id IS NULL) = (p_channel_id IS NULL) THEN
    RAISE EXCEPTION 'exactly one of custodian or channel scope is required'
      USING ERRCODE='BZ197',
            HINT='{"type":"invalidArguments","detail":"exactly one of custodianUserId or channelId"}';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'hold requires a reason' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"reason is required"}';
  END IF;
  SELECT status INTO v_status FROM ediscovery_cases WHERE id = p_case_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'case % not found', p_case_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"case not found"}';
  END IF;
  IF v_status <> 'active' THEN
    RAISE EXCEPTION 'case % is not open', p_case_id USING ERRCODE='BZ198',
      HINT='{"type":"stateMismatch","detail":"case is not open"}';
  END IF;
  IF p_channel_id IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM chat_channels WHERE id = p_channel_id) THEN
    RAISE EXCEPTION 'channel % not found', p_channel_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"channel not found"}';
  END IF;

  -- L4 both-miss race lock, BEFORE the idempotence check and the snapshot.
  IF p_custodian_user_id IS NOT NULL THEN
    PERFORM pg_advisory_xact_lock(hashtext('chat_hold_user_' || p_custodian_user_id::text));
  ELSE
    PERFORM pg_advisory_xact_lock(hashtext('chat_hold_chan_' || p_channel_id::text));
  END IF;

  SELECT id INTO v_hold_id FROM chat_case_holds
   WHERE case_id = p_case_id AND released_at IS NULL
     AND custodian_user_id IS NOT DISTINCT FROM p_custodian_user_id
     AND channel_id        IS NOT DISTINCT FROM p_channel_id;
  IF FOUND THEN RETURN v_hold_id; END IF;   -- idempotent re-set: existing id, no new acts

  INSERT INTO chat_case_holds (case_id, custodian_user_id, channel_id, reason, created_by)
  VALUES (p_case_id, p_custodian_user_id, p_channel_id, p_reason, p_admin_user_id)
  RETURNING id INTO v_hold_id;

  -- Coverage snapshot (L4): memberships UNION authored channels, or the one
  -- channel for scope B. UNION (not UNION ALL) dedups across the legs.
  -- review F3: the authored-channels leg is index-only on
  -- chat_messages_author_idx (author_id, channel_id) — V128 — so this DISTINCT
  -- scan stays cheap while running INSIDE the txn that holds the custodian's
  -- chat_hold_user_ advisory lock (a full seq scan here would serialize every
  -- concurrent hold-set/join on that custodian behind it).
  FOR v_ch IN
    SELECT cm.channel_id FROM chat_channel_members cm
     WHERE p_custodian_user_id IS NOT NULL AND cm.user_id = p_custodian_user_id
    UNION
    SELECT DISTINCT m.channel_id FROM chat_messages m
     WHERE p_custodian_user_id IS NOT NULL AND m.author_id = p_custodian_user_id
    UNION
    SELECT p_channel_id WHERE p_channel_id IS NOT NULL
  LOOP
    INSERT INTO chat_case_hold_channels (hold_id, channel_id, source)
    VALUES (v_hold_id, v_ch.channel_id, 'snapshot')
    ON CONFLICT DO NOTHING;
    PERFORM chat_access_audit(p_admin_user_id, v_ch.channel_id, 'hold.set', 'channel',
      v_ch.channel_id, NULL,
      jsonb_build_object('caseId', p_case_id, 'holdId', v_hold_id,
                         'scope', CASE WHEN p_custodian_user_id IS NULL
                                       THEN 'channel' ELSE 'custodian' END),
      NULL, p_reason);
  END LOOP;

  RETURN v_hold_id;
END;
$$;

SELECT apply_worker_ownership('chat_case_hold_set(BIGINT, BIGINT, BIGINT, BIGINT, TEXT)'::regprocedure);
