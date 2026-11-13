-- chat_case_hold_release.sql — Chat A4b Task 2: case-scoped hold release.
--
-- Release is CASE-SCOPED BY CONSTRUCTION (dissolves A4a's N8 reason-string
-- workaround): a hold row belongs to one case, so releasing it can never
-- drop another case's coverage. A hold.release act is written ONLY for
-- channels losing their LAST active case-hold coverage — a channel still
-- covered by another case's hold gets no act. The A4a boolean arm is NOT
-- consulted: it has its own act stream (chat_channel_set_hold).
-- Coverage rows are KEPT as history — the predicate arm joins
-- released_at IS NULL, so a released hold's rows are inert (spec §5).
-- A second release of the same hold raises BZ197 (spec §6.1) — cleanly:
-- no state change, no duplicate act.
--
-- review F1: the "act only when losing LAST active coverage" NOT EXISTS
-- check is a READ COMMITTED write-skew hazard — two concurrent releases each
-- covering a shared channel can each see the OTHER's release as not-yet-
-- committed, so BOTH conclude "still covered by someone else" and skip the
-- act, losing it entirely. Fixed by taking
-- pg_advisory_xact_lock(hashtext('chat_hold_chan_' || channel_id)) — the
-- SAME per-channel key chat_case_hold_set's channel-scope path takes — BEFORE
-- the coverage check, one channel at a time in id order (deadlock-free: every
-- caller locks in the same order). The lock is held for the releasing
-- transaction's lifetime, so the second releaser to reach a given channel
-- blocks until the first COMMITS, then re-reads with that commit visible
-- (READ COMMITTED re-snapshots per statement) — the true last releaser always
-- sees the correct picture and is the one who writes the act.
CREATE OR REPLACE FUNCTION chat_case_hold_release(
  p_admin_user_id BIGINT, p_hold_id BIGINT, p_reason TEXT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_hold RECORD;
  v_ch   RECORD;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;
  SELECT * INTO v_hold FROM chat_case_holds WHERE id = p_hold_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'hold % not found', p_hold_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"hold not found"}';
  END IF;
  IF v_hold.released_at IS NOT NULL THEN
    RAISE EXCEPTION 'hold % is already released', p_hold_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"hold already released"}';
  END IF;

  UPDATE chat_case_holds
     SET released_at = now(), released_by = p_admin_user_id
   WHERE id = p_hold_id;

  -- hold.release act per channel losing its LAST active case-hold coverage.
  -- (p_hold_id is already stamped released above, and the NOT EXISTS
  -- excludes it explicitly anyway — belt and braces.) F1: per-channel
  -- advisory lock, ORDER BY channel_id so every concurrent release acquires
  -- the same channels in the same order (no lock-order deadlock), taken
  -- BEFORE the coverage check so the true last releaser sees a fully
  -- committed picture.
  -- ponytail: one advisory lock per covered channel, ALL held to commit — an
  -- org-wide custodian hold spanning thousands of channels pressures the
  -- shared lock table (max_locks_per_transaction sizing). Rare admin op;
  -- batch the loop by channel ranges if a deployment ever hits it.
  FOR v_ch IN
    SELECT hc.channel_id FROM chat_case_hold_channels hc
     WHERE hc.hold_id = p_hold_id
     ORDER BY hc.channel_id
  LOOP
    PERFORM pg_advisory_xact_lock(hashtext('chat_hold_chan_' || v_ch.channel_id::text));
    IF NOT EXISTS (SELECT 1
                     FROM chat_case_hold_channels hc2
                     JOIN chat_case_holds h2 ON h2.id = hc2.hold_id
                                            AND h2.released_at IS NULL
                    WHERE hc2.channel_id = v_ch.channel_id
                      AND hc2.hold_id <> p_hold_id) THEN
      PERFORM chat_access_audit(p_admin_user_id, v_ch.channel_id, 'hold.release', 'channel',
        v_ch.channel_id,
        jsonb_build_object('caseId', v_hold.case_id, 'holdId', p_hold_id),
        NULL, NULL, p_reason);
    END IF;
  END LOOP;
END;
$$;

SELECT apply_worker_ownership('chat_case_hold_release(BIGINT, BIGINT, TEXT)'::regprocedure);
