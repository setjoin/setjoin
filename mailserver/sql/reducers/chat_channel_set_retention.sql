-- chat_channel_set_retention.sql — Chat A4a Task 4: per-channel retention
-- override.
--
-- SECURITY DEFINER + apply_worker_ownership: chat_channels has no UPDATE
-- policy (V119 FORCE-RLS, deny-by-default is the correct fail-closed
-- interim — Global Constraints), so an invoker-rights UPDATE would match 0
-- rows and surface as a bogus "channel missing" (the recurring
-- DEFINER-under-FORCE-RLS trap). Authorization is route-declared
-- (chat.compliance_manage, Task 11a) — this reducer takes the admin id for
-- audit provenance only.
--
-- The override is IMMEDIATE-BY-DESIGN, not graced (plan FIX 3 / §Goal): a
-- per-channel override is one admin acting on one channel through
-- chat.compliance_manage, not an org-wide policy edit, so the rail is
-- friction at the point of action (Task 12's typed-DESTROY confirm on a
-- shortening edit) rather than a week's delay. No effective_at exists on
-- chat_channels — do not add a per-channel grace state machine here.
CREATE OR REPLACE FUNCTION chat_channel_set_retention(
  p_admin_user_id BIGINT, p_channel_id BIGINT, p_days INTEGER
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_old INTEGER;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ195',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;

  IF p_days IS NOT NULL AND p_days <= 0 THEN
    RAISE EXCEPTION 'retention days must be positive' USING ERRCODE='BZ195',
      HINT='{"type":"invalidArguments","detail":"retention days must be a positive integer or null"}';
  END IF;

  SELECT retention_days INTO v_old FROM chat_channels WHERE id = p_channel_id;

  UPDATE chat_channels SET retention_days = p_days WHERE id = p_channel_id;  -- BZ192 trigger backstops gxp
  IF NOT FOUND THEN
    RAISE EXCEPTION 'channel not found' USING ERRCODE='BZ195',
      HINT='{"type":"invalidArguments","detail":"channel not found"}';
  END IF;

  PERFORM chat_access_audit(p_admin_user_id, p_channel_id, 'retention.change', 'channel', p_channel_id,
    jsonb_build_object('retentionDays', v_old), jsonb_build_object('retentionDays', p_days), NULL, NULL);
END;
$$;

SELECT apply_worker_ownership('chat_channel_set_retention(BIGINT, BIGINT, INTEGER)'::regprocedure);
