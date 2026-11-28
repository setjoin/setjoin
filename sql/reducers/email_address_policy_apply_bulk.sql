-- Admin "Apply now": re-stamp every personal mailbox whose owner is policy-enabled.
-- ORDER BY m.id makes numeric-suffix assignment deterministic (creation order),
-- so re-running Apply-now is idempotent. p_policy_id is accepted for the API
-- contract; v1 re-evaluates the winning policy per recipient. Returns the count
-- of mailboxes whose primary address changed.
CREATE OR REPLACE FUNCTION email_address_policy_apply_bulk(p_policy_id BIGINT DEFAULT NULL)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE v_count INT := 0; v_rec RECORD; v_res TEXT; v_before TEXT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM feature_toggles WHERE key = 'feature.email_address_policy' AND enabled) THEN
    RETURN 0;
  END IF;
  FOR v_rec IN
    SELECT m.id AS mailbox_id, m.user_id
      FROM mailboxes m
      JOIN users u ON u.id = m.user_id
     WHERE m.is_primary AND u.address_policy_enabled
     ORDER BY m.id
  LOOP
    SELECT email INTO v_before FROM mailboxes WHERE id = v_rec.mailbox_id;
    v_res := email_address_policy_apply(v_rec.mailbox_id, v_rec.user_id);
    IF v_res IS NOT NULL AND v_res IS DISTINCT FROM v_before THEN
      v_count := v_count + 1;
    END IF;
  END LOOP;
  RETURN v_count;
END;
$$;
