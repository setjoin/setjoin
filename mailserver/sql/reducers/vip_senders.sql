-- vip_senders.sql — VIP senders (QoL #10a). p_user_id from the auth context in
-- every statement (R1/R2/R3); sender_email is lower()'d on write so the table's
-- CHECK constraint and PK are always satisfied regardless of caller casing.
-- No jmap_*_state bump: like saved_searches/quick_steps, VIP membership is not
-- a JMAP-visible entity type — the webmail re-reads the list on demand.

CREATE OR REPLACE FUNCTION vip_sender_set(
  p_user_id BIGINT, p_email TEXT, p_on BOOLEAN
) RETURNS JSONB AS $$
DECLARE
  v_email TEXT := lower(trim(coalesce(p_email, '')));
BEGIN
  IF v_email = '' THEN
    RAISE EXCEPTION 'vip sender email required'
      USING ERRCODE = 'BZ122', HINT = '{"type":"invalidArguments"}';
  END IF;

  IF p_on THEN
    INSERT INTO vip_senders (user_id, sender_email)      -- R2: user_id from auth param
    VALUES (p_user_id, v_email)
    ON CONFLICT (user_id, sender_email) DO NOTHING;
  ELSE
    DELETE FROM vip_senders
     WHERE user_id = p_user_id AND sender_email = v_email; -- R3: ownership in WHERE
  END IF;

  RETURN jsonb_build_object('email', v_email, 'vip', p_on);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION vip_senders_list(p_user_id BIGINT) RETURNS JSONB AS $$
  SELECT COALESCE(jsonb_agg(sender_email ORDER BY created_at, sender_email), '[]'::JSONB)
  FROM vip_senders WHERE user_id = p_user_id;              -- R1: filter by auth user_id
$$ LANGUAGE sql STABLE;
